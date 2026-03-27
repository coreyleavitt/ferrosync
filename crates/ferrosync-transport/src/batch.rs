//! Batch recording and replay transport (`--write-batch` / `--read-batch`).
//!
//! Records the raw wire protocol exchange to a file for later replay
//! without a network connection.

use std::io::{Read as StdRead, Write as StdWrite};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Transport, TransportStreams};
use ferrosync_types::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

const BATCH_MAGIC: &[u8; 4] = b"FBAT";
const BATCH_VERSION: u32 = 1;
const DIR_READ: u8 = 0x00;
const DIR_WRITE: u8 = 0x01;

// ---------------------------------------------------------------------------
// Recording wrapper
// ---------------------------------------------------------------------------

/// Transport wrapper that records all wire I/O to a batch file.
pub struct BatchRecordTransport<T: Transport> {
    inner: T,
    batch_path: PathBuf,
}

impl<T: Transport> BatchRecordTransport<T> {
    pub fn new(inner: T, batch_path: impl Into<PathBuf>) -> Self {
        Self {
            inner,
            batch_path: batch_path.into(),
        }
    }
}

impl<T: Transport + 'static> Transport for BatchRecordTransport<T> {
    fn connect(
        self: Box<Self>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let mut streams = Box::new(self.inner).connect().await?;

            let file = std::fs::File::create(&self.batch_path).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("failed to create batch file: {e}"),
                }
            })?;
            let mut file = std::io::BufWriter::new(file);

            // Write header.
            file.write_all(BATCH_MAGIC)
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("batch write error: {e}"),
                })?;
            file.write_all(&BATCH_VERSION.to_le_bytes()).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("batch write error: {e}"),
                }
            })?;

            let recorder = Arc::new(Mutex::new(file));

            // Take ownership of fields from TransportStreams (which has Drop).
            let inner_reader = std::mem::replace(&mut streams.reader, Box::new(tokio::io::empty()));
            let inner_writer = std::mem::replace(&mut streams.writer, Box::new(tokio::io::sink()));
            let bg_task = streams.background_task.take();
            // Keep streams alive so the background task is not aborted.
            let _streams_guard = streams;

            let reader = Box::new(RecordingReader {
                inner: inner_reader,
                recorder: Arc::clone(&recorder),
            }) as Box<dyn AsyncRead + Unpin + Send>;

            let writer = Box::new(RecordingWriter {
                inner: inner_writer,
                recorder,
            }) as Box<dyn AsyncWrite + Unpin + Send>;

            Ok(TransportStreams {
                reader,
                writer,
                background_task: bg_task,
            })
        })
    }
}

/// AsyncRead wrapper that records all data read.
struct RecordingReader {
    inner: Box<dyn AsyncRead + Unpin + Send>,
    recorder: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
}

impl AsyncRead for RecordingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let new_data = &buf.filled()[before..];
            if !new_data.is_empty() {
                if let Ok(mut file) = self.recorder.lock() {
                    let _ = file.write_all(&[DIR_READ]);
                    let _ = file.write_all(&(new_data.len() as u32).to_le_bytes());
                    let _ = file.write_all(new_data);
                }
            }
        }
        result
    }
}

/// AsyncWrite wrapper that records all data written.
struct RecordingWriter {
    inner: Box<dyn AsyncWrite + Unpin + Send>,
    recorder: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                if let Ok(mut file) = self.recorder.lock() {
                    let _ = file.write_all(&[DIR_WRITE]);
                    let _ = file.write_all(&(*n as u32).to_le_bytes());
                    let _ = file.write_all(&buf[..*n]);
                }
            }
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Replay transport
// ---------------------------------------------------------------------------

/// Transport that replays a previously recorded batch file.
pub struct BatchReplayTransport {
    batch_path: PathBuf,
}

impl BatchReplayTransport {
    pub fn new(batch_path: impl Into<PathBuf>) -> Self {
        Self {
            batch_path: batch_path.into(),
        }
    }
}

impl Transport for BatchReplayTransport {
    fn connect(
        self: Box<Self>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let mut file = std::fs::File::open(&self.batch_path).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("failed to open batch file: {e}"),
                }
            })?;

            // Read and verify header.
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("batch read error: {e}"),
                })?;
            if &magic != BATCH_MAGIC {
                return Err(TransportError::ConnectionFailed {
                    message: "invalid batch file magic".to_string(),
                });
            }
            let mut version_bytes = [0u8; 4];
            file.read_exact(&mut version_bytes)
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("batch read error: {e}"),
                })?;
            let version = u32::from_le_bytes(version_bytes);
            if version != BATCH_VERSION {
                return Err(TransportError::ConnectionFailed {
                    message: format!("unsupported batch version: {version}"),
                });
            }

            // Read all records into read/write buffers.
            let mut read_data = Vec::new();
            let mut write_data = Vec::new();
            let mut dir = [0u8; 1];
            let mut len_buf = [0u8; 4];
            while file.read_exact(&mut dir).is_ok() {
                file.read_exact(&mut len_buf)
                    .map_err(|e| TransportError::ConnectionFailed {
                        message: format!("batch read error: {e}"),
                    })?;
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut data = vec![0u8; len];
                file.read_exact(&mut data)
                    .map_err(|e| TransportError::ConnectionFailed {
                        message: format!("batch read error: {e}"),
                    })?;
                match dir[0] {
                    DIR_READ => read_data.extend(data),
                    DIR_WRITE => write_data.extend(data),
                    _ => {} // skip unknown directions
                }
            }

            // Create streams backed by the buffered data.
            let reader = Box::new(tokio::io::BufReader::new(std::io::Cursor::new(read_data)))
                as Box<dyn AsyncRead + Unpin + Send>;
            let writer = Box::new(tokio::io::sink()) as Box<dyn AsyncWrite + Unpin + Send>;

            Ok(TransportStreams {
                reader,
                writer,
                background_task: None,
            })
        })
    }
}
