//! Multiplexed I/O for the rsync wire protocol.
//!
//! Rsync multiplexes data and control messages over a single stream. Each
//! message is preceded by a 4-byte little-endian header:
//!
//! - Bits 0-23: payload length (max 0xFFFFFF = 16 MiB)
//! - Bits 24-31: `MPLEX_BASE (7) + message_code`
//!
//! Multiplexing is disabled during the initial handshake and enabled once
//! both sides have exchanged protocol versions.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Offset added to message codes in the tag byte.
const MPLEX_BASE: u8 = 7;

/// Maximum payload size per multiplexed frame (24 bits).
const MAX_PAYLOAD: u32 = 0x00FF_FFFF;

/// Typical data chunk size (matches rsync's IO_BUFFER_SIZE).
pub(crate) const DATA_CHUNK_SIZE: usize = 32_768;

// ---------------------------------------------------------------------------
// Message codes
// ---------------------------------------------------------------------------

/// Rsync multiplexed message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MsgCode {
    /// Raw file/transfer data.
    Data = 0,
    /// Transfer error (FERROR_XFER).
    ErrorXfer = 1,
    /// Informational output (FINFO).
    Info = 2,
    /// Error output (FERROR).
    Error = 3,
    /// Warning output (FWARNING).
    Warning = 4,
    /// Socket error (FERROR_SOCKET).
    ErrorSocket = 5,
    /// Log-file-only output (FLOG).
    Log = 6,
    /// Client-side output (FCLIENT).
    Client = 7,
    /// UTF-8 error (FERROR_UTF8).
    ErrorUtf8 = 8,
    /// Reprocess a file list index.
    Redo = 9,
    /// Statistics data.
    Stats = 10,
    /// Sending side had an I/O error.
    IoError = 22,
    /// Daemon communicates its timeout value.
    IoTimeout = 33,
    /// Keep-alive / no-op.
    Noop = 42,
    /// Synchronize error-exit (protocol >= 31).
    ErrorExit = 86,
    /// Successfully updated a file.
    Success = 100,
    /// Successfully deleted a file.
    Deleted = 101,
    /// Sender failed to open a requested file.
    NoSend = 102,
}

impl MsgCode {
    /// Convert from the raw tag byte (after subtracting MPLEX_BASE).
    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Data),
            1 => Ok(Self::ErrorXfer),
            2 => Ok(Self::Info),
            3 => Ok(Self::Error),
            4 => Ok(Self::Warning),
            5 => Ok(Self::ErrorSocket),
            6 => Ok(Self::Log),
            7 => Ok(Self::Client),
            8 => Ok(Self::ErrorUtf8),
            9 => Ok(Self::Redo),
            10 => Ok(Self::Stats),
            22 => Ok(Self::IoError),
            33 => Ok(Self::IoTimeout),
            42 => Ok(Self::Noop),
            86 => Ok(Self::ErrorExit),
            100 => Ok(Self::Success),
            101 => Ok(Self::Deleted),
            102 => Ok(Self::NoSend),
            _ => Err(ProtocolError::UnexpectedMessageType { msg_type: tag }),
        }
    }
}

// ---------------------------------------------------------------------------
// Decoded message
// ---------------------------------------------------------------------------

/// A decoded multiplexed message.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum MplexMessage {
    /// Raw transfer data.
    Data(Bytes),
    /// Informational text (MSG_INFO).
    Info(String),
    /// Error text (MSG_ERROR, MSG_ERROR_XFER, MSG_ERROR_SOCKET, MSG_ERROR_UTF8).
    Error { code: MsgCode, text: String },
    /// Warning text (MSG_WARNING).
    Warning(String),
    /// Log text (MSG_LOG, MSG_CLIENT).
    Log(String),
    /// Reprocess a file list index.
    Redo(i32),
    /// Successfully updated file at index.
    Success(i32),
    /// Deleted file at index.
    Deleted(i32),
    /// Failed to send file at index.
    NoSend(i32),
    /// I/O error flags from sender.
    IoError(i32),
    /// Daemon timeout value.
    IoTimeout(i32),
    /// Statistics (8 bytes).
    Stats(Bytes),
    /// Keep-alive.
    Noop,
    /// Error-exit synchronization (protocol >= 31).
    ErrorExit(Bytes),
}

// ---------------------------------------------------------------------------
// Reader (demultiplexer)
// ---------------------------------------------------------------------------

/// Demultiplexes an rsync multiplexed input stream.
///
/// Reads 4-byte headers and dispatches messages by type.
pub(crate) struct MplexReader<R> {
    inner: R,
    /// Remaining bytes of the current MSG_DATA payload.
    #[allow(dead_code)]
    data_remaining: u32,
}

impl<R: AsyncRead + Unpin> MplexReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            data_remaining: 0,
        }
    }

    /// Read the next complete message from the multiplexed stream.
    ///
    /// For MSG_DATA, reads the full payload into a `Bytes` buffer. For control
    /// messages, reads and interprets the payload.
    pub async fn read_message(&mut self) -> Result<MplexMessage> {
        // Read the 4-byte header.
        let mut hdr = [0u8; 4];
        self.inner.read_exact(&mut hdr).await?;
        let raw = u32::from_le_bytes(hdr);

        let payload_len = raw & MAX_PAYLOAD;
        let tag_byte = (raw >> 24) as u8;

        if tag_byte < MPLEX_BASE {
            return Err(ProtocolError::InvalidMplexTag {
                tag: tag_byte as u32,
            });
        }

        let code = MsgCode::from_tag(tag_byte - MPLEX_BASE)?;

        match code {
            MsgCode::Data => {
                let mut buf = BytesMut::zeroed(payload_len as usize);
                self.inner.read_exact(&mut buf).await?;
                Ok(MplexMessage::Data(buf.freeze()))
            }

            MsgCode::Info => {
                let text = self.read_text(payload_len).await?;
                Ok(MplexMessage::Info(text))
            }

            MsgCode::Warning => {
                let text = self.read_text(payload_len).await?;
                Ok(MplexMessage::Warning(text))
            }

            MsgCode::Error | MsgCode::ErrorXfer | MsgCode::ErrorSocket | MsgCode::ErrorUtf8 => {
                let text = self.read_text(payload_len).await?;
                Ok(MplexMessage::Error { code, text })
            }

            MsgCode::Log | MsgCode::Client => {
                let text = self.read_text(payload_len).await?;
                Ok(MplexMessage::Log(text))
            }

            MsgCode::Redo => Ok(MplexMessage::Redo(self.read_i32().await?)),
            MsgCode::Success => Ok(MplexMessage::Success(self.read_i32().await?)),
            MsgCode::Deleted => Ok(MplexMessage::Deleted(self.read_i32().await?)),
            MsgCode::NoSend => Ok(MplexMessage::NoSend(self.read_i32().await?)),
            MsgCode::IoError => Ok(MplexMessage::IoError(self.read_i32().await?)),
            MsgCode::IoTimeout => Ok(MplexMessage::IoTimeout(self.read_i32().await?)),

            MsgCode::Stats => {
                let mut buf = BytesMut::zeroed(payload_len as usize);
                self.inner.read_exact(&mut buf).await?;
                Ok(MplexMessage::Stats(buf.freeze()))
            }

            MsgCode::Noop => Ok(MplexMessage::Noop),

            MsgCode::ErrorExit => {
                let mut buf = BytesMut::zeroed(payload_len as usize);
                self.inner.read_exact(&mut buf).await?;
                Ok(MplexMessage::ErrorExit(buf.freeze()))
            }
        }
    }

    /// Read a data-only message, skipping and logging control messages.
    ///
    /// If `data_remaining` is non-zero from a previous partial read, continues
    /// reading from the current data frame. Otherwise reads the next header
    /// and returns the data payload. Control messages are dispatched to the
    /// provided callback.
    #[allow(dead_code)]
    pub async fn read_data<F>(&mut self, buf: &mut [u8], mut on_control: F) -> Result<usize>
    where
        F: FnMut(MplexMessage),
    {
        loop {
            // If we have data remaining from a previous frame, read from it.
            if self.data_remaining > 0 {
                let to_read = buf.len().min(self.data_remaining as usize);
                self.inner.read_exact(&mut buf[..to_read]).await?;
                self.data_remaining -= to_read as u32;
                return Ok(to_read);
            }

            // Read next message.
            match self.read_message().await? {
                MplexMessage::Data(data) => {
                    let to_copy = buf.len().min(data.len());
                    buf[..to_copy].copy_from_slice(&data[..to_copy]);
                    if data.len() > to_copy {
                        // This shouldn't happen with read_message returning full
                        // payloads, but handle it gracefully.
                        self.data_remaining = (data.len() - to_copy) as u32;
                    }
                    return Ok(to_copy);
                }
                ctrl => on_control(ctrl),
            }
        }
    }

    async fn read_text(&mut self, len: u32) -> Result<String> {
        let mut buf = vec![0u8; len as usize];
        self.inner.read_exact(&mut buf).await?;
        // rsync sends text as potentially non-UTF8; lossy conversion is safe.
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn read_i32(&mut self) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf).await?;
        Ok(i32::from_le_bytes(buf))
    }
}

// ---------------------------------------------------------------------------
// Writer (multiplexer)
// ---------------------------------------------------------------------------

/// Multiplexes messages onto an rsync output stream.
pub struct MplexWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> MplexWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Write a multiplexed message with the given code and payload.
    pub(crate) async fn write_message(&mut self, code: MsgCode, payload: &[u8]) -> Result<()> {
        let len = payload.len() as u32;
        if len > MAX_PAYLOAD {
            return Err(ProtocolError::FrameTooLarge {
                size: len,
                max: MAX_PAYLOAD,
            });
        }

        let tag = (MPLEX_BASE + code as u8) as u32;
        let hdr = (tag << 24) | len;
        self.inner.write_all(&hdr.to_le_bytes()).await?;

        if !payload.is_empty() {
            self.inner.write_all(payload).await?;
        }

        Ok(())
    }

    /// Write a MSG_DATA payload, splitting into chunks if necessary.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(DATA_CHUNK_SIZE) {
            self.write_message(MsgCode::Data, chunk).await?;
        }
        Ok(())
    }

    /// Write a control message carrying a file list index (MSG_REDO,
    /// MSG_SUCCESS, MSG_DELETED, MSG_NO_SEND).
    #[allow(dead_code)]
    pub(crate) async fn write_index(&mut self, code: MsgCode, idx: i32) -> Result<()> {
        self.write_message(code, &idx.to_le_bytes()).await
    }

    /// Write an informational text message.
    pub async fn write_info(&mut self, text: &str) -> Result<()> {
        self.write_message(MsgCode::Info, text.as_bytes()).await
    }

    /// Write an error text message.
    pub async fn write_error(&mut self, text: &str) -> Result<()> {
        self.write_message(MsgCode::Error, text.as_bytes()).await
    }

    /// Flush the underlying writer.
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// Consume the writer and return the inner stream.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Shut down the underlying writer (send EOF).
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_frame(code: MsgCode, payload: &[u8]) -> Vec<u8> {
        let tag = (MPLEX_BASE + code as u8) as u32;
        let hdr = (tag << 24) | (payload.len() as u32);
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(payload);
        buf
    }

    #[tokio::test]
    async fn test_header_encoding() {
        // MSG_DATA with 256-byte payload: tag = 7, length = 0x100.
        let frame = build_frame(MsgCode::Data, &[0xAA; 256]);
        assert_eq!(frame[0], 0x00); // length byte 0
        assert_eq!(frame[1], 0x01); // length byte 1
        assert_eq!(frame[2], 0x00); // length byte 2
        assert_eq!(frame[3], 0x07); // tag = MPLEX_BASE + 0
    }

    #[tokio::test]
    async fn test_header_info() {
        // MSG_INFO with 5-byte payload: tag = 9.
        let frame = build_frame(MsgCode::Info, b"hello");
        assert_eq!(frame[3], 0x09); // tag = 7 + 2
        assert_eq!(frame[0], 0x05); // length = 5
    }

    #[tokio::test]
    async fn test_write_read_data() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        writer.write_data(b"hello world").await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));
        match reader.read_message().await.unwrap() {
            MplexMessage::Data(data) => assert_eq!(&data[..], b"hello world"),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_write_read_info() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        writer.write_info("test message").await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));
        match reader.read_message().await.unwrap() {
            MplexMessage::Info(text) => assert_eq!(text, "test message"),
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_write_read_error() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        writer.write_error("something failed").await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));
        match reader.read_message().await.unwrap() {
            MplexMessage::Error { code, text } => {
                assert_eq!(code, MsgCode::Error);
                assert_eq!(text, "something failed");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_write_read_index_messages() {
        let cases = [
            (MsgCode::Redo, 42_i32),
            (MsgCode::Success, 100),
            (MsgCode::Deleted, 7),
            (MsgCode::NoSend, 0),
        ];

        for (code, idx) in cases {
            let mut buf = Vec::new();
            let mut writer = MplexWriter::new(&mut buf);
            writer.write_index(code, idx).await.unwrap();

            let mut reader = MplexReader::new(Cursor::new(&buf));
            let msg = reader.read_message().await.unwrap();
            let got_idx = match msg {
                MplexMessage::Redo(i) => i,
                MplexMessage::Success(i) => i,
                MplexMessage::Deleted(i) => i,
                MplexMessage::NoSend(i) => i,
                other => panic!("expected index message, got {other:?}"),
            };
            assert_eq!(got_idx, idx, "index mismatch for {code:?}");
        }
    }

    #[tokio::test]
    async fn test_data_chunking() {
        // Data larger than DATA_CHUNK_SIZE should be split into multiple frames.
        let payload = vec![0xBB; DATA_CHUNK_SIZE + 100];
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        writer.write_data(&payload).await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));

        // First chunk: DATA_CHUNK_SIZE bytes.
        match reader.read_message().await.unwrap() {
            MplexMessage::Data(data) => assert_eq!(data.len(), DATA_CHUNK_SIZE),
            other => panic!("expected Data, got {other:?}"),
        }

        // Second chunk: remaining 100 bytes.
        match reader.read_message().await.unwrap() {
            MplexMessage::Data(data) => assert_eq!(data.len(), 100),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_interleaved_data_and_control() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);

        writer.write_data(b"part1").await.unwrap();
        writer.write_info("progress: 50%").await.unwrap();
        writer.write_data(b"part2").await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));

        match reader.read_message().await.unwrap() {
            MplexMessage::Data(d) => assert_eq!(&d[..], b"part1"),
            other => panic!("expected Data, got {other:?}"),
        }
        match reader.read_message().await.unwrap() {
            MplexMessage::Info(t) => assert_eq!(t, "progress: 50%"),
            other => panic!("expected Info, got {other:?}"),
        }
        match reader.read_message().await.unwrap() {
            MplexMessage::Data(d) => assert_eq!(&d[..], b"part2"),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_data_skips_control() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);

        writer.write_info("skip me").await.unwrap();
        writer.write_data(b"the data").await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));
        let mut data_buf = [0u8; 64];
        let mut control_msgs = Vec::new();

        let n = reader
            .read_data(&mut data_buf, |msg| control_msgs.push(msg))
            .await
            .unwrap();

        assert_eq!(&data_buf[..n], b"the data");
        assert_eq!(control_msgs.len(), 1);
        match &control_msgs[0] {
            MplexMessage::Info(t) => assert_eq!(t, "skip me"),
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_noop_message() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        writer.write_message(MsgCode::Noop, &[]).await.unwrap();

        let mut reader = MplexReader::new(Cursor::new(&buf));
        match reader.read_message().await.unwrap() {
            MplexMessage::Noop => {}
            other => panic!("expected Noop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_tag() {
        // Tag byte below MPLEX_BASE should error.
        let hdr: u32 = (3u32 << 24) | 5; // tag=3 < MPLEX_BASE=7
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0; 5]);

        let mut reader = MplexReader::new(Cursor::new(&buf));
        assert!(reader.read_message().await.is_err());
    }

    #[tokio::test]
    async fn test_frame_too_large() {
        let mut buf = Vec::new();
        let mut writer = MplexWriter::new(&mut buf);
        let oversized = vec![0u8; (MAX_PAYLOAD + 1) as usize];
        assert!(writer
            .write_message(MsgCode::Data, &oversized)
            .await
            .is_err());
    }

    // -----------------------------------------------------------------------
    // Truncated / malformed multiplex input tests (#54)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_read_message_truncated_empty() {
        let mut reader = MplexReader::new(Cursor::new(&[] as &[u8]));
        let result = reader.read_message().await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_message_truncated_partial_header() {
        // Only 2 bytes instead of the required 4-byte header.
        let mut reader = MplexReader::new(Cursor::new(&[0x05, 0x00]));
        let result = reader.read_message().await;
        assert!(result.is_err(), "partial header should return error");
    }

    #[tokio::test]
    async fn test_read_message_truncated_data_payload() {
        // Valid header claiming 100 bytes of MSG_DATA, but only 5 bytes follow.
        let hdr: u32 = (7u32 << 24) | 100; // tag=MPLEX_BASE+DATA, len=100
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0xAA; 5]); // only 5 of 100 bytes

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(
            result.is_err(),
            "truncated data payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_message_truncated_info_payload() {
        // Valid header claiming 50 bytes of MSG_INFO, but no payload.
        let hdr: u32 = (9u32 << 24) | 50; // tag=MPLEX_BASE+INFO, len=50
        let buf = hdr.to_le_bytes().to_vec();

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(
            result.is_err(),
            "truncated info payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_message_invalid_tag_zero() {
        // Tag byte of 0 is below MPLEX_BASE.
        let hdr: u32 = 10;
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0; 10]);

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(result.is_err(), "tag below MPLEX_BASE should return error");
    }

    #[tokio::test]
    async fn test_read_message_invalid_tag_below_base() {
        // Tag byte of 5 is below MPLEX_BASE (7).
        let hdr: u32 = (5u32 << 24) | 4;
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0; 4]);

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(result.is_err(), "tag below MPLEX_BASE should return error");
    }

    #[tokio::test]
    async fn test_read_message_unknown_message_type() {
        // Tag byte for an unrecognized message code (MPLEX_BASE + 50 = 57).
        let hdr: u32 = 57u32 << 24;
        let buf = hdr.to_le_bytes().to_vec();

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(result.is_err(), "unknown message type should return error");
    }

    #[tokio::test]
    async fn test_read_message_truncated_index_payload() {
        // MSG_REDO (code=9) expects a 4-byte i32 payload, but only 2 bytes given.
        let hdr: u32 = ((MPLEX_BASE as u32 + 9) << 24) | 4; // tag for Redo, len=4
        let mut buf = hdr.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0x01, 0x02]); // only 2 of 4 bytes

        let mut reader = MplexReader::new(Cursor::new(buf));
        let result = reader.read_message().await;
        assert!(
            result.is_err(),
            "truncated index payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_data_truncated_mid_stream() {
        // Build a valid data frame followed by a truncated one.
        let mut buf = Vec::new();

        // First frame: valid 5-byte data.
        let hdr1: u32 = (7u32 << 24) | 5;
        buf.extend_from_slice(&hdr1.to_le_bytes());
        buf.extend_from_slice(b"hello");

        // Second frame: header claims 100 bytes but has only 3.
        let hdr2: u32 = (7u32 << 24) | 100;
        buf.extend_from_slice(&hdr2.to_le_bytes());
        buf.extend_from_slice(&[0xBB; 3]);

        let mut reader = MplexReader::new(Cursor::new(buf));

        // First read should succeed.
        let mut data_buf = [0u8; 64];
        let n = reader.read_data(&mut data_buf, |_| {}).await.unwrap();
        assert_eq!(&data_buf[..n], b"hello");

        // Second read should fail due to truncated payload.
        let result = reader.read_data(&mut data_buf, |_| {}).await;
        assert!(
            result.is_err(),
            "truncated second frame should return error"
        );
    }

    #[tokio::test]
    async fn test_msg_code_from_tag_all_invalid_values() {
        // Verify that unrecognized tag values return errors, not panics.
        let invalid_tags: &[u8] = &[
            11, 12, 13, 20, 21, 23, 30, 40, 41, 43, 50, 80, 85, 87, 99, 103, 200, 255,
        ];
        for &tag in invalid_tags {
            let result = MsgCode::from_tag(tag);
            assert!(result.is_err(), "tag {tag} should return error");
        }
    }
}
