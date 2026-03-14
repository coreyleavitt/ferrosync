//! Streaming file list with transfer overlap.
//!
//! Allows the generator to begin producing file signatures before the
//! complete file list has been received, enabling overlap between file
//! enumeration and transfer.

use tokio::sync::mpsc;

use crate::filelist::entry::FileEntry;

/// Default bounded channel capacity for streaming file lists.
const DEFAULT_CAPACITY: usize = 256;

/// Consumer side of a streaming file list.
///
/// Wraps an `mpsc::Receiver<FileEntry>` for incremental consumption of
/// file entries as they arrive from the wire.
#[derive(Debug)]
pub struct StreamingFileList {
    rx: mpsc::Receiver<FileEntry>,
    /// Tracks whether the sender has closed the channel.
    complete: bool,
}

impl StreamingFileList {
    /// Get the next file entry as it arrives.
    ///
    /// Returns `None` when the sender has closed the channel (all entries
    /// have been sent).
    pub async fn next(&mut self) -> Option<FileEntry> {
        match self.rx.recv().await {
            Some(entry) => Some(entry),
            None => {
                self.complete = true;
                None
            }
        }
    }

    /// Returns `true` if the sender has closed the channel, meaning all
    /// entries have been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Producer side of a streaming file list.
///
/// Wraps an `mpsc::Sender<FileEntry>` for incremental production of
/// file entries. When dropped (or `complete()` is called), signals to
/// the consumer that no more entries will arrive.
#[derive(Debug, Clone)]
pub struct StreamingFileListBuilder {
    tx: mpsc::Sender<FileEntry>,
}

impl StreamingFileListBuilder {
    /// Send a file entry to the consumer.
    ///
    /// Back-pressures when the bounded buffer is full.
    /// Returns an error if the consumer has been dropped.
    pub async fn push(&self, entry: FileEntry) -> Result<(), StreamingPushError> {
        self.tx
            .send(entry)
            .await
            .map_err(|_| StreamingPushError::ReceiverDropped)
    }

    /// Signal that no more entries will be sent.
    ///
    /// This drops the sender, which causes the consumer's `next()` to
    /// return `None`.
    pub fn complete(self) {
        // Dropping self.tx closes the channel.
        drop(self);
    }
}

/// Error returned when pushing to a streaming file list whose consumer
/// has been dropped.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StreamingPushError {
    #[error("streaming file list receiver was dropped")]
    ReceiverDropped,
}

/// Create a new streaming file list pair with the given buffer capacity.
///
/// The `capacity` parameter controls the bounded channel size. A larger
/// capacity allows more entries to be buffered, reducing the chance of
/// the producer blocking, at the cost of memory.
pub fn new_streaming_flist(capacity: usize) -> (StreamingFileListBuilder, StreamingFileList) {
    let (tx, rx) = mpsc::channel(capacity);
    (
        StreamingFileListBuilder { tx },
        StreamingFileList {
            rx,
            complete: false,
        },
    )
}

/// Create a new streaming file list pair with the default capacity (256).
pub fn new_streaming_flist_default() -> (StreamingFileListBuilder, StreamingFileList) {
    new_streaming_flist(DEFAULT_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filelist::entry::{S_IFDIR, S_IFREG};

    fn make_file_entry(name: &[u8], size: i64) -> FileEntry {
        FileEntry {
            name: name.to_vec(),
            len: size,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        }
    }

    fn make_dir_entry(name: &[u8]) -> FileEntry {
        FileEntry {
            name: name.to_vec(),
            len: 0,
            mtime: 1700000000,
            mode: S_IFDIR | 0o755,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_producer_consumer_in_order() {
        let (builder, mut flist) = new_streaming_flist(16);

        let entries = vec![
            make_dir_entry(b"subdir"),
            make_file_entry(b"subdir/a.txt", 100),
            make_file_entry(b"subdir/b.txt", 200),
        ];

        let expected = entries.clone();

        // Spawn producer.
        tokio::spawn(async move {
            for entry in entries {
                builder.push(entry).await.unwrap();
            }
            builder.complete();
        });

        // Consumer receives in order.
        let mut received = Vec::new();
        while let Some(entry) = flist.next().await {
            received.push(entry);
        }

        assert!(flist.is_complete());
        assert_eq!(received.len(), 3);
        for (got, want) in received.iter().zip(expected.iter()) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.len, want.len);
        }
    }

    #[tokio::test]
    async fn test_bounded_backpressure() {
        // Use a very small buffer to test backpressure.
        let (builder, mut flist) = new_streaming_flist(2);

        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();

        let producer = tokio::spawn(async move {
            // First two go into the buffer immediately.
            builder.push(make_file_entry(b"1.txt", 1)).await.unwrap();
            builder.push(make_file_entry(b"2.txt", 2)).await.unwrap();
            // Signal that we've filled the buffer.
            started_tx.send(()).unwrap();
            // Third will block until consumer reads.
            builder.push(make_file_entry(b"3.txt", 3)).await.unwrap();
            builder.complete();
        });

        // Wait for producer to fill the buffer.
        started_rx.await.unwrap();

        // Now consume all.
        let mut count = 0;
        while let Some(_entry) = flist.next().await {
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(flist.is_complete());

        producer.await.unwrap();
    }

    #[tokio::test]
    async fn test_complete_signal_propagates() {
        let (builder, mut flist) = new_streaming_flist(16);

        assert!(!flist.is_complete());

        // Drop the builder immediately to signal completion.
        builder.complete();

        // Consumer should get None.
        let result = flist.next().await;
        assert!(result.is_none());
        assert!(flist.is_complete());
    }

    #[tokio::test]
    async fn test_empty_file_list() {
        let (builder, mut flist) = new_streaming_flist(16);

        // Complete immediately without sending any entries.
        builder.complete();

        assert!(flist.next().await.is_none());
        assert!(flist.is_complete());
    }

    #[tokio::test]
    async fn test_large_file_list_ordering() {
        let (builder, mut flist) = new_streaming_flist(64);

        let count = 1500;

        // Spawn producer that sends 1500 entries.
        tokio::spawn(async move {
            for i in 0..count {
                let name = format!("file_{:05}.dat", i);
                let entry = make_file_entry(name.as_bytes(), i as i64);
                builder.push(entry).await.unwrap();
            }
            builder.complete();
        });

        // Verify ordering is preserved.
        let mut received = 0usize;
        while let Some(entry) = flist.next().await {
            let expected_name = format!("file_{:05}.dat", received);
            assert_eq!(entry.name, expected_name.as_bytes());
            assert_eq!(entry.len, received as i64);
            received += 1;
        }

        assert_eq!(received, count);
        assert!(flist.is_complete());
    }

    #[tokio::test]
    async fn test_consumer_dropped_before_producer() {
        let (builder, flist) = new_streaming_flist(4);

        // Drop the consumer.
        drop(flist);

        // Producer should get an error.
        let result = builder.push(make_file_entry(b"orphan.txt", 0)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_directories_before_children() {
        let (builder, mut flist) = new_streaming_flist(16);

        // Simulate a sender that sends directories before their children.
        tokio::spawn(async move {
            builder.push(make_dir_entry(b"alpha")).await.unwrap();
            builder
                .push(make_file_entry(b"alpha/one.txt", 10))
                .await
                .unwrap();
            builder
                .push(make_file_entry(b"alpha/two.txt", 20))
                .await
                .unwrap();
            builder.push(make_dir_entry(b"beta")).await.unwrap();
            builder
                .push(make_file_entry(b"beta/three.txt", 30))
                .await
                .unwrap();
            builder.complete();
        });

        let mut received = Vec::new();
        while let Some(entry) = flist.next().await {
            received.push(entry);
        }

        assert_eq!(received.len(), 5);
        // Verify directory comes before its children.
        assert_eq!(received[0].name, b"alpha");
        assert!(received[0].is_dir());
        assert_eq!(received[1].name, b"alpha/one.txt");
        assert!(received[1].is_file());
        assert_eq!(received[3].name, b"beta");
        assert!(received[3].is_dir());
    }

    #[tokio::test]
    async fn test_default_capacity() {
        let (_builder, _flist) = new_streaming_flist_default();
        // Just verify it doesn't panic.
    }

    #[tokio::test]
    async fn test_checkpoint_streaming_integration() {
        use super::super::checkpoint::{Checkpoint, CheckpointFile};
        use std::path::PathBuf;

        let dir = tempfile::tempdir().unwrap();
        let (builder, mut flist) = new_streaming_flist(16);

        // Simulate a partial transfer: first file fully done, second partially done.
        let files = vec![
            make_file_entry(b"complete.dat", 8192),
            make_file_entry(b"partial.dat", 16384),
            make_file_entry(b"pending.dat", 4096),
        ];

        // Save checkpoint for the partial file.
        let mut ckpt = Checkpoint::new(
            PathBuf::from("partial.dat"),
            16384,
            4096, // 4 blocks
            99,
            1700000000,
        );
        {
            let mut state = ckpt.resume_state();
            state.mark_block_done(0);
            state.mark_block_done(1);
            // blocks 2 and 3 still pending
        }
        CheckpointFile::save(dir.path(), &ckpt).unwrap();

        // Send files through the streaming list.
        let files_clone = files.clone();
        tokio::spawn(async move {
            for f in files_clone {
                builder.push(f).await.unwrap();
            }
            builder.complete();
        });

        // Consumer processes files, checking for checkpoints.
        let mut processed = Vec::new();
        while let Some(entry) = flist.next().await {
            let filename = String::from_utf8_lossy(&entry.name).to_string();
            let ckpt = CheckpointFile::load(dir.path(), &filename).unwrap();

            if let Some(mut ckpt) = ckpt {
                let state = ckpt.resume_state();
                let remaining = state.blocks_remaining();
                processed.push((filename, remaining));
            } else {
                // No checkpoint -- all blocks needed.
                processed.push((filename, usize::MAX));
            }
        }

        assert_eq!(processed.len(), 3);
        // complete.dat has no checkpoint, needs all blocks.
        assert_eq!(processed[0].0, "complete.dat");
        assert_eq!(processed[0].1, usize::MAX);
        // partial.dat has checkpoint with 2 of 4 blocks remaining.
        assert_eq!(processed[1].0, "partial.dat");
        assert_eq!(processed[1].1, 2);
        // pending.dat has no checkpoint.
        assert_eq!(processed[2].0, "pending.dat");
        assert_eq!(processed[2].1, usize::MAX);

        // Clean up checkpoint after "completing" the transfer.
        CheckpointFile::remove(dir.path(), "partial.dat").unwrap();
        assert!(CheckpointFile::load(dir.path(), "partial.dat")
            .unwrap()
            .is_none());
    }
}
