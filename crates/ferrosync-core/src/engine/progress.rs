//! Progress tracking with callbacks for file transfers.
//!
//! The progress system allows callers to observe transfer progress
//! at both per-file and overall levels.

/// Progress event emitted during a transfer.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Starting to process a file.
    FileStart {
        /// File index in the file list.
        index: i32,
        /// File name (relative path).
        name: Vec<u8>,
        /// Total file size in bytes.
        size: i64,
    },
    /// Progress on the current file.
    FileProgress {
        /// File index.
        index: i32,
        /// Bytes transferred so far for this file.
        bytes_transferred: u64,
        /// Total file size.
        total_size: i64,
    },
    /// Finished transferring a file.
    FileComplete {
        /// File index.
        index: i32,
        /// File name.
        name: Vec<u8>,
        /// Bytes of literal data sent (not matched).
        literal_bytes: u64,
        /// Bytes matched from basis file.
        matched_bytes: u64,
    },
    /// A file was skipped (already up to date).
    FileSkipped {
        /// File index.
        index: i32,
        /// File name.
        name: Vec<u8>,
    },
    /// A file was deleted from the receiver.
    FileDeleted {
        /// File name.
        name: Vec<u8>,
    },
    /// Overall transfer progress.
    OverallProgress {
        /// Files completed so far.
        files_done: u64,
        /// Total files to process.
        files_total: u64,
        /// Total bytes transferred so far.
        bytes_transferred: u64,
        /// Total bytes to transfer.
        bytes_total: u64,
    },
}

/// Callback type for progress events.
pub type ProgressCallback = Box<dyn Fn(&ProgressEvent) + Send + Sync>;

/// Progress tracker that dispatches events to registered callbacks.
pub struct ProgressTracker {
    callback: Option<ProgressCallback>,
    files_done: u64,
    files_total: u64,
    bytes_transferred: u64,
    bytes_total: u64,
}

impl std::fmt::Debug for ProgressTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressTracker")
            .field("files_done", &self.files_done)
            .field("files_total", &self.files_total)
            .field("bytes_transferred", &self.bytes_transferred)
            .field("bytes_total", &self.bytes_total)
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            callback: None,
            files_done: 0,
            files_total: 0,
            bytes_transferred: 0,
            bytes_total: 0,
        }
    }

    /// Create a tracker with a callback.
    pub fn with_callback(callback: ProgressCallback) -> Self {
        Self {
            callback: Some(callback),
            ..Self::new()
        }
    }

    /// Set the total file count and byte count for overall progress.
    pub fn set_totals(&mut self, files: u64, bytes: u64) {
        self.files_total = files;
        self.bytes_total = bytes;
    }

    /// Emit a progress event.
    pub fn emit(&mut self, event: ProgressEvent) {
        match &event {
            ProgressEvent::FileComplete { .. } | ProgressEvent::FileSkipped { .. } => {
                self.files_done += 1;
            }
            ProgressEvent::FileProgress {
                bytes_transferred, ..
            } => {
                self.bytes_transferred = *bytes_transferred;
            }
            _ => {}
        }

        if let Some(cb) = &self.callback {
            cb(&event);
        }
    }

    /// Emit an overall progress event.
    pub fn emit_overall(&self) {
        if let Some(cb) = &self.callback {
            cb(&ProgressEvent::OverallProgress {
                files_done: self.files_done,
                files_total: self.files_total,
                bytes_transferred: self.bytes_transferred,
                bytes_total: self.bytes_total,
            });
        }
    }

    /// Number of files completed.
    pub fn files_done(&self) -> u64 {
        self.files_done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_progress_tracker_no_callback() {
        let mut tracker = ProgressTracker::new();
        tracker.set_totals(10, 1000);
        // Should not panic with no callback.
        tracker.emit(ProgressEvent::FileStart {
            index: 0,
            name: b"test.txt".to_vec(),
            size: 100,
        });
        tracker.emit(ProgressEvent::FileComplete {
            index: 0,
            name: b"test.txt".to_vec(),
            literal_bytes: 50,
            matched_bytes: 50,
        });
        assert_eq!(tracker.files_done(), 1);
    }

    #[test]
    fn test_progress_callback() {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let mut tracker = ProgressTracker::with_callback(Box::new(move |event| {
            let desc = match event {
                ProgressEvent::FileStart { name, .. } => {
                    format!("start:{}", String::from_utf8_lossy(name))
                }
                ProgressEvent::FileComplete { name, .. } => {
                    format!("complete:{}", String::from_utf8_lossy(name))
                }
                _ => "other".to_string(),
            };
            events_clone.lock().unwrap().push(desc);
        }));

        tracker.emit(ProgressEvent::FileStart {
            index: 0,
            name: b"a.txt".to_vec(),
            size: 10,
        });
        tracker.emit(ProgressEvent::FileComplete {
            index: 0,
            name: b"a.txt".to_vec(),
            literal_bytes: 10,
            matched_bytes: 0,
        });

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], "start:a.txt");
        assert_eq!(captured[1], "complete:a.txt");
    }

    #[test]
    fn test_overall_progress() {
        let seen_overall = Arc::new(Mutex::new(false));
        let seen_clone = seen_overall.clone();

        let mut tracker = ProgressTracker::with_callback(Box::new(move |event| {
            if matches!(event, ProgressEvent::OverallProgress { .. }) {
                *seen_clone.lock().unwrap() = true;
            }
        }));

        tracker.set_totals(5, 5000);
        tracker.emit_overall();

        assert!(*seen_overall.lock().unwrap());
    }
}
