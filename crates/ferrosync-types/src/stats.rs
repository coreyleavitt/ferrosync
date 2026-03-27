//! Transfer statistics tracking.
//!
//! Collects metrics during a transfer for `--stats` output and
//! progress reporting.

use std::time::{Duration, Instant};

/// Statistics collected during a file transfer.
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// Number of regular files transferred.
    pub files_transferred: u64,
    /// Total number of files in the file list.
    pub total_files: u64,
    /// Total bytes of file data sent over the wire.
    pub bytes_sent: u64,
    /// Total bytes of file data received over the wire.
    pub bytes_received: u64,
    /// Total size of all transferred files (pre-delta).
    pub total_size: u64,
    /// Total size of matched block data (not sent over wire).
    pub matched_data: u64,
    /// Total size of literal data sent.
    pub literal_data: u64,
    /// Number of files that were up to date (skipped).
    pub files_skipped: u64,
    /// Number of files deleted on the receiver.
    pub files_deleted: u64,
    /// Number of symlinks created/updated.
    pub symlinks: u64,
    /// Number of directories created.
    pub directories_created: u64,
    /// When the transfer started.
    start_time: Option<Instant>,
    /// Total elapsed time.
    pub elapsed: Duration,
}

impl Default for TransferStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferStats {
    pub fn new() -> Self {
        Self {
            files_transferred: 0,
            total_files: 0,
            bytes_sent: 0,
            bytes_received: 0,
            total_size: 0,
            matched_data: 0,
            literal_data: 0,
            files_skipped: 0,
            files_deleted: 0,
            symlinks: 0,
            directories_created: 0,
            start_time: None,
            elapsed: Duration::ZERO,
        }
    }

    /// Mark the start of a transfer.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Mark the end of a transfer, recording elapsed time.
    pub fn finish(&mut self) {
        if let Some(start) = self.start_time.take() {
            self.elapsed = start.elapsed();
        }
    }

    /// Effective transfer rate in bytes per second.
    pub fn transfer_rate(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            self.bytes_sent as f64 / secs
        } else {
            0.0
        }
    }

    /// Speedup ratio: total_size / bytes_sent.
    pub fn speedup(&self) -> f64 {
        if self.bytes_sent > 0 {
            self.total_size as f64 / self.bytes_sent as f64
        } else if self.total_size > 0 {
            f64::INFINITY
        } else {
            1.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_stats() {
        let stats = TransferStats::new();
        assert_eq!(stats.files_transferred, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.elapsed, Duration::ZERO);
    }

    #[test]
    fn test_speedup() {
        let mut stats = TransferStats::new();
        stats.total_size = 10_000;
        stats.bytes_sent = 1_000;
        assert!((stats.speedup() - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_speedup_zero_sent() {
        let mut stats = TransferStats::new();
        stats.total_size = 100;
        stats.bytes_sent = 0;
        assert!(stats.speedup().is_infinite());
    }

    #[test]
    fn test_speedup_both_zero() {
        let stats = TransferStats::new();
        assert!((stats.speedup() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_start_finish() {
        let mut stats = TransferStats::new();
        stats.start();
        std::thread::sleep(Duration::from_millis(10));
        stats.finish();
        assert!(stats.elapsed >= Duration::from_millis(5));
    }
}
