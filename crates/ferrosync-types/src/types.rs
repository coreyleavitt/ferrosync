//! Semantic newtypes for values that appear across multiple modules.
//!
//! These types prevent accidental confusion between raw numeric values
//! that carry different meanings (e.g., file sizes vs. timestamps).

use std::fmt;

/// File size in bytes.
///
/// Wraps `i64` because the rsync wire protocol uses signed 64-bit
/// integers for file lengths.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct FileSize(pub i64);

impl FileSize {
    /// Return the raw byte count.
    pub fn bytes(self) -> i64 {
        self.0
    }

    /// Return the byte count as `u64` (for cumulative statistics).
    pub fn as_u64(self) -> u64 {
        self.0 as u64
    }
}

impl From<i64> for FileSize {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl fmt::Debug for FileSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileSize({})", self.0)
    }
}

impl fmt::Display for FileSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::iter::Sum for FileSize {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        FileSize(iter.map(|s| s.0).sum())
    }
}

/// Unix timestamp in seconds since epoch.
///
/// Wraps `i64` because the rsync wire protocol uses signed 64-bit
/// integers for modification times.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct UnixTimestamp(pub i64);

impl UnixTimestamp {
    /// Return the raw seconds value.
    pub fn secs(self) -> i64 {
        self.0
    }

    /// Absolute difference in seconds between two timestamps.
    pub fn abs_diff(self, other: Self) -> i64 {
        (self.0 - other.0).abs()
    }
}

impl From<i64> for UnixTimestamp {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl fmt::Debug for UnixTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnixTimestamp({})", self.0)
    }
}

impl fmt::Display for UnixTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
