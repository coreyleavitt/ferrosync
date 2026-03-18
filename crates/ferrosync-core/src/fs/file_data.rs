//! Memory-mapped or heap-allocated file data.
//!
//! `FileData` wraps either a memory-mapped region or a `Vec<u8>`,
//! presenting a uniform `&[u8]` interface via `Deref`. This avoids
//! copying large files into heap buffers while keeping small-file
//! and fallback paths simple.

use std::ops::Deref;

/// File contents backed by either an mmap region or a heap buffer.
///
/// All consumers take `&[u8]` and auto-deref through this type,
/// so switching from `Vec<u8>` to `FileData` requires zero changes
/// in the delta/checksum layer.
#[derive(Default)]
pub enum FileData {
    /// Memory-mapped file (zero-copy for large files).
    Mmap(memmap2::Mmap),
    /// Heap-allocated buffer (small files or mmap fallback).
    Vec(Vec<u8>),
    /// Empty file (no allocation needed).
    #[default]
    Empty,
}

impl Deref for FileData {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            FileData::Mmap(m) => m,
            FileData::Vec(v) => v,
            FileData::Empty => &[],
        }
    }
}

impl AsRef<[u8]> for FileData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
