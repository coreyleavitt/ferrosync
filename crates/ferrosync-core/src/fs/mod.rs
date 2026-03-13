//! Cross-platform filesystem abstraction.
//!
//! The [`FileSystem`] trait provides a uniform interface for filesystem
//! operations needed during rsync transfers. Platform-specific implementations
//! handle metadata mapping (Unix modes, ownership, timestamps).

#[cfg(unix)]
pub mod unix;

mod metadata;

pub use metadata::FileMetadata;

use std::path::Path;

use crate::error::FsError;

type Result<T> = std::result::Result<T, FsError>;

/// Abstraction over filesystem operations needed for rsync transfers.
///
/// Object-safe for testability and future server-mode reuse.
pub trait FileSystem: Send + Sync {
    /// Read file metadata without following symlinks.
    fn lstat(&self, path: &Path) -> Result<FileMetadata>;

    /// Read file metadata, following symlinks.
    fn stat(&self, path: &Path) -> Result<FileMetadata>;

    /// Read the target of a symbolic link.
    fn read_link(&self, path: &Path) -> Result<Vec<u8>>;

    /// Read the entire contents of a file.
    fn read_file(&self, path: &Path) -> Result<Vec<u8>>;

    /// Write data to a file atomically (write to temp, then rename).
    ///
    /// If `dest` already exists, its permissions are preserved unless
    /// `mode` is `Some`.
    fn write_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()>;

    /// Create a directory (and parents if needed).
    fn mkdir(&self, path: &Path, mode: u32) -> Result<()>;

    /// Create or update a symbolic link.
    fn create_symlink(&self, target: &[u8], link_path: &Path) -> Result<()>;

    /// Set file permissions.
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;

    /// Set file modification time.
    fn set_mtime(&self, path: &Path, mtime: i64, mtime_nsec: u32) -> Result<()>;

    /// Set file ownership (uid, gid). May require elevated privileges.
    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()>;

    /// Remove a file.
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// Remove a directory (must be empty).
    fn remove_dir(&self, path: &Path) -> Result<()>;

    /// List directory entries. Returns relative names (not full paths).
    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>>;

    /// Check if a path exists (does not follow symlinks).
    fn lexists(&self, path: &Path) -> bool;

    /// Get the device ID for a path (for `--one-file-system`).
    fn device_id(&self, path: &Path) -> Result<u64>;
}

/// A directory entry returned by [`FileSystem::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name (just the filename, not the full path).
    pub name: Vec<u8>,
    /// Metadata for this entry (from lstat).
    pub metadata: FileMetadata,
}
