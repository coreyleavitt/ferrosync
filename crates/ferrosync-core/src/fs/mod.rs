//! Cross-platform filesystem abstraction.
//!
//! The [`FileSystem`] trait provides a uniform interface for filesystem
//! operations needed during rsync transfers. Platform-specific implementations
//! handle metadata mapping (Unix modes, ownership, timestamps).

#[cfg(unix)]
pub mod fake_super;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

mod atomic_writer;
mod file_data;
mod metadata;

pub use file_data::FileData;
pub use metadata::FileMetadata;

use std::io::{Read, Write};
use std::path::Path;

use crate::error::FsError;

type Result<T> = std::result::Result<T, FsError>;

/// Abstraction over filesystem operations needed for rsync transfers.
///
/// Object-safe for testability and future server-mode reuse.
///
/// Platform-specific methods (`set_owner`, `device_id`) are only available
/// on Unix via `#[cfg(unix)]`. Non-Unix platforms should use the platform
/// filesystem implementation which handles these concepts differently.
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
    ///
    /// Only available on Unix platforms. Non-Unix implementations should
    /// handle ownership through platform-specific mechanisms.
    #[cfg(unix)]
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
    ///
    /// Only available on Unix platforms. Non-Unix platforms do not have
    /// a portable device ID concept.
    #[cfg(unix)]
    fn device_id(&self, path: &Path) -> Result<u64>;

    /// List extended attribute names for a path.
    #[cfg(unix)]
    fn list_xattrs(&self, path: &Path) -> Result<Vec<Vec<u8>>>;

    /// Get an extended attribute value.
    #[cfg(unix)]
    fn get_xattr(&self, path: &Path, name: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set an extended attribute value.
    #[cfg(unix)]
    fn set_xattr(&self, path: &Path, name: &[u8], value: &[u8]) -> Result<()>;

    /// Remove an extended attribute.
    #[cfg(unix)]
    fn remove_xattr(&self, path: &Path, name: &[u8]) -> Result<()>;

    /// Write data to a file in-place (overwrites directly, no atomic rename).
    /// Used with `--inplace`. Preserves the file's inode.
    fn write_file_inplace(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.write_file(path, data, mode)
    }

    /// Write data to a file with sparse optimization.
    /// Zero-filled blocks are converted to file holes.
    fn write_file_sparse(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.write_file(path, data, mode)
    }

    /// Append data to the end of a file (creating it if needed).
    fn append_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        // Default: just write the full data (implementations can optimize).
        self.write_file(path, data, mode)
    }

    /// Create a hard link from `link_path` pointing to `target`.
    fn hard_link(&self, target: &Path, link_path: &Path) -> Result<()>;

    /// Rename/move a file or directory.
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;

    /// Copy a file from `src` to `dst`.
    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()>;

    /// Return the file contents as a `FileData`, using mmap for large files.
    ///
    /// Files smaller than [`MMAP_THRESHOLD`] are read into a `Vec`. Empty
    /// files return `FileData::Empty`. The default implementation always
    /// reads into a `Vec`; platform implementations override with mmap.
    fn map_file(&self, path: &Path) -> Result<FileData> {
        let data = self.read_file(path)?;
        if data.is_empty() {
            Ok(FileData::Empty)
        } else {
            Ok(FileData::Vec(data))
        }
    }

    /// Return a streaming reader for the file at `path`.
    ///
    /// Enables reading large files without loading them entirely into memory.
    /// The default implementation reads the whole file via [`read_file`] and
    /// wraps it in a `Cursor`.
    fn read_file_stream(&self, path: &Path) -> Result<Box<dyn Read + Send>> {
        let data = self.read_file(path)?;
        Ok(Box::new(std::io::Cursor::new(data)))
    }

    /// Return a streaming writer for the file at `path`.
    ///
    /// The writer creates the file (or truncates if it exists).
    fn write_file_stream(&self, path: &Path, mode: Option<u32>) -> Result<Box<dyn Write + Send>>;

    /// Open a file for in-place streaming write (truncates existing file).
    ///
    /// Unlike `write_file_stream` which uses a temp file and atomic rename,
    /// this writes directly to the given path, preserving the inode.
    fn write_file_inplace_stream(
        &self,
        path: &Path,
        mode: Option<u32>,
    ) -> Result<Box<dyn Write + Send>>;
}

/// Threshold in bytes above which streaming I/O is preferred over buffered
/// whole-file reads/writes. Currently set to 64 MiB.
pub const STREAMING_THRESHOLD: i64 = 64 * 1024 * 1024;

/// Threshold in bytes below which `map_file` uses a heap buffer instead of
/// mmap. Below 32 KiB the mmap setup cost outweighs the copy.
pub const MMAP_THRESHOLD: i64 = 32 * 1024;

/// A directory entry returned by [`FileSystem::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name (just the filename, not the full path).
    pub name: Vec<u8>,
    /// Metadata for this entry (from lstat).
    pub metadata: FileMetadata,
}
