//! Platform-independent file metadata.

use ferrosync_types::entry::{FileEntry, HardLinkInfo};
use ferrosync_types::mode::*;
use ferrosync_types::types::{FileSize, UnixTimestamp};

/// File metadata used for transfer decisions and attribute preservation.
#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    /// File size in bytes.
    pub len: FileSize,
    /// Modification time (Unix timestamp, seconds).
    pub mtime: UnixTimestamp,
    /// Modification time nanoseconds.
    pub mtime_nsec: u32,
    /// File mode (type + permissions), in platform format.
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device number for device files.
    pub rdev: u64,
    /// Device ID of the filesystem containing this file.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Number of hard links.
    pub nlink: u64,
}

impl FileMetadata {
    /// Get hard-link identity info (only meaningful when nlink > 1).
    pub fn hard_link_info(&self) -> Option<HardLinkInfo> {
        if self.nlink > 1 {
            Some(HardLinkInfo {
                dev: self.dev,
                ino: self.ino,
                nlink: self.nlink,
            })
        } else {
            None
        }
    }

    /// Convert to a [`FileEntry`] for file list building.
    pub fn to_file_entry(&self, name: Vec<u8>) -> FileEntry {
        FileEntry {
            name,
            len: self.len,
            mtime: self.mtime,
            mtime_nsec: self.mtime_nsec,
            mode: to_wire_mode(self.mode),
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            hard_link_info: self.hard_link_info(),
            ..Default::default()
        }
    }
}

/// Convert a platform file mode to the wire representation.
///
/// The only transformation: symlink modes are normalized to use `0120000`
/// as the file-type bits, regardless of the platform's `S_IFLNK` value.
#[cfg(unix)]
fn to_wire_mode(mode: u32) -> u32 {
    if (mode & S_IFMT) == S_IFLNK {
        (mode & !S_IFMT) | WIRE_S_IFLNK
    } else {
        mode
    }
}

/// Convert a platform file mode to the wire representation (non-Unix).
#[cfg(not(unix))]
fn to_wire_mode(mode: u32) -> u32 {
    mode
}
