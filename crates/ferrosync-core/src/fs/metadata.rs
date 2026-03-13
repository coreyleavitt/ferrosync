//! Platform-independent file metadata.

/// File metadata used for transfer decisions and attribute preservation.
#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    /// File size in bytes.
    pub len: i64,
    /// Modification time (Unix timestamp, seconds).
    pub mtime: i64,
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
    /// Convert to a [`crate::filelist::entry::FileEntry`] for file list building.
    pub fn to_file_entry(&self, name: Vec<u8>) -> crate::filelist::entry::FileEntry {
        use crate::filelist::entry;
        crate::filelist::entry::FileEntry {
            name,
            len: self.len,
            mtime: self.mtime,
            mtime_nsec: self.mtime_nsec,
            mode: entry::to_wire_mode(self.mode),
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            ..Default::default()
        }
    }
}
