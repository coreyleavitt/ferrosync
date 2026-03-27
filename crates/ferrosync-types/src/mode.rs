//! Unix file mode type constants.
//!
//! These are the POSIX `S_IF*` constants used for file type identification
//! on the wire. They are platform-independent values matching the standard
//! Unix definitions.

/// File type bitmask (POSIX S_IFMT).
pub const S_IFMT: u32 = 0o170000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// Symlink (0o120000). Identical on all Unix platforms and on the wire.
pub const S_IFLNK: u32 = 0o120000;
/// Alias for backward compat.
pub const WIRE_S_IFLNK: u32 = S_IFLNK;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// FIFO.
pub const S_IFIFO: u32 = 0o010000;
/// Socket.
pub const S_IFSOCK: u32 = 0o140000;
