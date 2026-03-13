//! XMIT flag constants for the rsync file list wire format.
//!
//! These flags are transmitted as part of each file entry to indicate which
//! fields have changed relative to the previous entry (delta encoding).

/// Entry is a top-level directory.
pub const XMIT_TOP_DIR: u32 = 1 << 0;

/// File mode unchanged from previous entry.
pub const XMIT_SAME_MODE: u32 = 1 << 1;

/// (Proto < 28) rdev same as previous entry.
pub const XMIT_SAME_RDEV_PRE28: u32 = 1 << 2;

/// (Proto >= 28) A second flag byte follows.
pub const XMIT_EXTENDED_FLAGS: u32 = 1 << 2;

/// UID unchanged from previous entry.
pub const XMIT_SAME_UID: u32 = 1 << 3;

/// GID unchanged from previous entry.
pub const XMIT_SAME_GID: u32 = 1 << 4;

/// Filename shares a prefix with the previous entry.
pub const XMIT_SAME_NAME: u32 = 1 << 5;

/// Filename suffix length > 255 (use varint30 instead of byte).
pub const XMIT_LONG_NAME: u32 = 1 << 6;

/// Modification time unchanged from previous entry.
pub const XMIT_SAME_TIME: u32 = 1 << 7;

/// (Proto >= 28) rdev major unchanged from previous entry.
pub const XMIT_SAME_RDEV_MAJOR: u32 = 1 << 8;

/// (Proto >= 30) Directory with no content to transfer.
pub const XMIT_NO_CONTENT_DIR: u32 = 1 << 8;

/// Entry is a hard link.
pub const XMIT_HLINKED: u32 = 1 << 9;

/// (Proto < 30) Hard link device same as previous.
pub const XMIT_SAME_DEV_PRE30: u32 = 1 << 10;

/// (Proto >= 30) Username string follows uid.
pub const XMIT_USER_NAME_FOLLOWS: u32 = 1 << 10;

/// (Proto < 30) rdev minor fits in 1 byte.
pub const XMIT_RDEV_MINOR_8_PRE30: u32 = 1 << 11;

/// (Proto >= 30) Group name string follows gid.
pub const XMIT_GROUP_NAME_FOLLOWS: u32 = 1 << 11;

/// First occurrence of a hard link group.
pub const XMIT_HLINK_FIRST: u32 = 1 << 12;

/// End-of-list marker with io_error.
pub const XMIT_IO_ERROR_ENDLIST: u32 = 1 << 12;

/// (Proto >= 31) Nanosecond modification time follows.
pub const XMIT_MOD_NSEC: u32 = 1 << 13;

/// Access time unchanged from previous entry.
pub const XMIT_SAME_ATIME: u32 = 1 << 14;

/// Creation time equals mtime (don't send separately).
pub const XMIT_CRTIME_EQ_MTIME: u32 = 1 << 17;
