//! File list entry representation.
//!
//! `FileEntry` holds all metadata for a single file in an rsync transfer.
//! The struct is designed to be protocol-version independent -- the codec
//! layer handles wire format differences.

/// Metadata for a single file in an rsync file list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileEntry {
    /// Full relative path (dirname + basename), stored as bytes for
    /// wire compatibility (rsync paths are not guaranteed UTF-8).
    pub name: Vec<u8>,

    /// File size in bytes.
    pub len: i64,

    /// Modification time (Unix timestamp, seconds).
    pub mtime: i64,

    /// Modification time nanoseconds (proto >= 31, 0 otherwise).
    pub mtime_nsec: u32,

    /// Unix file mode (type + permissions), in wire format.
    /// Use `from_wire_mode` / `to_wire_mode` to convert.
    pub mode: u32,

    /// Owner user ID (0 if not preserved).
    pub uid: u32,

    /// Owner group ID (0 if not preserved).
    pub gid: u32,

    /// Device number (major << 8 | minor) for device/special files.
    pub rdev: u64,

    /// Symlink target path (empty if not a symlink).
    pub link_target: Vec<u8>,

    /// File-level checksum (when `--checksum` is used), empty otherwise.
    pub checksum: Vec<u8>,

    /// Flags from the XMIT encoding (used during transfer, not persisted).
    pub flags: u32,

    /// Owner username (proto >= 30, when name follows uid).
    pub user_name: Vec<u8>,

    /// Group name (proto >= 30, when name follows gid).
    pub group_name: Vec<u8>,

    /// For hardlink duplicates: name of the first occurrence to hardlink from.
    /// Set during file list decoding when `-H` is active. `None` for first
    /// occurrences and non-hardlinked files.
    pub hlink_source: Option<Vec<u8>>,

    /// Hard-link identity from the source filesystem (dev, ino, nlink).
    /// Populated by the scanner when `-H` is active so the encoder can
    /// detect duplicate inodes and emit XMIT_HLINKED flags.
    pub hard_link_info: Option<super::codec::HardLinkInfo>,
}

impl FileEntry {
    /// Returns true if this entry is a regular file.
    pub fn is_file(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    /// Returns true if this entry is a directory.
    pub fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    /// Returns true if this entry is a symlink.
    pub fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == WIRE_S_IFLNK
    }

    /// Returns true if this entry is a block or character device.
    pub fn is_device(&self) -> bool {
        let ft = self.mode & S_IFMT;
        ft == S_IFBLK || ft == S_IFCHR
    }

    /// Returns hard-link identity info for regular files with nlink > 1.
    /// Directories and other non-regular files are never hardlink candidates,
    /// matching rsync's behavior (flist.c only sets tmp_dev for S_ISREG).
    pub fn hard_link_info(&self) -> Option<&super::codec::HardLinkInfo> {
        if self.is_file() {
            self.hard_link_info.as_ref()
        } else {
            None
        }
    }

    /// Returns true if this entry is a special file (FIFO, socket, or
    /// device on proto < 31).
    pub fn is_special(&self) -> bool {
        let ft = self.mode & S_IFMT;
        ft == S_IFIFO || ft == S_IFSOCK
    }

    /// Extract the dirname portion (everything before the last `/`).
    /// Returns `None` if there is no directory component.
    pub fn dirname(&self) -> Option<&[u8]> {
        self.name
            .iter()
            .rposition(|&b| b == b'/')
            .map(|pos| &self.name[..pos])
    }

    /// Extract the basename portion (everything after the last `/`).
    pub fn basename(&self) -> &[u8] {
        match self.name.iter().rposition(|&b| b == b'/') {
            Some(pos) => &self.name[pos + 1..],
            None => &self.name,
        }
    }

    /// Device major number.
    pub fn rdev_major(&self) -> u32 {
        (self.rdev >> 8) as u32
    }

    /// Device minor number.
    pub fn rdev_minor(&self) -> u32 {
        (self.rdev & 0xFF) as u32
    }

    /// Convert the byte name to a [`PathBuf`], preserving non-UTF-8 on Unix.
    pub fn path(&self) -> std::path::PathBuf {
        Self::name_to_pathbuf(&self.name)
    }

    /// Format this entry for `--list-only` output (rsync ls -l style).
    pub fn format_list_entry(&self) -> String {
        let mode_str = format_mode(self.mode);
        let size = self.len;
        let name = String::from_utf8_lossy(&self.name);
        // Format mtime as YYYY/MM/DD HH:MM:SS
        let mtime_str = format_mtime(self.mtime);
        format!("{mode_str} {size:>12} {mtime_str} {name}")
    }

    /// Convert a byte slice to a [`PathBuf`].
    ///
    /// On Unix, uses `OsStr::from_bytes` to preserve arbitrary byte sequences.
    /// On other platforms, uses lossy UTF-8 conversion.
    pub fn name_to_pathbuf(bytes: &[u8]) -> std::path::PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
        }
        #[cfg(not(unix))]
        {
            std::path::PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// Wire mode constants and conversion
// ---------------------------------------------------------------------------

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

/// Convert a platform file mode to the wire representation.
///
/// The only transformation: symlink modes are normalized to use `0120000`
/// as the file-type bits, regardless of the platform's `S_IFLNK` value.
#[cfg(unix)]
pub fn to_wire_mode(mode: u32) -> u32 {
    if (mode & S_IFMT) == S_IFLNK {
        (mode & !S_IFMT) | WIRE_S_IFLNK
    } else {
        mode
    }
}

/// Convert a platform file mode to the wire representation (non-Unix).
#[cfg(not(unix))]
pub fn to_wire_mode(mode: u32) -> u32 {
    mode
}

/// Convert a wire file mode back to the platform representation.
#[cfg(unix)]
pub fn from_wire_mode(mode: u32) -> u32 {
    if (mode & S_IFMT) == WIRE_S_IFLNK {
        (mode & !S_IFMT) | S_IFLNK
    } else {
        mode
    }
}

/// Convert a wire file mode back to the platform representation (non-Unix).
#[cfg(not(unix))]
pub fn from_wire_mode(mode: u32) -> u32 {
    mode
}

/// Compute the entry name from a source path, optionally preserving the
/// full relative path structure.
///
/// When `relative` is true (corresponding to rsync's `-R` / `--relative`
/// flag), the entry name includes intermediate directories so that the
/// receiver can recreate the source's directory hierarchy. If the path
/// contains a `/./` marker (the rsync convention for splitting implied
/// dirs from the transfer root), everything after the marker becomes the
/// name. Otherwise the full path minus the leading `/` is used.
///
/// When `relative` is false, only the basename is returned (standard
/// rsync behavior for single-source transfers).
pub fn compute_entry_name(source: &std::path::Path, relative: bool) -> Vec<u8> {
    if relative {
        let s = source.to_string_lossy();
        // Check for /./ marker (rsync convention for splitting the path).
        if let Some(pos) = s.find("/./") {
            let after = &s[pos + 3..];
            return after.as_bytes().to_vec();
        }
        // Strip leading / if present, use full path.
        let s = s.strip_prefix('/').unwrap_or(&s);
        return s.as_bytes().to_vec();
    }

    // Default: basename only.
    source
        .file_name()
        .map(|n| {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                n.as_bytes().to_vec()
            }
            #[cfg(not(unix))]
            {
                n.to_string_lossy().as_bytes().to_vec()
            }
        })
        .unwrap_or_default()
}

/// Format a Unix mode as a human-readable permission string (e.g., "drwxr-xr-x").
fn format_mode(mode: u32) -> String {
    let file_type = match mode & S_IFMT {
        S_IFDIR => 'd',
        0o120000 => 'l', // S_IFLNK
        0o060000 => 'b', // S_IFBLK
        0o020000 => 'c', // S_IFCHR
        0o010000 => 'p', // S_IFIFO
        0o140000 => 's', // S_IFSOCK
        _ => '-',        // S_IFREG or unknown
    };

    let perms = mode & 0o7777;
    let mut s = String::with_capacity(10);
    s.push(file_type);
    s.push(if perms & 0o400 != 0 { 'r' } else { '-' });
    s.push(if perms & 0o200 != 0 { 'w' } else { '-' });
    s.push(if perms & 0o4000 != 0 {
        if perms & 0o100 != 0 {
            's'
        } else {
            'S'
        }
    } else if perms & 0o100 != 0 {
        'x'
    } else {
        '-'
    });
    s.push(if perms & 0o040 != 0 { 'r' } else { '-' });
    s.push(if perms & 0o020 != 0 { 'w' } else { '-' });
    s.push(if perms & 0o2000 != 0 {
        if perms & 0o010 != 0 {
            's'
        } else {
            'S'
        }
    } else if perms & 0o010 != 0 {
        'x'
    } else {
        '-'
    });
    s.push(if perms & 0o004 != 0 { 'r' } else { '-' });
    s.push(if perms & 0o002 != 0 { 'w' } else { '-' });
    s.push(if perms & 0o1000 != 0 {
        if perms & 0o001 != 0 {
            't'
        } else {
            'T'
        }
    } else if perms & 0o001 != 0 {
        'x'
    } else {
        '-'
    });
    s
}

/// Format a Unix timestamp as YYYY/MM/DD HH:MM:SS.
fn format_mtime(mtime: i64) -> String {
    // Simple UTC formatting without external dependencies.
    // Approximate: days since epoch, then break into Y/M/D.
    let secs_per_day = 86400i64;
    let days = mtime / secs_per_day;
    let time_of_day = (mtime % secs_per_day) as u32;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}/{m:02}/{d:02} {hours:02}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn test_format_mode_regular_file() {
        assert_eq!(format_mode(0o100644), "-rw-r--r--");
    }

    #[test]
    fn test_format_mode_directory() {
        assert_eq!(format_mode(0o040755), "drwxr-xr-x");
    }

    #[test]
    fn test_format_mode_executable() {
        assert_eq!(format_mode(0o100755), "-rwxr-xr-x");
    }

    #[test]
    fn test_format_mode_symlink() {
        assert_eq!(format_mode(0o120777), "lrwxrwxrwx");
    }

    #[test]
    fn test_format_mtime() {
        // 2024-01-15 11:50:45 UTC = 1705319445
        let s = format_mtime(1705319445);
        assert_eq!(s, "2024/01/15 11:50:45");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_entry_defaults() {
        let e = FileEntry::default();
        assert!(!e.is_file());
        assert!(!e.is_dir());
        assert!(!e.is_symlink());
        assert!(e.name.is_empty());
        assert_eq!(e.len, 0);
    }

    #[test]
    fn test_file_type_checks() {
        let e = FileEntry {
            mode: S_IFREG | 0o644,
            ..Default::default()
        };
        assert!(e.is_file());
        assert!(!e.is_dir());

        let e = FileEntry {
            mode: S_IFDIR | 0o755,
            ..Default::default()
        };
        assert!(e.is_dir());
        assert!(!e.is_file());

        let e = FileEntry {
            mode: WIRE_S_IFLNK | 0o777,
            ..Default::default()
        };
        assert!(e.is_symlink());

        let e = FileEntry {
            mode: S_IFBLK | 0o660,
            ..Default::default()
        };
        assert!(e.is_device());

        let e = FileEntry {
            mode: S_IFIFO | 0o644,
            ..Default::default()
        };
        assert!(e.is_special());
    }

    #[test]
    fn test_dirname_basename() {
        let e = FileEntry {
            name: b"foo/bar/baz.txt".to_vec(),
            ..Default::default()
        };
        assert_eq!(e.dirname(), Some(b"foo/bar".as_slice()));
        assert_eq!(e.basename(), b"baz.txt");

        let e = FileEntry {
            name: b"simple.txt".to_vec(),
            ..Default::default()
        };
        assert_eq!(e.dirname(), None);
        assert_eq!(e.basename(), b"simple.txt");
    }

    #[test]
    fn test_path_utf8() {
        let e = FileEntry {
            name: b"hello/world.txt".to_vec(),
            ..Default::default()
        };
        assert_eq!(e.path(), std::path::PathBuf::from("hello/world.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn test_path_non_utf8_unix() {
        let e = FileEntry {
            name: b"hello/\xff\xfe.bin".to_vec(),
            ..Default::default()
        };
        use std::os::unix::ffi::OsStrExt;
        let expected = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"hello/\xff\xfe.bin"));
        assert_eq!(e.path(), expected);
    }

    #[test]
    fn test_name_to_pathbuf_static() {
        let p = FileEntry::name_to_pathbuf(b"foo/bar");
        assert_eq!(p, std::path::PathBuf::from("foo/bar"));
    }

    #[test]
    fn test_wire_mode_roundtrip() {
        // Regular file should pass through unchanged.
        let mode = S_IFREG | 0o644;
        assert_eq!(from_wire_mode(to_wire_mode(mode)), mode);

        // Directory should pass through unchanged.
        let mode = S_IFDIR | 0o755;
        assert_eq!(from_wire_mode(to_wire_mode(mode)), mode);
    }
}
