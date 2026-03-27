//! File list entry representation.
//!
//! `FileEntry` holds all metadata for a single file in an rsync transfer.
//! The struct is designed to be protocol-version independent -- the codec
//! layer handles wire format differences.
//!
//! The canonical type definitions live in `ferrosync_types::entry`.
//! This module re-exports them for backward compatibility.

// Re-export all types from ferrosync-types.
pub use ferrosync_types::entry::*;

// Re-export mode constants for backward compatibility.
pub use ferrosync_types::mode::*;

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

#[cfg(test)]
mod tests {
    use super::*;

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
