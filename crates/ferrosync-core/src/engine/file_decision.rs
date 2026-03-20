//! Per-file decision logic for transfers.
//!
//! Pure functions extracted from `transfer.rs` that decide whether a file
//! should be skipped, how to write it, and what metadata to set. Used by
//! both the local transfer engine and the wire-level receiver.

use std::path::{Path, PathBuf};

use crate::filelist::entry::FileEntry;
use crate::fs::FileSystem;
use crate::options::TransferOptions;

use super::progress::ItemizedChanges;

/// Check if a file should be skipped based on existence checks.
///
/// Returns `true` if `--existing` is set and dest doesn't exist, or
/// `--ignore-existing` is set and dest exists.
pub fn check_existence_skip(
    fs: &dyn FileSystem,
    dest_path: &Path,
    options: &TransferOptions,
) -> bool {
    let dest_exists = fs.lexists(dest_path);
    if options.existing() && !dest_exists {
        return true;
    }
    if options.ignore_existing() && dest_exists {
        return true;
    }
    false
}

/// Check if a file should be skipped based on size and mtime comparison.
///
/// Returns `true` if the destination file exists with the same size and
/// an mtime that indicates it is already up-to-date.
pub fn quick_check_skip(
    fs: &dyn FileSystem,
    src_entry: &FileEntry,
    dest_path: &Path,
    options: &TransferOptions,
) -> bool {
    // --ignore-times: never skip, always transfer
    if options.ignore_times() {
        return false;
    }

    let dest_meta = match fs.lstat(dest_path) {
        Ok(m) => m,
        Err(_) => return false, // dest doesn't exist, must transfer
    };

    // Size differs -> must transfer.
    if dest_meta.len != src_entry.len {
        return false;
    }

    // --size-only: sizes match -> skip (don't check mtime)
    if options.size_only() {
        return true;
    }

    // --update: skip if dest is newer.
    if options.update() && dest_meta.mtime > src_entry.mtime {
        return true;
    }

    // Same size and same mtime -> skip.
    if dest_meta.mtime == src_entry.mtime {
        return true;
    }

    false
}

/// Check if an identical file exists in any of the alternate destination dirs.
///
/// Returns the path in the alt dir if size and mtime match.
pub fn check_alt_dest(
    fs: &dyn FileSystem,
    src_entry: &FileEntry,
    alt_dirs: &[PathBuf],
) -> Option<PathBuf> {
    for dir in alt_dirs {
        let alt_path = dir.join(src_entry.path());
        if let Ok(meta) = fs.lstat(&alt_path) {
            if meta.len == src_entry.len && meta.mtime == src_entry.mtime {
                return Some(alt_path);
            }
        }
    }
    None
}

/// Resolve --link-dest directories relative to the destination.
///
/// rsync resolves relative paths against the destination directory.
/// Absolute paths are used as-is.
pub fn resolve_link_dest_dirs(link_dest: &[PathBuf], dest: &Path) -> Vec<PathBuf> {
    link_dest
        .iter()
        .map(|d| {
            if d.is_relative() {
                dest.join(d)
            } else {
                d.clone()
            }
        })
        .collect()
}

/// Check if a file should be skipped based on size limits.
///
/// Returns `true` if the file exceeds `--max-size` or is below `--min-size`.
pub fn check_size_limits(entry: &FileEntry, options: &TransferOptions) -> bool {
    if let Some(max) = options.max_size() {
        if entry.len as u64 > max {
            return true;
        }
    }
    if let Some(min) = options.min_size() {
        if (entry.len as u64) < min {
            return true;
        }
    }
    false
}

/// Create a backup of a file before overwriting.
pub fn create_backup(
    fs: &dyn FileSystem,
    path: &Path,
    suffix: &str,
    backup_dir: Option<&Path>,
) -> std::result::Result<(), crate::error::FsError> {
    let file_name = path.file_name().unwrap_or_default();
    let backup_name = format!("{}{}", file_name.to_string_lossy(), suffix);

    let backup_path = if let Some(dir) = backup_dir {
        fs.mkdir(dir, 0o755)?;
        dir.join(&backup_name)
    } else {
        path.with_file_name(&backup_name)
    };

    fs.rename(path, &backup_path)
}

/// Write a file choosing the appropriate method based on options.
pub fn write_file_with_options(
    fs: &dyn FileSystem,
    dest_path: &Path,
    data: &[u8],
    entry: &FileEntry,
    options: &TransferOptions,
) -> std::result::Result<(), crate::FerrosyncError> {
    let mode = if options.preserve_perms() {
        Some(entry.mode & 0o7777)
    } else {
        None
    };

    if options.sparse() {
        fs.write_file_sparse(dest_path, data, mode)?;
    } else if options.inplace() {
        fs.write_file_inplace(dest_path, data, mode)?;
    } else if data.len() as i64 >= crate::fs::STREAMING_THRESHOLD {
        use std::io::Write;
        let mut writer = fs.write_file_stream(dest_path, mode)?;
        writer.write_all(data).map_err(|e| {
            crate::FerrosyncError::Fs(crate::error::FsError::Io {
                path: dest_path.to_path_buf(),
                source: std::sync::Arc::new(e),
            })
        })?;
        writer.flush().map_err(|e| {
            crate::FerrosyncError::Fs(crate::error::FsError::Io {
                path: dest_path.to_path_buf(),
                source: std::sync::Arc::new(e),
            })
        })?;
    } else {
        fs.write_file(dest_path, data, mode)?;
    }

    Ok(())
}

/// Set file metadata (times, ownership) based on options.
pub fn set_file_metadata(
    fs: &dyn FileSystem,
    dest_path: &Path,
    entry: &FileEntry,
    options: &TransferOptions,
) {
    if options.preserve_times() {
        if let Err(e) = fs.set_mtime(dest_path, entry.mtime, entry.mtime_nsec) {
            tracing::warn!(path = %dest_path.display(), error = %e, "failed to set mtime");
        }
    }
    #[cfg(unix)]
    if options.preserve_owner() {
        if let Err(e) = fs.set_owner(dest_path, entry.uid, entry.gid) {
            tracing::warn!(path = %dest_path.display(), error = %e, "failed to set owner");
        }
    }
}

/// Compute itemized change flags by comparing source entry against destination.
pub fn compute_itemized(
    fs: &dyn FileSystem,
    src_entry: &FileEntry,
    dest_path: &Path,
    options: &TransferOptions,
) -> ItemizedChanges {
    let file_type = if src_entry.is_dir() {
        'd'
    } else if src_entry.is_symlink() {
        'L'
    } else if src_entry.is_device() {
        'D'
    } else {
        'f'
    };

    let dest_meta = match fs.lstat(dest_path) {
        Ok(m) => m,
        Err(_) => {
            // Dest doesn't exist -- creating.
            return ItemizedChanges {
                update_type: 'c',
                file_type,
                checksum_changed: false,
                size_changed: true,
                time_changed: true,
                perms_changed: true,
                owner_changed: true,
                group_changed: true,
            };
        }
    };

    let size_changed = dest_meta.len != src_entry.len;
    let time_changed = dest_meta.mtime != src_entry.mtime;
    let perms_changed =
        options.preserve_perms() && (dest_meta.mode & 0o7777) != (src_entry.mode & 0o7777);
    let owner_changed = options.preserve_owner() && dest_meta.uid != src_entry.uid;
    let group_changed =
        (options.preserve_group() || options.preserve_owner()) && dest_meta.gid != src_entry.gid;

    let any_change =
        size_changed || time_changed || perms_changed || owner_changed || group_changed;
    let update_type = if any_change { '>' } else { '.' };

    ItemizedChanges {
        update_type,
        file_type,
        checksum_changed: false,
        size_changed,
        time_changed,
        perms_changed,
        owner_changed,
        group_changed,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn make_entry(name: &str, len: i64, mtime: i64) -> FileEntry {
        FileEntry {
            name: name.as_bytes().to_vec(),
            len,
            mtime,
            mode: 0o100644,
            ..Default::default()
        }
    }

    #[test]
    fn test_ignore_times_never_skips() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("file.txt");
        std::fs::write(&dest, "hello").unwrap();
        filetime::set_file_mtime(&dest, filetime::FileTime::from_unix_time(1_700_000_000, 0))
            .unwrap();

        let entry = make_entry("file.txt", 5, 1_700_000_000);
        let opts = TransferOptions::builder().ignore_times(true).build();
        // Same size, same mtime -- would normally skip, but --ignore-times forces transfer
        assert!(!quick_check_skip(&fs, &entry, &dest, &opts));
    }

    #[test]
    fn test_size_only_skips_matching_size() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("file.txt");
        std::fs::write(&dest, "hello").unwrap();
        filetime::set_file_mtime(&dest, filetime::FileTime::from_unix_time(1_600_000_000, 0))
            .unwrap();

        let entry = make_entry("file.txt", 5, 1_700_000_000);
        let opts = TransferOptions::builder().size_only(true).build();
        // Different mtime but same size -- size-only should skip
        assert!(quick_check_skip(&fs, &entry, &dest, &opts));
    }

    #[test]
    fn test_existing_skips_when_dest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("nope.txt");
        let opts = TransferOptions::builder().existing(true).build();
        assert!(check_existence_skip(&fs, &dest, &opts));
    }

    #[test]
    fn test_existing_allows_when_dest_present() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("yes.txt");
        std::fs::write(&dest, "data").unwrap();
        let opts = TransferOptions::builder().existing(true).build();
        assert!(!check_existence_skip(&fs, &dest, &opts));
    }

    #[test]
    fn test_ignore_existing_skips_when_dest_present() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("yes.txt");
        std::fs::write(&dest, "data").unwrap();
        let opts = TransferOptions::builder().ignore_existing(true).build();
        assert!(check_existence_skip(&fs, &dest, &opts));
    }

    #[test]
    fn test_ignore_existing_allows_when_dest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = crate::fs::unix::UnixFileSystem::new();
        let dest = tmp.path().join("nope.txt");
        let opts = TransferOptions::builder().ignore_existing(true).build();
        assert!(!check_existence_skip(&fs, &dest, &opts));
    }
}
