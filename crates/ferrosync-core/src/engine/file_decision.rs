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

    // --update: skip if dest is newer (regardless of size).
    // Must be checked before size comparison -- rsync skips when
    // the receiver is newer even if the files differ in size.
    if options.update() && dest_meta.mtime > src_entry.mtime {
        return true;
    }

    // Size differs -> must transfer.
    if dest_meta.len != src_entry.len {
        return false;
    }

    // --size-only: sizes match -> skip (don't check mtime)
    if options.size_only() {
        return true;
    }

    // Same size and mtime within --modify-window tolerance -> skip.
    let window = options.modify_window() as i64;
    if (dest_meta.mtime - src_entry.mtime).abs() <= window {
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
    options: &TransferOptions,
) -> Option<PathBuf> {
    let window = options.modify_window() as i64;
    for dir in alt_dirs {
        let alt_path = dir.join(src_entry.path());
        if let Ok(meta) = fs.lstat(&alt_path) {
            if meta.len == src_entry.len && (meta.mtime - src_entry.mtime).abs() <= window {
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

/// Check if a symlink target is unsafe (would escape the transfer tree).
///
/// A symlink is unsafe if:
/// - It points to an absolute path
/// - Relative path components (`..`) would escape the transfer root
pub fn is_unsafe_symlink(target: &[u8]) -> bool {
    let target_str = String::from_utf8_lossy(target);
    let target_path = std::path::Path::new(target_str.as_ref());

    // Absolute targets are always unsafe.
    if target_path.is_absolute() {
        return true;
    }

    // Count depth: normal components add depth, ParentDir subtracts.
    // If depth ever goes negative, the symlink escapes the tree.
    let mut depth: i32 = 0;
    for component in target_path.components() {
        match component {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            std::path::Component::Normal(_) => {
                depth += 1;
            }
            _ => {}
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
    chmod: Option<&crate::chmod::ChmodSpec>,
) -> std::result::Result<(), crate::FerrosyncError> {
    let mode = if options.preserve_perms() {
        Some(entry.mode & 0o7777)
    } else {
        None
    };
    let mode = mode.map(|m| {
        if let Some(spec) = chmod {
            spec.apply(m, entry.is_dir())
        } else {
            m
        }
    });

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
    {
        let uid = options.chown_uid().unwrap_or(entry.uid);
        let gid = options.chown_gid().unwrap_or(entry.gid);
        if options.preserve_owner()
            || options.chown_uid().is_some()
            || options.chown_gid().is_some()
        {
            if let Err(e) = fs.set_owner(dest_path, uid, gid) {
                tracing::warn!(path = %dest_path.display(), error = %e, "failed to set owner");
            }
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

/// Compute a fuzzy similarity score between two byte strings.
///
/// Returns the length of the longest common subsequence divided by the
/// maximum length. Returns 0.0 for empty inputs, 1.0 for identical strings.
pub fn fuzzy_score(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let max_len = a.len().max(b.len());
    let lcs_len = longest_common_subsequence_len(a, b);
    lcs_len as f64 / max_len as f64
}

fn longest_common_subsequence_len(a: &[u8], b: &[u8]) -> usize {
    // Space-optimized LCS: only need previous and current row.
    let mut prev = vec![0usize; b.len() + 1];
    let mut curr = vec![0usize; b.len() + 1];

    for i in 1..=a.len() {
        for j in 1..=b.len() {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1] + 1
            } else {
                prev[j].max(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev[b.len()]
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
