//! Delete extraneous files on the receiver.
//!
//! Extracted from [`super::transfer`] so that both the local transfer
//! engine and the wire transfer session can share the same delete logic.
//! Functions accept `impl IntoIterator<Item = &FileEntry>` so callers
//! can pass `&[FileListItem]` (mapped) or `&[FileEntry]` directly.

use std::collections::HashSet;
use std::path::Path;

use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::FileSystem;

/// Delete files on the receiver that don't exist in the source file list.
pub fn delete_extraneous<'a>(
    fs: &dyn FileSystem,
    dest: &Path,
    source_entries: impl IntoIterator<Item = &'a FileEntry>,
    filters: &FilterRuleList,
    dry_run: bool,
    delete_excluded: bool,
) -> Result<u64, FsError> {
    let mut deleted = 0u64;

    // Build a set of source names for quick lookup.
    let source_names: HashSet<&[u8]> = source_entries
        .into_iter()
        .map(|e| e.name.as_slice())
        .collect();

    // Walk the destination and remove anything not in source.
    if let Ok(dest_entries) = fs.read_dir(dest) {
        for dest_entry in dest_entries {
            if source_names.contains(dest_entry.name.as_slice()) {
                continue;
            }

            // Respect filter rules: excluded files on dest are protected
            // unless --delete-excluded is in effect.
            if !delete_excluded {
                let is_dir = dest_entry.metadata.mode & S_IFMT == S_IFDIR;
                if !filters.is_included(&dest_entry.name, is_dir) {
                    continue;
                }
            }

            let path = dest.join(FileEntry::name_to_pathbuf(&dest_entry.name));
            if !dry_run {
                if dest_entry.metadata.mode & S_IFMT == S_IFDIR {
                    let _ = fs.remove_dir(&path);
                } else {
                    let _ = fs.remove_file(&path);
                }
            }
            deleted += 1;
        }
    }

    Ok(deleted)
}

/// Delete extraneous files within a specific directory (for --delete-during).
pub fn delete_extraneous_in_dir<'a>(
    fs: &dyn FileSystem,
    dest_dir: &Path,
    source_entries: impl IntoIterator<Item = &'a FileEntry>,
    dir_name: &[u8],
    filters: &FilterRuleList,
    dry_run: bool,
    delete_excluded: bool,
) -> Result<u64, FsError> {
    let mut deleted = 0u64;

    let dest_entries = match fs.read_dir(dest_dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };

    // Build set of direct children of this directory in the source list.
    let source_children: HashSet<&[u8]> = source_entries
        .into_iter()
        .filter_map(|e| {
            let name = &e.name;
            if dir_name == b"." {
                // Top-level directory: direct children have no '/'.
                if !name.contains(&b'/') && name != b"." {
                    Some(name.as_slice())
                } else {
                    None
                }
            } else if name.len() > dir_name.len()
                && name.starts_with(dir_name)
                && name[dir_name.len()] == b'/'
            {
                // Nested dir: child if exactly one more path component.
                let rest = &name[dir_name.len() + 1..];
                if !rest.contains(&b'/') {
                    Some(rest)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    for dest_entry in dest_entries {
        if source_children.contains(dest_entry.name.as_slice()) {
            continue;
        }

        if !delete_excluded {
            let is_dir = dest_entry.metadata.mode & S_IFMT == S_IFDIR;
            if !filters.is_included(&dest_entry.name, is_dir) {
                continue;
            }
        }

        let path = dest_dir.join(FileEntry::name_to_pathbuf(&dest_entry.name));
        if !dry_run {
            if dest_entry.metadata.mode & S_IFMT == S_IFDIR {
                let _ = fs.remove_dir(&path);
            } else {
                let _ = fs.remove_file(&path);
            }
        }
        deleted += 1;
    }

    Ok(deleted)
}
