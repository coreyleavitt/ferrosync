//! Shared directory walking for building file entry lists.
//!
//! This module provides a single implementation of recursive directory
//! traversal that is used by both the client engine (`engine/session.rs`)
//! and the server session (`server/session.rs`), eliminating code
//! duplication.

use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::{DirEntry, FileSystem};

/// Recursively collect directory entries into a flat `FileEntry` list.
///
/// - `fs`: filesystem abstraction for stat/readdir operations.
/// - `dir_path`: absolute path of the directory to walk.
/// - `prefix`: relative path prefix for child names (empty for the root).
/// - `entries`: output vector to append entries to.
/// - `filters`: filter rules; entries not matching are skipped.
///
/// The directory itself is added first (with name `"."` if `prefix` is empty),
/// followed by its children in sorted order. Subdirectories are recursed into.
pub fn collect_directory_entries(
    fs: &dyn FileSystem,
    dir_path: &std::path::Path,
    prefix: &[u8],
    entries: &mut Vec<FileEntry>,
    filters: &FilterRuleList,
) -> Result<(), FsError> {
    let dir_meta = fs.lstat(dir_path)?;
    let dir_name = if prefix.is_empty() {
        b".".to_vec()
    } else {
        prefix.to_vec()
    };
    entries.push(dir_meta.to_file_entry(dir_name));

    let mut children: Vec<DirEntry> = fs.read_dir(dir_path)?;
    children.sort_by(|a, b| a.name.cmp(&b.name));

    for child in children {
        let child_name = if prefix.is_empty() {
            child.name.clone()
        } else {
            let mut n = prefix.to_vec();
            n.push(b'/');
            n.extend(&child.name);
            n
        };

        let is_dir = child.metadata.mode & S_IFMT == S_IFDIR;
        if !filters.is_included(&child_name, is_dir) {
            continue;
        }

        let child_path = dir_path.join(std::str::from_utf8(&child.name).unwrap_or("?"));

        if is_dir {
            collect_directory_entries(fs, &child_path, &child_name, entries, filters)?;
        } else {
            let mut entry = child.metadata.to_file_entry(child_name);
            if entry.is_symlink() {
                entry.link_target = fs.read_link(&child_path).unwrap_or_default();
            }
            entries.push(entry);
        }
    }

    Ok(())
}
