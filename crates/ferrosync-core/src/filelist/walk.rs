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

/// Options controlling directory walk behavior.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Follow symlinks during scan (`-L`).
    pub copy_links: bool,
    /// Don't cross filesystem boundaries (`-x`). Currently only used by transfer.rs's collect_directory.
    pub one_file_system: bool,
    /// Per-directory .rsync-filter merge level: 0=off, 1=-F, 2=-FF.
    pub filter_merge_files: u8,
}

/// Recursively collect directory entries into a flat `FileEntry` list.
///
/// - `fs`: filesystem abstraction for stat/readdir operations.
/// - `dir_path`: absolute path of the directory to walk.
/// - `prefix`: relative path prefix for child names (empty for the root).
/// - `entries`: output vector to append entries to.
/// - `filters`: filter rules; entries not matching are skipped.
/// - `walk_opts`: options controlling walk behavior.
///
/// The directory itself is added first (with name `"."` if `prefix` is empty),
/// followed by its children in sorted order. Subdirectories are recursed into.
pub fn collect_directory_entries(
    fs: &dyn FileSystem,
    dir_path: &std::path::Path,
    prefix: &[u8],
    entries: &mut Vec<FileEntry>,
    filters: &mut FilterRuleList,
    walk_opts: &WalkOptions,
) -> Result<(), FsError> {
    let dir_meta = if walk_opts.copy_links {
        fs.stat(dir_path)?
    } else {
        fs.lstat(dir_path)?
    };
    let dir_name = if prefix.is_empty() {
        b".".to_vec()
    } else {
        prefix.to_vec()
    };
    entries.push(dir_meta.to_file_entry(dir_name));

    // Per-directory filter merge (-F).
    let has_merge = walk_opts.filter_merge_files > 0;
    let filter_path = dir_path.join(".rsync-filter");
    let merged = if has_merge && filter_path.exists() {
        filters.push_scope();
        // Silently ignore errors reading merge files.
        let _ = filters.merge_filter_file(&filter_path);
        if walk_opts.filter_merge_files >= 2 {
            // -FF: also exclude the .rsync-filter file itself.
            let _ = filters.add_exclude(".rsync-filter");
        }
        true
    } else {
        false
    };

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

        let child_path = dir_path.join(FileEntry::name_to_pathbuf(&child.name));

        let child_meta = if walk_opts.copy_links {
            match fs.stat(&child_path) {
                Ok(m) => m,
                Err(_) => {
                    tracing::warn!(path = %child_path.display(), "skipping broken symlink");
                    continue;
                }
            }
        } else {
            child.metadata.clone()
        };

        let is_dir = child_meta.mode & S_IFMT == S_IFDIR;
        if !filters.is_included(&child_name, is_dir) {
            continue;
        }

        if is_dir {
            collect_directory_entries(fs, &child_path, &child_name, entries, filters, walk_opts)?;
        } else {
            let mut entry = child_meta.to_file_entry(child_name);
            if !walk_opts.copy_links && entry.is_symlink() {
                entry.link_target = match fs.read_link(&child_path) {
                    Ok(target) => target,
                    Err(e) => {
                        tracing::warn!(path = %child_path.display(), error = %e, "failed to read symlink target");
                        Vec::new()
                    }
                };
            }
            entries.push(entry);
        }
    }

    if merged {
        filters.pop_scope();
    }

    Ok(())
}
