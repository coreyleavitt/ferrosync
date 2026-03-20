//! Delete extraneous files on the receiver.
//!
//! [`Deleter`] bundles the filesystem, filter rules, dry-run flag,
//! delete-excluded flag, and deletion budget into a single object so
//! that callers don't need to thread six parameters through every call.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::FileSystem;

// ---------------------------------------------------------------------------
// DeleteBudget
// ---------------------------------------------------------------------------

/// Tracks remaining deletions for `--max-delete`.
pub struct DeleteBudget {
    remaining: AtomicU64,
}

impl DeleteBudget {
    /// Create a new budget. `None` means unlimited.
    pub fn new(max_delete: Option<u64>) -> Self {
        Self {
            remaining: AtomicU64::new(max_delete.unwrap_or(u64::MAX)),
        }
    }

    /// Try to consume one deletion from the budget.
    /// Returns `true` if a deletion is allowed, `false` if the budget is exhausted.
    pub fn try_consume(&self) -> bool {
        loop {
            let current = self.remaining.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if current == u64::MAX {
                return true; // unlimited
            }
            match self.remaining.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deleter
// ---------------------------------------------------------------------------

/// Context for deleting extraneous files on the receiver.
///
/// Bundles the shared state needed by both `delete_extraneous` and
/// `delete_extraneous_in_dir`, keeping method signatures lean.
pub struct Deleter<'a> {
    fs: &'a dyn FileSystem,
    filters: &'a FilterRuleList,
    budget: &'a DeleteBudget,
    dry_run: bool,
    delete_excluded: bool,
}

impl<'a> Deleter<'a> {
    pub fn new(
        fs: &'a dyn FileSystem,
        filters: &'a FilterRuleList,
        budget: &'a DeleteBudget,
        dry_run: bool,
        delete_excluded: bool,
    ) -> Self {
        Self {
            fs,
            filters,
            budget,
            dry_run,
            delete_excluded,
        }
    }

    /// Delete files in `dest` that don't exist in the source file list.
    pub fn delete_extraneous<'b>(
        &self,
        dest: &Path,
        source_entries: impl IntoIterator<Item = &'b FileEntry>,
    ) -> Result<u64, FsError> {
        let mut deleted = 0u64;

        let source_names: HashSet<&[u8]> = source_entries
            .into_iter()
            .map(|e| e.name.as_slice())
            .collect();

        if let Ok(dest_entries) = self.fs.read_dir(dest) {
            for dest_entry in dest_entries {
                if source_names.contains(dest_entry.name.as_slice()) {
                    continue;
                }

                if !self.delete_excluded {
                    let is_dir = dest_entry.metadata.mode & S_IFMT == S_IFDIR;
                    if !self.filters.is_included(&dest_entry.name, is_dir) {
                        continue;
                    }
                }

                if !self.budget.try_consume() {
                    break;
                }
                let path = dest.join(FileEntry::name_to_pathbuf(&dest_entry.name));
                if !self.dry_run {
                    if dest_entry.metadata.mode & S_IFMT == S_IFDIR {
                        let _ = self.fs.remove_dir(&path);
                    } else {
                        let _ = self.fs.remove_file(&path);
                    }
                }
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Delete extraneous files within a specific directory (for --delete-during).
    pub fn delete_extraneous_in_dir<'b>(
        &self,
        dest_dir: &Path,
        source_entries: impl IntoIterator<Item = &'b FileEntry>,
        dir_name: &[u8],
    ) -> Result<u64, FsError> {
        let mut deleted = 0u64;

        let dest_entries = match self.fs.read_dir(dest_dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };

        // Build set of direct children of this directory in the source list.
        let source_children: HashSet<&[u8]> = source_entries
            .into_iter()
            .filter_map(|e| {
                let name = &e.name;
                if dir_name == b"." {
                    if !name.contains(&b'/') && name != b"." {
                        Some(name.as_slice())
                    } else {
                        None
                    }
                } else if name.len() > dir_name.len()
                    && name.starts_with(dir_name)
                    && name[dir_name.len()] == b'/'
                {
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

            if !self.delete_excluded {
                let is_dir = dest_entry.metadata.mode & S_IFMT == S_IFDIR;
                if !self.filters.is_included(&dest_entry.name, is_dir) {
                    continue;
                }
            }

            if !self.budget.try_consume() {
                break;
            }
            let path = dest_dir.join(FileEntry::name_to_pathbuf(&dest_entry.name));
            if !self.dry_run {
                if dest_entry.metadata.mode & S_IFMT == S_IFDIR {
                    let _ = self.fs.remove_dir(&path);
                } else {
                    let _ = self.fs.remove_file(&path);
                }
            }
            deleted += 1;
        }

        Ok(deleted)
    }
}

// ---------------------------------------------------------------------------
// Prune empty directories
// ---------------------------------------------------------------------------

/// Remove empty directories bottom-up after a transfer.
///
/// Recurses into `dest`, visiting children before parents. After processing
/// all children of a directory, if it is now empty and is not `dest` itself,
/// removes it. Returns total number of directories pruned.
pub fn prune_empty_dirs(fs: &dyn FileSystem, dest: &Path, dry_run: bool) -> Result<u64, FsError> {
    prune_empty_dirs_recursive(fs, dest, dest, dry_run)
}

fn prune_empty_dirs_recursive(
    fs: &dyn FileSystem,
    root: &Path,
    dir: &Path,
    dry_run: bool,
) -> Result<u64, FsError> {
    let mut pruned = 0u64;

    let entries = match fs.read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(0),
    };

    for entry in entries {
        let path = dir.join(FileEntry::name_to_pathbuf(&entry.name));
        if entry.metadata.mode & S_IFMT == S_IFDIR {
            pruned += prune_empty_dirs_recursive(fs, root, &path, dry_run)?;
        }
    }

    // After processing children, check if this directory is now empty.
    // Never remove the root destination itself.
    if dir != root {
        let remaining = match fs.read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(pruned),
        };
        if remaining.is_empty() {
            if !dry_run {
                let _ = fs.remove_dir(dir);
            }
            pruned += 1;
        }
    }

    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_unlimited() {
        let budget = DeleteBudget::new(None);
        for _ in 0..1000 {
            assert!(budget.try_consume());
        }
    }

    #[test]
    fn test_budget_limited() {
        let budget = DeleteBudget::new(Some(3));
        assert!(budget.try_consume());
        assert!(budget.try_consume());
        assert!(budget.try_consume());
        assert!(!budget.try_consume());
        assert!(!budget.try_consume());
    }

    #[test]
    fn test_prune_empty_dirs_removes_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let fs = crate::fs::unix::UnixFileSystem::new();

        std::fs::create_dir_all(root.join("empty_a")).unwrap();
        std::fs::create_dir_all(root.join("has_file")).unwrap();
        std::fs::write(root.join("has_file/data.txt"), "keep").unwrap();
        std::fs::create_dir_all(root.join("nested/inner")).unwrap();

        let pruned = prune_empty_dirs(&fs, root, false).unwrap();

        // empty_a, inner, then nested (becomes empty after inner removed)
        assert_eq!(pruned, 3);
        assert!(!root.join("empty_a").exists());
        assert!(!root.join("nested").exists());
        assert!(root.join("has_file/data.txt").exists());
        assert!(root.exists());
    }

    #[test]
    fn test_prune_empty_dirs_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let fs = crate::fs::unix::UnixFileSystem::new();

        std::fs::create_dir_all(root.join("empty")).unwrap();

        let pruned = prune_empty_dirs(&fs, root, true).unwrap();
        assert_eq!(pruned, 1);
        // Dry run: directory should still exist.
        assert!(root.join("empty").exists());
    }
}
