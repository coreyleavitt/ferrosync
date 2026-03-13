//! Multi-file transfer engine.
//!
//! Orchestrates a complete rsync-style transfer: builds file lists,
//! applies filter rules, determines which files need updating, and
//! runs the delta transfer pipeline for each file.

use std::path::{Path, PathBuf};

use crate::delta::checksum;
use crate::error::FsError;
use crate::filelist::entry::{self, FileEntry, S_IFDIR, S_IFMT, S_IFREG};
use crate::filter::FilterRuleList;
use crate::fs::{DirEntry, FileSystem};
use crate::options::{DeleteMode, TransferOptions};
use crate::protocol::handshake::ChecksumType;
use crate::stats::TransferStats;

use super::pipeline;
use super::progress::{ProgressEvent, ProgressTracker};

type Result<T> = std::result::Result<T, crate::FerrosyncError>;

/// Result of a complete transfer operation.
#[derive(Debug)]
pub struct TransferResult {
    /// Transfer statistics.
    pub stats: TransferStats,
}

/// Execute a file transfer from source to destination.
///
/// This is the main entry point for performing an rsync-style transfer.
/// It builds file lists, applies filters, and transfers files that need
/// updating.
pub async fn execute_transfer(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    seed: i32,
    checksum_type: ChecksumType,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    let source_paths = &options.source;
    let dest = options
        .dest
        .as_ref()
        .ok_or_else(|| FsError::NotFound {
            path: PathBuf::from("<no destination>"),
        })?;

    // Build filter rules from options.
    let filters =
        FilterRuleList::from_options(&options.exclude, &options.include, &options.filter)?;

    // Build the source file list.
    let source_entries = build_file_list(fs, source_paths, options.recursive, &filters)?;
    stats.total_files = source_entries.len() as u64;

    // Calculate total bytes for progress.
    let total_bytes: i64 = source_entries.iter().map(|e| e.entry.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    // Handle --delete modes.
    if options.delete != DeleteMode::None && options.delete == DeleteMode::Before {
        let deleted = delete_extraneous(fs, dest, &source_entries, &filters, options.dry_run)?;
        stats.files_deleted = deleted;
    }

    // Transfer each file.
    for item in &source_entries {
        let dest_path = dest.join(
            std::str::from_utf8(&item.entry.name).unwrap_or("?"),
        );

        if item.entry.is_dir() {
            if !options.dry_run {
                let mode = if options.preserve_perms {
                    item.entry.mode & 0o7777
                } else {
                    0o755
                };
                fs.mkdir(&dest_path, mode)?;
            }
            stats.directories_created += 1;
            continue;
        }

        if item.entry.is_symlink() && options.preserve_links {
            if !options.dry_run && !item.entry.link_target.is_empty() {
                fs.create_symlink(&item.entry.link_target, &dest_path)?;
            }
            stats.symlinks += 1;
            progress.emit(ProgressEvent::FileComplete {
                index: item.index,
                name: item.entry.name.clone(),
                literal_bytes: 0,
                matched_bytes: 0,
            });
            continue;
        }

        if !item.entry.is_file() {
            continue;
        }

        // Check if the file needs updating.
        if !options.checksum_mode && should_skip(fs, &item.entry, &dest_path, options) {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index: item.index,
                name: item.entry.name.clone(),
            });
            continue;
        }

        // Checksum mode: compare file-level checksums.
        if options.checksum_mode {
            if let Ok(dest_data) = fs.read_file(&dest_path) {
                let src_sum = checksum::file_checksum(
                    &item.source_data,
                    seed,
                    checksum_type,
                );
                let dst_sum = checksum::file_checksum(&dest_data, seed, checksum_type);
                if src_sum == dst_sum {
                    stats.files_skipped += 1;
                    progress.emit(ProgressEvent::FileSkipped {
                        index: item.index,
                        name: item.entry.name.clone(),
                    });
                    continue;
                }
            }
        }

        progress.emit(ProgressEvent::FileStart {
            index: item.index,
            name: item.entry.name.clone(),
            size: item.entry.len,
        });

        if options.dry_run {
            stats.files_transferred += 1;
            stats.total_size += item.entry.len as u64;
            progress.emit(ProgressEvent::FileComplete {
                index: item.index,
                name: item.entry.name.clone(),
                literal_bytes: item.entry.len as u64,
                matched_bytes: 0,
            });
            continue;
        }

        // Read basis file (if it exists on the receiver side).
        let basis_data = fs.read_file(&dest_path).unwrap_or_default();

        // Transfer via delta pipeline.
        let result_data = if options.whole_file || basis_data.is_empty() {
            // Whole-file mode or no basis: just copy the data.
            item.source_data.clone()
        } else {
            pipeline::transfer_file(
                &item.source_data,
                &basis_data,
                seed,
                checksum_type,
            )
            .await
            .map_err(crate::FerrosyncError::Protocol)?
        };

        let literal_bytes = result_data.len() as u64;

        // Write the file.
        let mode = if options.preserve_perms {
            Some(item.entry.mode & 0o7777)
        } else {
            None
        };
        fs.write_file(&dest_path, &result_data, mode)?;

        // Set metadata.
        if options.preserve_times {
            fs.set_mtime(&dest_path, item.entry.mtime, item.entry.mtime_nsec)?;
        }
        if options.preserve_owner {
            let _ = fs.set_owner(&dest_path, item.entry.uid, item.entry.gid);
        }

        stats.files_transferred += 1;
        stats.total_size += item.entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.bytes_sent += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: item.index,
            name: item.entry.name.clone(),
            literal_bytes,
            matched_bytes: 0,
        });
    }

    // Handle --delete-after.
    if options.delete == DeleteMode::After {
        let deleted = delete_extraneous(fs, dest, &source_entries, &filters, options.dry_run)?;
        stats.files_deleted = deleted;
    }

    stats.finish();
    Ok(TransferResult { stats })
}

/// A file list entry with associated source data.
#[derive(Debug)]
struct FileListItem {
    index: i32,
    entry: FileEntry,
    source_data: Vec<u8>,
}

/// Build a file list from one or more source paths.
fn build_file_list(
    fs: &dyn FileSystem,
    source_paths: &[PathBuf],
    recursive: bool,
    filters: &FilterRuleList,
) -> std::result::Result<Vec<FileListItem>, FsError> {
    let mut items = Vec::new();
    let mut index = 0i32;

    for source in source_paths {
        let meta = fs.lstat(source)?;
        let name = source
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
            .unwrap_or_default();

        if !filters.is_included(&name, meta.mode & S_IFMT == S_IFDIR) {
            continue;
        }

        if meta.mode & S_IFMT == S_IFDIR {
            if recursive {
                collect_directory(fs, source, &[], &mut items, &mut index, filters)?;
            }
        } else {
            let source_data = if meta.mode & S_IFMT == S_IFREG {
                fs.read_file(source)?
            } else {
                Vec::new()
            };

            let mut entry = meta.to_file_entry(name);
            if meta.mode & S_IFMT == entry::WIRE_S_IFLNK || meta.mode & S_IFMT == libc_s_iflnk() {
                entry.link_target = fs.read_link(source).unwrap_or_default();
            }

            items.push(FileListItem {
                index,
                entry,
                source_data,
            });
            index += 1;
        }
    }

    Ok(items)
}

/// Recursively collect directory entries.
fn collect_directory(
    fs: &dyn FileSystem,
    dir_path: &Path,
    prefix: &[u8],
    items: &mut Vec<FileListItem>,
    index: &mut i32,
    filters: &FilterRuleList,
) -> std::result::Result<(), FsError> {
    // Add the directory itself.
    let dir_meta = fs.lstat(dir_path)?;
    let dir_name = if prefix.is_empty() {
        b".".to_vec()
    } else {
        prefix.to_vec()
    };

    items.push(FileListItem {
        index: *index,
        entry: dir_meta.to_file_entry(dir_name),
        source_data: Vec::new(),
    });
    *index += 1;

    let mut entries: Vec<DirEntry> = fs.read_dir(dir_path)?;
    // Sort for deterministic order.
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    for dir_entry in entries {
        let child_name = if prefix.is_empty() {
            dir_entry.name.clone()
        } else {
            let mut n = prefix.to_vec();
            n.push(b'/');
            n.extend(&dir_entry.name);
            n
        };

        let is_dir = dir_entry.metadata.mode & S_IFMT == S_IFDIR;

        if !filters.is_included(&child_name, is_dir) {
            continue;
        }

        let child_path = dir_path.join(
            std::str::from_utf8(&dir_entry.name).unwrap_or("?"),
        );

        if is_dir {
            collect_directory(fs, &child_path, &child_name, items, index, filters)?;
        } else {
            let source_data = if dir_entry.metadata.mode & S_IFMT == S_IFREG {
                fs.read_file(&child_path)?
            } else {
                Vec::new()
            };

            let mut entry = dir_entry.metadata.to_file_entry(child_name);
            if dir_entry.metadata.mode & S_IFMT == entry::WIRE_S_IFLNK
                || dir_entry.metadata.mode & S_IFMT == libc_s_iflnk()
            {
                entry.link_target = fs.read_link(&child_path).unwrap_or_default();
            }

            items.push(FileListItem {
                index: *index,
                entry,
                source_data,
            });
            *index += 1;
        }
    }

    Ok(())
}

/// Get the platform's S_IFLNK value.
#[cfg(unix)]
fn libc_s_iflnk() -> u32 {
    libc::S_IFLNK
}

#[cfg(not(unix))]
fn libc_s_iflnk() -> u32 {
    entry::WIRE_S_IFLNK
}

/// Check if a file should be skipped based on size and mtime comparison.
fn should_skip(
    fs: &dyn FileSystem,
    src_entry: &FileEntry,
    dest_path: &Path,
    options: &TransferOptions,
) -> bool {
    let dest_meta = match fs.lstat(dest_path) {
        Ok(m) => m,
        Err(_) => return false, // dest doesn't exist, must transfer
    };

    // Size differs -> must transfer.
    if dest_meta.len != src_entry.len {
        return false;
    }

    // --update: skip if dest is newer.
    if options.update && dest_meta.mtime > src_entry.mtime {
        return true;
    }

    // Same size and same mtime -> skip.
    if dest_meta.mtime == src_entry.mtime {
        return true;
    }

    false
}

/// Delete files on the receiver that don't exist in the source file list.
fn delete_extraneous(
    fs: &dyn FileSystem,
    dest: &Path,
    source_entries: &[FileListItem],
    _filters: &FilterRuleList,
    dry_run: bool,
) -> std::result::Result<u64, FsError> {
    let mut deleted = 0u64;

    // Build a set of source names for quick lookup.
    let source_names: std::collections::HashSet<&[u8]> =
        source_entries.iter().map(|e| e.entry.name.as_slice()).collect();

    // Walk the destination and remove anything not in source.
    if let Ok(dest_entries) = fs.read_dir(dest) {
        for dest_entry in dest_entries {
            if !source_names.contains(dest_entry.name.as_slice()) {
                let path = dest.join(
                    std::str::from_utf8(&dest_entry.name).unwrap_or("?"),
                );
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
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::unix::UnixFileSystem;
    use tempfile::TempDir;

    async fn do_transfer(
        _src_dir: &Path,
        _dst_dir: &Path,
        opts: TransferOptions,
    ) -> TransferResult {
        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        execute_transfer(&fs, &opts, 42, ChecksumType::Md5, &mut progress)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_transfer_single_file() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("hello.txt"), "hello world").unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("hello.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("hello.txt")).unwrap(),
            "hello world"
        );
    }

    #[tokio::test]
    async fn test_transfer_recursive_directory() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("a.txt"), "aaa").unwrap();
        std::fs::write(src.join("sub/b.txt"), "bbb").unwrap();

        let opts = TransferOptions::builder()
            .recursive(true)
            .source(src.clone())
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 2);
        assert_eq!(
            std::fs::read_to_string(dst.join("a.txt")).unwrap(),
            "aaa"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(),
            "bbb"
        );
    }

    #[tokio::test]
    async fn test_transfer_with_exclude() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("keep.txt"), "keep").unwrap();
        std::fs::write(src.join("skip.tmp"), "skip").unwrap();

        let opts = TransferOptions::builder()
            .recursive(true)
            .source(src.clone())
            .dest(dst.clone())
            .exclude("*.tmp")
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert!(dst.join("keep.txt").exists());
        assert!(!dst.join("skip.tmp").exists());
    }

    #[tokio::test]
    async fn test_transfer_dry_run() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .dry_run(true)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        // File should NOT actually exist on disk.
        assert!(!dst.join("file.txt").exists());
    }

    #[tokio::test]
    async fn test_transfer_skip_unchanged() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        let content = "same content";
        std::fs::write(src.join("file.txt"), content).unwrap();
        std::fs::write(dst.join("file.txt"), content).unwrap();

        // Set both files to the same mtime using libc::utimensat.
        let fs = UnixFileSystem::new();
        let target_mtime: i64 = 1_000_000;
        fs.set_mtime(&src.join("file.txt"), target_mtime, 0).unwrap();
        fs.set_mtime(&dst.join("file.txt"), target_mtime, 0).unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_skipped, 1);
        assert_eq!(result.stats.files_transferred, 0);
    }

    #[tokio::test]
    async fn test_transfer_delete_before() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("keep.txt"), "keep").unwrap();
        std::fs::write(dst.join("extra.txt"), "extra").unwrap();

        let opts = TransferOptions::builder()
            .recursive(true)
            .source(src.clone())
            .dest(dst.clone())
            .delete(DeleteMode::Before)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_deleted, 1);
        assert!(!dst.join("extra.txt").exists());
    }

    #[tokio::test]
    async fn test_transfer_preserve_perms() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("exec.sh"), "#!/bin/sh").unwrap();
        std::fs::set_permissions(
            src.join("exec.sh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let opts = TransferOptions::builder()
            .preserve_perms(true)
            .source(src.join("exec.sh"))
            .dest(dst.clone())
            .build();

        do_transfer(&src, &dst, opts).await;

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dst.join("exec.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}
