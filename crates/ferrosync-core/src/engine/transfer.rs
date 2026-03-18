//! Multi-file transfer engine.
//!
//! Orchestrates a complete rsync-style transfer: builds file lists,
//! applies filter rules, determines which files need updating, and
//! runs the delta transfer pipeline for each file.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::delta::checksum;
use crate::delta::ProtocolContext;
use crate::error::FsError;
use crate::filelist::entry::{self, FileEntry, S_IFDIR, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::{DirEntry, FileSystem};
use crate::options::{DeleteMode, TransferOptions};
use crate::protocol::handshake::NegotiatedProtocol;
use crate::stats::TransferStats;

use super::file_decision;
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
/// updating. Supports timeout via `TransferOptions::timeout`.
pub async fn execute_transfer(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    ctx: &ProtocolContext,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    if let Some(timeout_secs) = options.timeout() {
        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            execute_transfer_impl(fs, options, ctx, progress),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::FerrosyncError::Fs(FsError::Io {
                path: PathBuf::from("<timeout>"),
                source: std::sync::Arc::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("transfer timed out after {timeout_secs} seconds"),
                )),
            })),
        }
    } else {
        execute_transfer_impl(fs, options, ctx, progress).await
    }
}

/// Execute a file transfer using a negotiated protocol.
///
/// Like [`execute_transfer`] but takes a [`NegotiatedProtocol`] instead of
/// separate seed and checksum type. This is the preferred entry point when
/// a wire-level handshake has been performed.
pub async fn execute_transfer_protocol(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    protocol: &NegotiatedProtocol,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let ctx = ProtocolContext::from_protocol(protocol);
    execute_transfer(fs, options, &ctx, progress).await
}

/// Execute a transfer consuming file entries from a channel.
///
/// This enables streaming transfers where file list entries arrive
/// incrementally (e.g., from an incremental file list receiver). The
/// transfer starts processing entries as they arrive rather than waiting
/// for the complete file list.
///
/// Entries received through the channel are processed in order. The
/// channel should be closed by the sender when all entries have been sent.
pub async fn execute_transfer_streaming(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    protocol: &NegotiatedProtocol,
    rx: &mut tokio::sync::mpsc::Receiver<FileEntry>,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let ctx = ProtocolContext::from_protocol(protocol);

    if let Some(timeout_secs) = options.timeout() {
        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            execute_transfer_streaming_impl(fs, options, &ctx, rx, progress),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::FerrosyncError::Fs(FsError::Io {
                path: PathBuf::from("<timeout>"),
                source: std::sync::Arc::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("transfer timed out after {timeout_secs} seconds"),
                )),
            })),
        }
    } else {
        execute_transfer_streaming_impl(fs, options, &ctx, rx, progress).await
    }
}

async fn execute_transfer_impl(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    ctx: &ProtocolContext,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    let source_paths = options.source();
    let dest = options.dest().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no destination>"),
    })?;

    // Build filter rules from options.
    let filters =
        FilterRuleList::from_options(options.exclude(), options.include(), options.filter())?;

    // Build the source file list.
    let source_entries = if let Some(files_from) = options.files_from() {
        build_file_list_from_file(fs, source_paths, files_from, &filters)?
    } else {
        build_file_list(
            fs,
            source_paths,
            options.recursive(),
            &filters,
            options.one_file_system(),
        )?
    };
    stats.total_files = source_entries.len() as u64;

    // Calculate total bytes for progress.
    let total_bytes: i64 = source_entries.iter().map(|e| e.entry.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    let delete_excluded = options.delete() == DeleteMode::Excluded;

    // Handle --delete-before.
    if options.delete() == DeleteMode::Before
        || (delete_excluded && options.delete() == DeleteMode::Excluded)
    {
        let deleted = delete_extraneous(
            fs,
            dest,
            &source_entries,
            &filters,
            options.dry_run(),
            delete_excluded,
        )?;
        stats.files_deleted = deleted;
    }

    // Transfer each file.
    for item in &source_entries {
        let dest_path = dest.join(std::str::from_utf8(&item.entry.name).unwrap_or("?"));

        if item.entry.is_dir() {
            if !options.dry_run() {
                let mode = if options.preserve_perms() {
                    item.entry.mode & 0o7777
                } else {
                    0o755
                };
                fs.mkdir(&dest_path, mode)?;
            }
            stats.directories_created += 1;

            // --delete-during: remove extraneous files in this directory.
            if options.delete() == DeleteMode::During {
                let deleted = delete_extraneous_in_dir(
                    fs,
                    &dest_path,
                    &source_entries,
                    &item.entry.name,
                    &filters,
                    options.dry_run(),
                    false,
                )?;
                stats.files_deleted += deleted;
            }

            continue;
        }

        if item.entry.is_symlink() && options.preserve_links() {
            if !options.dry_run() && !item.entry.link_target.is_empty() {
                fs.create_symlink(&item.entry.link_target, &dest_path)?;
            }
            stats.symlinks += 1;
            progress.emit(ProgressEvent::FileComplete {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                literal_bytes: 0,
                matched_bytes: 0,
            });
            continue;
        }

        if !item.entry.is_file() {
            continue;
        }

        // Check file size limits (--max-size, --min-size).
        if file_decision::check_size_limits(&item.entry, options) {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
            });
            continue;
        }

        // --compare-dest: skip if identical file exists in any compare-dest dir.
        if !options.compare_dest().is_empty()
            && file_decision::check_alt_dest(fs, &item.entry, options.compare_dest()).is_some()
        {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
            });
            continue;
        }

        // --link-dest: hard-link from alt dir if unchanged.
        if !options.link_dest().is_empty() && !options.dry_run() {
            if let Some(alt_path) =
                file_decision::check_alt_dest(fs, &item.entry, options.link_dest())
            {
                if fs.hard_link(&alt_path, &dest_path).is_ok() {
                    stats.files_transferred += 1;
                    progress.emit(ProgressEvent::FileComplete {
                        index: item.index,
                        name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                        literal_bytes: 0,
                        matched_bytes: item.entry.len as u64,
                    });
                    continue;
                }
            }
        }

        // --copy-dest: copy from alt dir if unchanged (also use as basis).
        if !options.copy_dest().is_empty() && !options.dry_run() {
            if let Some(alt_path) =
                file_decision::check_alt_dest(fs, &item.entry, options.copy_dest())
            {
                if fs.copy_file(&alt_path, &dest_path).is_ok() {
                    stats.files_transferred += 1;
                    progress.emit(ProgressEvent::FileComplete {
                        index: item.index,
                        name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                        literal_bytes: 0,
                        matched_bytes: item.entry.len as u64,
                    });
                    continue;
                }
            }
        }

        // Check if the file needs updating.
        if !options.checksum_mode()
            && file_decision::quick_check_skip(fs, &item.entry, &dest_path, options)
        {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
            });
            continue;
        }

        // Checksum mode: compare file-level checksums.
        if options.checksum_mode() {
            if let Ok(dest_data) = fs.map_file(&dest_path) {
                let src_data = fs.map_file(&item.source_path)?;
                let src_sum = checksum::file_checksum(&src_data, ctx);
                let dst_sum = checksum::file_checksum(&dest_data, ctx);
                if src_sum == dst_sum {
                    stats.files_skipped += 1;
                    progress.emit(ProgressEvent::FileSkipped {
                        index: item.index,
                        name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                    });
                    continue;
                }
            }
        }

        // Compute and emit itemized changes if requested.
        if options.itemize_changes() {
            let changes = file_decision::compute_itemized(fs, &item.entry, &dest_path, options);
            progress.emit(ProgressEvent::FileItemized {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                changes,
            });
        }

        progress.emit(ProgressEvent::FileStart {
            index: item.index,
            name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
            size: item.entry.len,
        });

        if options.dry_run() {
            stats.files_transferred += 1;
            stats.total_size += item.entry.len as u64;
            progress.emit(ProgressEvent::FileComplete {
                index: item.index,
                name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                literal_bytes: item.entry.len as u64,
                matched_bytes: 0,
            });
            continue;
        }

        // Read basis file (if it exists on the receiver side).
        let basis_data = fs.map_file(&dest_path).unwrap_or_default();

        // --append: if dest exists and source is longer, only transfer the tail.
        if options.append() && !basis_data.is_empty() {
            let dest_len = basis_data.len();
            let source_data = fs.map_file(&item.source_path)?;
            if source_data.len() > dest_len {
                let append_data = &source_data[dest_len..];
                let mode = if options.preserve_perms() {
                    Some(item.entry.mode & 0o7777)
                } else {
                    None
                };
                fs.append_file(&dest_path, append_data, mode)?;

                let literal_bytes = append_data.len() as u64;
                stats.files_transferred += 1;
                stats.total_size += item.entry.len as u64;
                stats.literal_data += literal_bytes;
                stats.bytes_sent += literal_bytes;

                progress.emit(ProgressEvent::FileComplete {
                    index: item.index,
                    name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                    literal_bytes,
                    matched_bytes: dest_len as u64,
                });
                continue;
            } else {
                // Source is same length or shorter -- skip.
                stats.files_skipped += 1;
                progress.emit(ProgressEvent::FileSkipped {
                    index: item.index,
                    name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
                });
                continue;
            }
        }

        // Read the source file on-demand for the transfer.
        let source_data = fs.map_file(&item.source_path)?;

        // Transfer via delta pipeline.
        //
        // `delta_data` holds the result when we go through the delta path;
        // in the whole-file path we reuse `source_data` directly.
        let delta_data;
        let result_data: &[u8] = if options.whole_file() || basis_data.is_empty() {
            // Whole-file mode or no basis: use the data directly.
            &source_data
        } else if options.compress() {
            delta_data = pipeline::transfer_file_compressed(
                &source_data,
                &basis_data,
                ctx,
                options.compress_level(),
            )
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
            &delta_data
        } else {
            delta_data = pipeline::transfer_file(&source_data, &basis_data, ctx)
                .await
                .map_err(crate::FerrosyncError::Protocol)?;
            &delta_data
        };

        let literal_bytes = result_data.len() as u64;

        // --backup: create backup before overwriting.
        if options.backup() && fs.lexists(&dest_path) {
            file_decision::create_backup(
                fs,
                &dest_path,
                options.suffix(),
                options.backup_dir().map(|p| p.as_path()),
            )?;
        }

        // Choose write target (--partial-dir writes to temp location first).
        let write_path = if let Some(partial_dir) = options.partial_dir() {
            let partial = partial_dir.join(dest_path.file_name().unwrap_or_default());
            fs.mkdir(partial_dir, 0o755)?;
            partial
        } else {
            dest_path.clone()
        };

        // Write the file (choosing method based on options).
        file_decision::write_file_with_options(fs, &write_path, result_data, &item.entry, options)?;

        // --partial-dir: move from partial dir to final destination.
        if options.partial_dir().is_some() && write_path != dest_path {
            fs.rename(&write_path, &dest_path)?;
        }

        // Set metadata.
        file_decision::set_file_metadata(fs, &dest_path, &item.entry, options);

        stats.files_transferred += 1;
        stats.total_size += item.entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.bytes_sent += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: item.index,
            name: crate::engine::progress::name_to_pathbuf(&item.entry.name),
            literal_bytes,
            matched_bytes: 0,
        });

        // Bandwidth limiting: sleep to maintain the target rate.
        if let Some(limit) = options.bwlimit() {
            if limit > 0 {
                let sleep_secs = literal_bytes as f64 / limit as f64;
                if sleep_secs > 0.001 {
                    tokio::time::sleep(Duration::from_secs_f64(sleep_secs)).await;
                }
            }
        }
    }

    // Handle --delete-after.
    if options.delete() == DeleteMode::After {
        let deleted = delete_extraneous(
            fs,
            dest,
            &source_entries,
            &filters,
            options.dry_run(),
            false,
        )?;
        stats.files_deleted = deleted;
    }

    stats.finish();
    Ok(TransferResult { stats })
}

/// Streaming transfer implementation.
///
/// Processes file entries as they arrive from a channel. Directories are
/// created immediately; files are transferred using the delta pipeline.
/// Delete modes are not supported in streaming mode since the complete
/// file list isn't available upfront.
async fn execute_transfer_streaming_impl(
    fs: &dyn FileSystem,
    options: &TransferOptions,
    _ctx: &ProtocolContext,
    rx: &mut tokio::sync::mpsc::Receiver<FileEntry>,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    let dest = options.dest().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no destination>"),
    })?;

    let filters =
        FilterRuleList::from_options(options.exclude(), options.include(), options.filter())?;

    let mut index = 0i32;

    while let Some(entry) = rx.recv().await {
        let name_str = std::str::from_utf8(&entry.name).unwrap_or("?");

        if !filters.is_included(&entry.name, entry.is_dir()) {
            continue;
        }

        let dest_path = dest.join(name_str);
        stats.total_files += 1;

        if entry.is_dir() {
            if !options.dry_run() {
                let mode = if options.preserve_perms() {
                    entry.mode & 0o7777
                } else {
                    0o755
                };
                fs.mkdir(&dest_path, mode)?;
            }
            stats.directories_created += 1;
            index += 1;
            continue;
        }

        if entry.is_symlink() && options.preserve_links() {
            if !options.dry_run() && !entry.link_target.is_empty() {
                fs.create_symlink(&entry.link_target, &dest_path)?;
            }
            stats.symlinks += 1;
            progress.emit(ProgressEvent::FileComplete {
                index,
                name: crate::engine::progress::name_to_pathbuf(&entry.name),
                literal_bytes: 0,
                matched_bytes: 0,
            });
            index += 1;
            continue;
        }

        if !entry.is_file() {
            index += 1;
            continue;
        }

        // Check file size limits.
        if file_decision::check_size_limits(&entry, options) {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index,
                name: crate::engine::progress::name_to_pathbuf(&entry.name),
            });
            index += 1;
            continue;
        }

        // In streaming mode, we don't have source data -- the actual file
        // content arrives via the delta pipeline over the wire. For now,
        // emit progress events to track what would be transferred.
        // The full wire integration (connecting the generator/sender/receiver
        // pipeline to the transport streams) is deferred to the CLI phase.
        progress.emit(ProgressEvent::FileStart {
            index,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            size: entry.len,
        });

        if options.dry_run() {
            stats.files_transferred += 1;
            stats.total_size += entry.len as u64;
            progress.emit(ProgressEvent::FileComplete {
                index,
                name: crate::engine::progress::name_to_pathbuf(&entry.name),
                literal_bytes: entry.len as u64,
                matched_bytes: 0,
            });
            index += 1;
            continue;
        }

        // Set metadata for received files.
        if fs.lexists(&dest_path) {
            file_decision::set_file_metadata(fs, &dest_path, &entry, options);
        }

        stats.files_transferred += 1;
        stats.total_size += entry.len as u64;

        progress.emit(ProgressEvent::FileComplete {
            index,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            literal_bytes: entry.len as u64,
            matched_bytes: 0,
        });

        index += 1;
    }

    stats.finish();
    Ok(TransferResult { stats })
}

/// A file list entry with associated source data.
#[derive(Debug)]
struct FileListItem {
    index: i32,
    entry: FileEntry,
    source_path: PathBuf,
}

/// Build a file list from one or more source paths.
fn build_file_list(
    fs: &dyn FileSystem,
    source_paths: &[PathBuf],
    recursive: bool,
    filters: &FilterRuleList,
    one_file_system: bool,
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
                let root_dev = if one_file_system {
                    Some(meta.dev)
                } else {
                    None
                };
                collect_directory(fs, source, &[], &mut items, &mut index, filters, root_dev)?;
            }
        } else {
            let mut entry = meta.to_file_entry(name);
            if meta.mode & S_IFMT == entry::WIRE_S_IFLNK || meta.mode & S_IFMT == s_iflnk() {
                entry.link_target = fs.read_link(source).unwrap_or_default();
            }

            items.push(FileListItem {
                index,
                entry,
                source_path: source.to_path_buf(),
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
    root_dev: Option<u64>,
) -> std::result::Result<(), FsError> {
    // Check filesystem boundary (--one-file-system).
    #[cfg(unix)]
    if let Some(dev) = root_dev {
        if let Ok(current_dev) = fs.device_id(dir_path) {
            if current_dev != dev {
                return Ok(());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = root_dev;

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
        source_path: dir_path.to_path_buf(),
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

        let child_path = dir_path.join(std::str::from_utf8(&dir_entry.name).unwrap_or("?"));

        if is_dir {
            collect_directory(
                fs,
                &child_path,
                &child_name,
                items,
                index,
                filters,
                root_dev,
            )?;
        } else {
            let mut entry = dir_entry.metadata.to_file_entry(child_name);
            if dir_entry.metadata.mode & S_IFMT == entry::WIRE_S_IFLNK
                || dir_entry.metadata.mode & S_IFMT == s_iflnk()
            {
                entry.link_target = fs.read_link(&child_path).unwrap_or_default();
            }

            items.push(FileListItem {
                index: *index,
                entry,
                source_path: child_path,
            });
            *index += 1;
        }
    }

    Ok(())
}

/// S_IFLNK value for mode comparisons.
///
/// Uses the wire-format constant (0o120000) which is identical to the
/// platform value on all Unix systems. No libc dependency needed.
fn s_iflnk() -> u32 {
    entry::S_IFLNK
}

/// Build a file list from a `--files-from` file.
///
/// Each line in the file is a relative path. We resolve against the first
/// source path (rsync behavior).
fn build_file_list_from_file(
    fs: &dyn FileSystem,
    source_paths: &[PathBuf],
    files_from: &Path,
    filters: &FilterRuleList,
) -> std::result::Result<Vec<FileListItem>, FsError> {
    let base = source_paths.first().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no source>"),
    })?;

    let content = fs.read_file(files_from)?;
    let text = String::from_utf8_lossy(&content);

    let mut items = Vec::new();
    let mut index = 0i32;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let full_path = base.join(line);
        let name = line.as_bytes().to_vec();

        if !filters.is_included(&name, false) {
            continue;
        }

        let meta = match fs.lstat(&full_path) {
            Ok(m) => m,
            Err(_) => continue, // skip missing files
        };

        items.push(FileListItem {
            index,
            entry: meta.to_file_entry(name),
            source_path: full_path,
        });
        index += 1;
    }

    Ok(items)
}

/// Delete files on the receiver that don't exist in the source file list.
fn delete_extraneous(
    fs: &dyn FileSystem,
    dest: &Path,
    source_entries: &[FileListItem],
    filters: &FilterRuleList,
    dry_run: bool,
    delete_excluded: bool,
) -> std::result::Result<u64, FsError> {
    let mut deleted = 0u64;

    // Build a set of source names for quick lookup.
    let source_names: HashSet<&[u8]> = source_entries
        .iter()
        .map(|e| e.entry.name.as_slice())
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

            let path = dest.join(std::str::from_utf8(&dest_entry.name).unwrap_or("?"));
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
fn delete_extraneous_in_dir(
    fs: &dyn FileSystem,
    dest_dir: &Path,
    source_entries: &[FileListItem],
    dir_name: &[u8],
    filters: &FilterRuleList,
    dry_run: bool,
    delete_excluded: bool,
) -> std::result::Result<u64, FsError> {
    let mut deleted = 0u64;

    let dest_entries = match fs.read_dir(dest_dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };

    // Build set of direct children of this directory in the source list.
    let source_children: HashSet<&[u8]> = source_entries
        .iter()
        .filter_map(|e| {
            let name = &e.entry.name;
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

        let path = dest_dir.join(std::str::from_utf8(&dest_entry.name).unwrap_or("?"));
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::delta::chunker::ChunkingStrategy;
    use crate::fs::unix::UnixFileSystem;
    use tempfile::TempDir;

    async fn do_transfer(
        _src_dir: &Path,
        _dst_dir: &Path,
        opts: TransferOptions,
    ) -> TransferResult {
        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        let ctx = ProtocolContext {
            seed: 42,
            checksum_type: crate::protocol::handshake::ChecksumType::Md5,
            char_offset: 0,
            proper_seed_order: true,
        };
        execute_transfer(&fs, &opts, &ctx, &mut progress)
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
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "aaa");
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

        // Set both files to the same mtime.
        let fs = UnixFileSystem::new();
        let target_mtime: i64 = 1_000_000;
        fs.set_mtime(&src.join("file.txt"), target_mtime, 0)
            .unwrap();
        fs.set_mtime(&dst.join("file.txt"), target_mtime, 0)
            .unwrap();

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

    // ----- New Tier 2 tests -----

    #[tokio::test]
    async fn test_max_size_filter() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("small.txt"), "hi").unwrap();
        std::fs::write(src.join("big.txt"), "a".repeat(1000)).unwrap();

        let opts = TransferOptions::builder()
            .recursive(true)
            .source(src.clone())
            .dest(dst.clone())
            .max_size(100)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert!(dst.join("small.txt").exists());
        assert!(!dst.join("big.txt").exists());
    }

    #[tokio::test]
    async fn test_min_size_filter() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("tiny.txt"), "x").unwrap();
        std::fs::write(src.join("normal.txt"), "a".repeat(100)).unwrap();

        let opts = TransferOptions::builder()
            .recursive(true)
            .source(src.clone())
            .dest(dst.clone())
            .min_size(10)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert!(!dst.join("tiny.txt").exists());
        assert!(dst.join("normal.txt").exists());
    }

    #[tokio::test]
    async fn test_inplace_write() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "new content").unwrap();
        std::fs::write(dst.join("file.txt"), "old content").unwrap();

        // Set dest to an older mtime so should_skip returns false.
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&dst.join("file.txt"), 1_000_000, 0).unwrap();

        // Record the inode of the dest file before transfer.
        use std::os::unix::fs::MetadataExt;
        let ino_before = std::fs::metadata(dst.join("file.txt")).unwrap().ino();

        let opts = TransferOptions::builder()
            .inplace(true)
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        do_transfer(&src, &dst, opts).await;

        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "new content"
        );
        // Inode should be preserved with inplace writes.
        let ino_after = std::fs::metadata(dst.join("file.txt")).unwrap().ino();
        assert_eq!(ino_before, ino_after);
    }

    #[tokio::test]
    async fn test_sparse_write() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        // Create a file with a large zero block.
        let mut data = vec![0u8; 8192];
        data.extend_from_slice(b"end marker");
        std::fs::write(src.join("sparse.bin"), &data).unwrap();

        let opts = TransferOptions::builder()
            .sparse(true)
            .source(src.join("sparse.bin"))
            .dest(dst.clone())
            .build();

        do_transfer(&src, &dst, opts).await;

        let written = std::fs::read(dst.join("sparse.bin")).unwrap();
        assert_eq!(written, data);
    }

    #[tokio::test]
    async fn test_delete_during() {
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
            .delete(DeleteMode::During)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_deleted, 1);
        assert!(!dst.join("extra.txt").exists());
        assert!(dst.join("keep.txt").exists());
    }

    #[tokio::test]
    async fn test_bwlimit() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();

        let opts = TransferOptions::builder()
            .bwlimit(1_000_000) // 1 MB/s -- small file, should complete quickly
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "data"
        );
    }

    #[tokio::test]
    async fn test_timeout_succeeds() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();

        let opts = TransferOptions::builder()
            .timeout(60)
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
    }

    #[tokio::test]
    async fn test_compressed_transfer() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        // Create basis and modified source to exercise delta+compression.
        let basis: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFE;
        std::fs::write(src.join("data.bin"), &source).unwrap();
        std::fs::write(dst.join("data.bin"), &basis).unwrap();
        // Set dest to older mtime.
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&dst.join("data.bin"), 1_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .compress(true)
            .compress_level(6)
            .source(src.join("data.bin"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(std::fs::read(dst.join("data.bin")).unwrap(), source);
    }

    #[tokio::test]
    async fn test_files_from() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("a.txt"), "aaa").unwrap();
        std::fs::write(src.join("b.txt"), "bbb").unwrap();
        std::fs::write(src.join("c.txt"), "ccc").unwrap();

        // files-from: only transfer a.txt and c.txt
        let files_list = tmp.path().join("filelist.txt");
        std::fs::write(&files_list, "a.txt\nc.txt\n").unwrap();

        let opts = TransferOptions::builder()
            .source(src.clone())
            .dest(dst.clone())
            .files_from(files_list)
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 2);
        assert!(dst.join("a.txt").exists());
        assert!(!dst.join("b.txt").exists());
        assert!(dst.join("c.txt").exists());
    }

    #[tokio::test]
    async fn test_link_dest() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        let alt = tmp.path().join("alt");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::create_dir_all(&alt).unwrap();

        std::fs::write(src.join("file.txt"), "data").unwrap();
        std::fs::write(alt.join("file.txt"), "data").unwrap();
        // Set matching mtime.
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&src.join("file.txt"), 2_000_000, 0).unwrap();
        ufs.set_mtime(&alt.join("file.txt"), 2_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .link_dest(alt.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert!(dst.join("file.txt").exists());

        // Should be a hard link (same inode as alt).
        use std::os::unix::fs::MetadataExt;
        let alt_ino = std::fs::metadata(alt.join("file.txt")).unwrap().ino();
        let dst_ino = std::fs::metadata(dst.join("file.txt")).unwrap().ino();
        assert_eq!(alt_ino, dst_ino);
    }

    #[tokio::test]
    async fn test_compare_dest() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        let alt = tmp.path().join("alt");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::create_dir_all(&alt).unwrap();

        std::fs::write(src.join("same.txt"), "data").unwrap();
        std::fs::write(alt.join("same.txt"), "data").unwrap();
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&src.join("same.txt"), 2_000_000, 0).unwrap();
        ufs.set_mtime(&alt.join("same.txt"), 2_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("same.txt"))
            .dest(dst.clone())
            .compare_dest(alt.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_skipped, 1);
        assert_eq!(result.stats.files_transferred, 0);
        assert!(!dst.join("same.txt").exists());
    }

    #[tokio::test]
    async fn test_backup() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "new content").unwrap();
        std::fs::write(dst.join("file.txt"), "old content").unwrap();

        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&dst.join("file.txt"), 1_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .backup(true)
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        do_transfer(&src, &dst, opts).await;
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "new content"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt~")).unwrap(),
            "old content"
        );
    }

    #[tokio::test]
    async fn test_backup_with_dir() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        let bak = tmp.path().join("backups");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "new").unwrap();
        std::fs::write(dst.join("file.txt"), "old").unwrap();

        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&dst.join("file.txt"), 1_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .backup(true)
            .backup_dir(bak.clone())
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        do_transfer(&src, &dst, opts).await;
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(bak.join("file.txt~")).unwrap(),
            "old"
        );
    }

    #[tokio::test]
    async fn test_append_mode() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("log.txt"), "line1\nline2\nline3\n").unwrap();
        std::fs::write(dst.join("log.txt"), "line1\n").unwrap();

        // Set dest to older mtime so it's not skipped.
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&dst.join("log.txt"), 1_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .append(true)
            .source(src.join("log.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("log.txt")).unwrap(),
            "line1\nline2\nline3\n"
        );
    }

    #[tokio::test]
    async fn test_partial_dir() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        let partial = dst.join(".partial");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();

        let opts = TransferOptions::builder()
            .partial_dir(partial)
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "data"
        );
    }

    #[tokio::test]
    async fn test_copy_dest() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        let alt = tmp.path().join("alt");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::create_dir_all(&alt).unwrap();

        std::fs::write(src.join("file.txt"), "data").unwrap();
        std::fs::write(alt.join("file.txt"), "data").unwrap();
        let ufs = UnixFileSystem::new();
        ufs.set_mtime(&src.join("file.txt"), 2_000_000, 0).unwrap();
        ufs.set_mtime(&alt.join("file.txt"), 2_000_000, 0).unwrap();

        let opts = TransferOptions::builder()
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .copy_dest(alt.clone())
            .build();

        let result = do_transfer(&src, &dst, opts).await;
        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "data"
        );
        // Should NOT be a hard link -- it's a copy.
        use std::os::unix::fs::MetadataExt;
        let alt_ino = std::fs::metadata(alt.join("file.txt")).unwrap().ino();
        let dst_ino = std::fs::metadata(dst.join("file.txt")).unwrap().ino();
        assert_ne!(alt_ino, dst_ino);
    }

    #[tokio::test]
    async fn test_itemize_changes_emitted() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "new").unwrap();

        use std::sync::{Arc, Mutex};
        let itemized: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let itemized_clone = itemized.clone();

        let mut progress = ProgressTracker::with_callback(Box::new(move |event| {
            if let ProgressEvent::FileItemized { changes, .. } = event {
                itemized_clone.lock().unwrap().push(changes.to_string());
            }
        }));

        let opts = TransferOptions::builder()
            .itemize_changes(true)
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let fs = UnixFileSystem::new();
        let ctx = ProtocolContext {
            seed: 42,
            checksum_type: crate::protocol::handshake::ChecksumType::Md5,
            char_offset: 0,
            proper_seed_order: true,
        };
        execute_transfer(&fs, &opts, &ctx, &mut progress)
            .await
            .unwrap();

        let captured = itemized.lock().unwrap();
        assert_eq!(captured.len(), 1);
        // Creating a new file: 'c' update type, 'f' file type.
        assert!(captured[0].starts_with("cf"));
    }

    #[tokio::test]
    async fn test_execute_transfer_protocol() {
        use crate::protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use crate::protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "protocol test").unwrap();

        let protocol = NegotiatedProtocol {
            version: 31,
            compat_flags: compat_flags::DEFAULT,

            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: true,
            seed: 42,
            chunking: ChunkingStrategy::default(),
            wire: WireFormat::new(31, compat_flags::DEFAULT),
        };

        let opts = TransferOptions::builder()
            .source(src.join("file.txt"))
            .dest(dst.clone())
            .build();

        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        let result = execute_transfer_protocol(&fs, &opts, &protocol, &mut progress)
            .await
            .unwrap();

        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "protocol test"
        );
    }

    #[tokio::test]
    async fn test_streaming_transfer_dry_run() {
        use crate::filelist::entry::S_IFREG;
        use crate::protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use crate::protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol {
            version: 31,
            compat_flags: compat_flags::DEFAULT,

            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: true,
            seed: 42,
            chunking: ChunkingStrategy::default(),
            wire: WireFormat::new(31, compat_flags::DEFAULT),
        };

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        // Send entries.
        tx.send(FileEntry {
            name: b"a.txt".to_vec(),
            len: 100,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"b.txt".to_vec(),
            len: 200,
            mtime: 1700000001,
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        drop(tx); // Close channel.

        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        let result = execute_transfer_streaming(&fs, &opts, &protocol, &mut rx, &mut progress)
            .await
            .unwrap();

        assert_eq!(result.stats.files_transferred, 2);
        assert_eq!(result.stats.total_size, 300);
        // Dry run: no actual files created.
        assert!(!dst.join("a.txt").exists());
    }

    #[tokio::test]
    async fn test_streaming_transfer_directories() {
        use crate::filelist::entry::{S_IFDIR, S_IFREG};
        use crate::protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use crate::protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol {
            version: 31,
            compat_flags: compat_flags::DEFAULT,

            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: true,
            seed: 42,
            chunking: ChunkingStrategy::default(),
            wire: WireFormat::new(31, compat_flags::DEFAULT),
        };

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        tx.send(FileEntry {
            name: b"subdir".to_vec(),
            len: 0,
            mtime: 1700000000,
            mode: S_IFDIR | 0o755,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"file.txt".to_vec(),
            len: 50,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        drop(tx);

        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        let result = execute_transfer_streaming(&fs, &opts, &protocol, &mut rx, &mut progress)
            .await
            .unwrap();

        assert_eq!(result.stats.directories_created, 1);
        assert_eq!(result.stats.files_transferred, 1);
    }

    #[tokio::test]
    async fn test_streaming_transfer_with_size_filter() {
        use crate::filelist::entry::S_IFREG;
        use crate::protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use crate::protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol {
            version: 31,
            compat_flags: compat_flags::DEFAULT,

            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: true,
            seed: 42,
            chunking: ChunkingStrategy::default(),
            wire: WireFormat::new(31, compat_flags::DEFAULT),
        };

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .max_size(150)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        tx.send(FileEntry {
            name: b"small.txt".to_vec(),
            len: 100,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"large.txt".to_vec(),
            len: 200,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        drop(tx);

        let fs = UnixFileSystem::new();
        let mut progress = ProgressTracker::new();
        let result = execute_transfer_streaming(&fs, &opts, &protocol, &mut rx, &mut progress)
            .await
            .unwrap();

        assert_eq!(result.stats.files_transferred, 1);
        assert_eq!(result.stats.files_skipped, 1);
    }
}
