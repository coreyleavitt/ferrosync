//! Multi-file transfer engine.
//!
//! Orchestrates a complete rsync-style transfer: builds file lists,
//! applies filter rules, determines which files need updating, and
//! runs the delta transfer pipeline for each file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ferrosync_codec::entry::FileEntry;
use ferrosync_delta::checksum;
use ferrosync_delta::ProtocolContext;
use ferrosync_filter::FilterRuleList;
use ferrosync_fs::FileSystem;
use ferrosync_protocol::handshake::NegotiatedProtocol;
use ferrosync_scanner::{
    self as scanner, FileListScanner, HardLinkGrouper, ScanOptions, SymlinkEnricher,
};
#[cfg(unix)]
use ferrosync_scanner::{AclEnricher, XattrEnricher};
use ferrosync_types::error::FsError;
use ferrosync_types::options::{DeleteMode, TransferConfig, TransferOptions};
use ferrosync_types::stats::TransferStats;

use crate::delete;
use crate::file_decision;
use crate::pipeline;
use crate::progress::{ProgressEvent, ProgressTracker};

type Result<T> = std::result::Result<T, ferrosync_types::FerrosyncError>;

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
    execute_transfer_config(fs, options, ctx, progress).await
}

/// Execute a file transfer using a [`TransferConfig`].
///
/// Same as [`execute_transfer`] but takes the decomposed config directly.
pub async fn execute_transfer_config(
    fs: &dyn FileSystem,
    options: &TransferConfig,
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
            Err(_) => Err(ferrosync_types::FerrosyncError::Fs(FsError::Io {
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
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = options.block_size();
    execute_transfer_config(fs, options, &ctx, progress).await
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
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = options.block_size();

    if let Some(timeout_secs) = options.timeout() {
        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            execute_transfer_streaming_impl(fs, options, &ctx, rx, progress),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(ferrosync_types::FerrosyncError::Fs(FsError::Io {
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
    options: &TransferConfig,
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
    let mut filters = FilterRuleList::from_options(
        options.exclude(),
        options.include(),
        options.filter(),
        options.include_from(),
        options.exclude_from(),
    )?;
    if options.cvs_exclude() {
        filters.add_cvs_excludes();
    }

    // Build the source file list.
    let source_entries = if let Some(files_from) = options.files_from() {
        scanner::build_file_list_from_file(fs, source_paths, files_from, &filters)?
    } else {
        let scan_opts = ScanOptions {
            dir_mode: options.dir_mode(),
            one_file_system: options.one_file_system(),
            copy_links: options.copy_links(),
            relative: options.relative(),
            filter_merge_files: options.filter_merge_files(),
            preserve_hard_links: options.preserve_hard_links(),
        };
        let mut scanner = FileListScanner::new(fs, scan_opts);
        if !options.copy_links() {
            scanner.add_enricher(Box::new(SymlinkEnricher::new(fs)));
        }
        if options.preserve_hard_links() {
            scanner.add_enricher(Box::new(HardLinkGrouper));
        }
        #[cfg(unix)]
        if options.preserve_acls() {
            scanner.add_enricher(Box::new(AclEnricher::new(fs)));
        }
        #[cfg(unix)]
        if options.preserve_xattrs() {
            scanner.add_enricher(Box::new(XattrEnricher::new(fs)));
        }
        scanner.scan(source_paths, &mut filters)?
    };

    stats.total_files = source_entries.len() as u64;

    // Calculate total bytes for progress.
    let total_bytes: i64 = source_entries.iter().map(|e| e.entry.len.bytes()).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    // --list-only: print file list and return without transferring.
    if options.list_only() {
        for item in &source_entries {
            println!("{}", item.entry.format_list_entry());
        }
        stats.finish();
        return Ok(TransferResult { stats });
    }

    let delete_excluded = options.delete() == DeleteMode::Excluded;
    let delete_budget = delete::DeleteBudget::new(options.max_delete());
    let deleter = delete::Deleter::new(
        fs,
        &filters,
        &delete_budget,
        options.dry_run(),
        delete_excluded,
    );

    // Handle --delete-before.
    if options.delete() == DeleteMode::Before
        || (delete_excluded && options.delete() == DeleteMode::Excluded)
    {
        let deleted =
            deleter.delete_extraneous(dest, source_entries.iter().map(|item| &item.entry))?;
        stats.files_deleted = deleted;
    }

    // Build a source path lookup for finding source files by entry name.
    let source_path_map: std::collections::HashMap<&[u8], &Path> = source_entries
        .iter()
        .map(|item| (item.entry.name.as_slice(), item.source_path.as_path()))
        .collect();

    let receiver = super::receiver_engine::ReceiverRef::new(fs, dest, options);

    // Collect all entries for hardlink resolution and delete-during.
    let all_entries: Vec<FileEntry> = source_entries.iter().map(|i| i.entry.clone()).collect();
    let mut deferred: Vec<(&FileEntry, Vec<u8>)> = Vec::new();

    for item in &source_entries {
        let index = item.index;

        match receiver.dispatch_entry(&item.entry)? {
            super::receiver_engine::EntryAction::Handled { kind } => {
                match kind {
                    super::receiver_engine::HandledKind::Directory => {
                        stats.directories_created += 1;
                        // --delete-during: remove extraneous files in this directory.
                        if options.delete() == DeleteMode::During {
                            let dest_path = receiver.dest_path(&item.entry);
                            let deleted = deleter.delete_extraneous_in_dir(
                                &dest_path,
                                all_entries.iter(),
                                &item.entry.name,
                            )?;
                            stats.files_deleted += deleted;
                        }
                    }
                    super::receiver_engine::HandledKind::Symlink => {
                        stats.symlinks += 1;
                        progress.emit(ProgressEvent::FileComplete {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                            literal_bytes: 0,
                            matched_bytes: 0,
                        });
                    }
                    super::receiver_engine::HandledKind::LinkDest
                    | super::receiver_engine::HandledKind::CopyDest => {
                        stats.files_transferred += 1;
                        progress.emit(ProgressEvent::FileComplete {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                            literal_bytes: 0,
                            matched_bytes: item.entry.len.as_u64(),
                        });
                    }
                    super::receiver_engine::HandledKind::DryRun => {
                        // Itemized changes before dry-run accounting.
                        if options.itemize_changes() {
                            let dest_path = receiver.dest_path(&item.entry);
                            let changes = file_decision::compute_itemized(
                                fs,
                                &item.entry,
                                &dest_path,
                                options,
                            );
                            progress.emit(ProgressEvent::FileItemized {
                                index,
                                name: super::progress::name_to_pathbuf(&item.entry.name),
                                changes,
                            });
                        }
                        progress.emit(ProgressEvent::FileStart {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                            size: item.entry.len.bytes(),
                        });
                        stats.files_transferred += 1;
                        stats.total_size += item.entry.len.as_u64();
                        progress.emit(ProgressEvent::FileComplete {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                            literal_bytes: item.entry.len.as_u64(),
                            matched_bytes: 0,
                        });
                    }
                }
            }
            super::receiver_engine::EntryAction::Skipped => {
                stats.files_skipped += 1;
                progress.emit(ProgressEvent::FileSkipped {
                    index,
                    name: super::progress::name_to_pathbuf(&item.entry.name),
                });
            }
            super::receiver_engine::EntryAction::DeferredHardlink { source_name } => {
                deferred.push((&item.entry, source_name));
            }
            super::receiver_engine::EntryAction::NeedsTransfer { basis } => {
                let basis_data = basis;

                // Checksum mode (local only): file-level comparison.
                if options.checksum_mode() {
                    if let Some(source_path) = source_path_map.get(item.entry.name.as_slice()) {
                        if let Ok(src_data) = fs.map_file(source_path) {
                            let src_sum = checksum::file_checksum(&src_data, ctx);
                            let dst_sum = checksum::file_checksum(&basis_data, ctx);
                            if src_sum == dst_sum {
                                stats.files_skipped += 1;
                                progress.emit(ProgressEvent::FileSkipped {
                                    index,
                                    name: super::progress::name_to_pathbuf(&item.entry.name),
                                });
                                continue;
                            }
                        }
                    }
                }

                // Itemized changes.
                if options.itemize_changes() {
                    let dest_path = receiver.dest_path(&item.entry);
                    let changes =
                        file_decision::compute_itemized(fs, &item.entry, &dest_path, options);
                    progress.emit(ProgressEvent::FileItemized {
                        index,
                        name: super::progress::name_to_pathbuf(&item.entry.name),
                        changes,
                    });
                }

                progress.emit(ProgressEvent::FileStart {
                    index,
                    name: super::progress::name_to_pathbuf(&item.entry.name),
                    size: item.entry.len.bytes(),
                });

                let source_path = source_path_map
                    .get(item.entry.name.as_slice())
                    .copied()
                    .ok_or_else(|| FsError::NotFound {
                        path: PathBuf::from(String::from_utf8_lossy(&item.entry.name).into_owned()),
                    })?;

                // Append mode.
                if (options.append() || options.append_verify()) && !basis_data.is_empty() {
                    let source_data = fs.map_file(source_path)?;
                    let dest_len = basis_data.len();
                    if source_data.len() <= dest_len {
                        stats.files_skipped += 1;
                        progress.emit(ProgressEvent::FileSkipped {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                        });
                        continue;
                    }
                    let append_data = &source_data[dest_len..];
                    let mode = if options.preserve_perms() {
                        Some(item.entry.mode & 0o7777)
                    } else {
                        None
                    };
                    let dest_path = receiver.dest_path(&item.entry);
                    fs.append_file(&dest_path, append_data, mode)?;

                    if options.append_verify() {
                        let dest_data = fs.map_file(&dest_path)?;
                        if dest_data.as_ref() != source_data.as_ref() {
                            tracing::debug!(
                                path = %dest_path.display(),
                                "append-verify mismatch, retransferring"
                            );
                            // Fall through to full transfer below.
                        } else {
                            let literal_bytes = append_data.len() as u64;
                            let matched_bytes = dest_len as u64;
                            stats.files_transferred += 1;
                            stats.total_size += item.entry.len.as_u64();
                            stats.literal_data += literal_bytes;
                            stats.bytes_sent += literal_bytes;
                            progress.emit(ProgressEvent::FileComplete {
                                index,
                                name: super::progress::name_to_pathbuf(&item.entry.name),
                                literal_bytes,
                                matched_bytes,
                            });
                            continue;
                        }
                    } else {
                        let literal_bytes = append_data.len() as u64;
                        let matched_bytes = dest_len as u64;
                        stats.files_transferred += 1;
                        stats.total_size += item.entry.len.as_u64();
                        stats.literal_data += literal_bytes;
                        stats.bytes_sent += literal_bytes;
                        progress.emit(ProgressEvent::FileComplete {
                            index,
                            name: super::progress::name_to_pathbuf(&item.entry.name),
                            literal_bytes,
                            matched_bytes,
                        });
                        continue;
                    }
                }

                // Data transfer via delta pipeline.
                let source_data = fs.map_file(source_path)?;
                let data = if options.whole_file() || basis_data.is_empty() {
                    source_data.to_vec()
                } else if options.compress() {
                    pipeline::transfer_file_compressed(
                        &source_data,
                        &basis_data,
                        ctx,
                        options.compress_level(),
                        ferrosync_protocol::handshake::CompressType::Zlib,
                    )
                    .await
                    .map_err(ferrosync_types::FerrosyncError::Protocol)?
                } else {
                    pipeline::transfer_file(&source_data, &basis_data, ctx)
                        .await
                        .map_err(ferrosync_types::FerrosyncError::Protocol)?
                };
                let literal_bytes = data.len() as u64;

                receiver.apply_transfer(&item.entry, &data, Some(source_path))?;

                stats.files_transferred += 1;
                stats.total_size += item.entry.len.as_u64();
                stats.literal_data += literal_bytes;
                stats.bytes_sent += literal_bytes;

                progress.emit(ProgressEvent::FileComplete {
                    index,
                    name: super::progress::name_to_pathbuf(&item.entry.name),
                    literal_bytes,
                    matched_bytes: 0,
                });

                // Bandwidth limiting.
                if let Some(limit) = options.bwlimit() {
                    if limit > 0 {
                        let sleep_secs = literal_bytes as f64 / limit as f64;
                        if sleep_secs > 0.001 {
                            tokio::time::sleep(Duration::from_secs_f64(sleep_secs)).await;
                        }
                    }
                }
            }
        }
    }

    // Create deferred hardlinks now that first occurrences are on disk.
    let hardlinks_created = receiver.create_deferred_hardlinks(&deferred, &all_entries)?;
    stats.files_transferred += hardlinks_created;

    // --delete-after
    if options.delete() == DeleteMode::After {
        let deleted = deleter.delete_extraneous(dest, all_entries.iter())?;
        stats.files_deleted = deleted;
    }

    // Handle --prune-empty-dirs (-m).
    if options.prune_empty_dirs() {
        let pruned = delete::prune_empty_dirs(fs, dest, options.dry_run())?;
        stats.files_deleted += pruned;
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
    options: &TransferConfig,
    _ctx: &ProtocolContext,
    rx: &mut tokio::sync::mpsc::Receiver<FileEntry>,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    let dest = options.dest().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no destination>"),
    })?;

    let receiver = super::receiver_engine::ReceiverRef::new(fs, dest, options);

    let mut filters = FilterRuleList::from_options(
        options.exclude(),
        options.include(),
        options.filter(),
        options.include_from(),
        options.exclude_from(),
    )?;
    if options.cvs_exclude() {
        filters.add_cvs_excludes();
    }

    let mut index = 0i32;

    while let Some(entry) = rx.recv().await {
        if !filters.is_included(&entry.name, entry.is_dir()) {
            continue;
        }

        let dest_path = receiver.dest_path(&entry);
        stats.total_files += 1;

        if entry.is_dir() {
            receiver.create_directory(&entry)?;
            stats.directories_created += 1;
            index += 1;
            continue;
        }

        if entry.is_symlink() && options.preserve_links() {
            if !receiver.create_symlink(&entry)? {
                stats.files_skipped += 1;
                index += 1;
                continue;
            }
            stats.symlinks += 1;
            progress.emit(ProgressEvent::FileComplete {
                index,
                name: crate::progress::name_to_pathbuf(&entry.name),
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

        // Unified skip checks.
        if receiver.should_skip_file(&entry) {
            stats.files_skipped += 1;
            progress.emit(ProgressEvent::FileSkipped {
                index,
                name: crate::progress::name_to_pathbuf(&entry.name),
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
            name: crate::progress::name_to_pathbuf(&entry.name),
            size: entry.len.bytes(),
        });

        if options.dry_run() {
            stats.files_transferred += 1;
            stats.total_size += entry.len.as_u64();
            progress.emit(ProgressEvent::FileComplete {
                index,
                name: crate::progress::name_to_pathbuf(&entry.name),
                literal_bytes: entry.len.as_u64(),
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
        stats.total_size += entry.len.as_u64();

        progress.emit(ProgressEvent::FileComplete {
            index,
            name: crate::progress::name_to_pathbuf(&entry.name),
            literal_bytes: entry.len.as_u64(),
            matched_bytes: 0,
        });

        index += 1;
    }

    stats.finish();
    Ok(TransferResult { stats })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ferrosync_delta::chunker::ChunkingStrategy;
    use ferrosync_fs::unix::UnixFileSystem;
    use ferrosync_types::types::{FileSize, UnixTimestamp};
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
            checksum_type: ferrosync_protocol::handshake::ChecksumType::Md5,
            char_offset: 0,
            proper_seed_order: true,
            block_size_override: None,
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
            checksum_type: ferrosync_protocol::handshake::ChecksumType::Md5,
            char_offset: 0,
            proper_seed_order: true,
            block_size_override: None,
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
        use ferrosync_protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use ferrosync_protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "protocol test").unwrap();

        let protocol = NegotiatedProtocol::new(
            31,
            compat_flags::DEFAULT,
            ChecksumType::Md5,
            CompressType::None,
            true,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(31, compat_flags::DEFAULT),
        );

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
        use ferrosync_codec::entry::S_IFREG;
        use ferrosync_protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use ferrosync_protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol::new(
            31,
            compat_flags::DEFAULT,
            ChecksumType::Md5,
            CompressType::None,
            true,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(31, compat_flags::DEFAULT),
        );

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        // Send entries.
        tx.send(FileEntry {
            name: b"a.txt".to_vec(),
            len: FileSize(100),
            mtime: UnixTimestamp(1700000000),
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"b.txt".to_vec(),
            len: FileSize(200),
            mtime: UnixTimestamp(1700000001),
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
        use ferrosync_codec::entry::{S_IFDIR, S_IFREG};
        use ferrosync_protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use ferrosync_protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol::new(
            31,
            compat_flags::DEFAULT,
            ChecksumType::Md5,
            CompressType::None,
            true,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(31, compat_flags::DEFAULT),
        );

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        tx.send(FileEntry {
            name: b"subdir".to_vec(),
            len: FileSize(0),
            mtime: UnixTimestamp(1700000000),
            mode: S_IFDIR | 0o755,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"file.txt".to_vec(),
            len: FileSize(50),
            mtime: UnixTimestamp(1700000000),
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
        use ferrosync_codec::entry::S_IFREG;
        use ferrosync_protocol::handshake::{
            compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
        };
        use ferrosync_protocol::wire_format::WireFormat;

        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();

        let protocol = NegotiatedProtocol::new(
            31,
            compat_flags::DEFAULT,
            ChecksumType::Md5,
            CompressType::None,
            true,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(31, compat_flags::DEFAULT),
        );

        let opts = TransferOptions::builder()
            .dest(dst.clone())
            .dry_run(true)
            .max_size(150)
            .build();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        tx.send(FileEntry {
            name: b"small.txt".to_vec(),
            len: FileSize(100),
            mtime: UnixTimestamp(1700000000),
            mode: S_IFREG | 0o644,
            ..Default::default()
        })
        .await
        .unwrap();
        tx.send(FileEntry {
            name: b"large.txt".to_vec(),
            len: FileSize(200),
            mtime: UnixTimestamp(1700000000),
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
