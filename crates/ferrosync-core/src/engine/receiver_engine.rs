//! Unified receiver engine for destination-side file operations.
//!
//! Extracts all destination-side logic (skip checks, backup, file writing,
//! metadata setting) into a single struct used by both the local transfer
//! engine and the wire transfer receiver. This eliminates the feature gap
//! where flags work locally but not over SSH.
//!
//! The engine stores an `Arc<dyn FileSystem>` for owned usage (wire transfers,
//! `LocalFileOps`). For borrowed usage (local transfer engine), callers
//! construct a `ReceiverRef` which borrows a `ReceiverEngine` and adds the
//! local-only source-path context.
//!
//! ## Unified dispatch via `process_entries()`
//!
//! The [`DataProvider`] trait abstracts the only thing that differs between
//! local and wire transfers: how file content is produced. Everything else
//! (skip checks, hardlinks, symlinks, metadata, stats, progress) is handled
//! by [`ReceiverEngine::process_entries()`], eliminating the duplicated
//! dispatch logic that previously lived in both `transfer.rs` and
//! `wire_transfer.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::chmod::ChmodSpec;
use crate::delta::checksum;
use crate::delta::ProtocolContext;
use crate::engine::delete;
use crate::engine::file_decision;
use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFLNK, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::FileSystem;
use crate::options::{DeleteMode, TransferOptions};
use crate::stats::TransferStats;

use super::progress::{ProgressEvent, ProgressTracker};

// ---------------------------------------------------------------------------
// DataProvider trait
// ---------------------------------------------------------------------------

/// Source of file data for the receiver.
///
/// The only thing that differs between local and wire transfers is how
/// file content is produced. Local transfers read source files and compute
/// deltas in-process. Wire transfers receive delta tokens from the remote
/// sender. Everything else (skip checks, hardlinks, symlinks, metadata,
/// stats, progress) is identical and handled by
/// [`ReceiverEngine::process_entries()`].
///
/// Methods are async to support both the local delta pipeline (which uses
/// async I/O internally) and wire transfers (which read from async streams).
pub trait DataProvider {
    /// Produce file data for a regular file entry.
    ///
    /// `basis` is the existing destination file data (empty if no basis).
    /// Returns the reconstructed file content to write.
    ///
    /// For local transfers: reads source file, applies delta/whole-file.
    /// For wire transfers: sends signatures to sender, receives delta tokens.
    fn provide_data(
        &mut self,
        index: i32,
        entry: &FileEntry,
        basis: &[u8],
    ) -> impl std::future::Future<Output = std::result::Result<Vec<u8>, crate::FerrosyncError>> + Send;

    /// Compute a file-level checksum of the source file for `--checksum` mode.
    ///
    /// Returns `None` if the provider cannot supply source checksums (e.g.,
    /// wire transfers where the sender performs checksum comparison).
    fn source_checksum(&self, _entry: &FileEntry, _ctx: &ProtocolContext) -> Option<Vec<u8>> {
        None
    }

    /// Get the source path for this entry (for `--remove-source-files`).
    ///
    /// Returns `None` for wire transfers where there is no local source.
    fn source_path(&self, _entry: &FileEntry) -> Option<PathBuf> {
        None
    }

    /// Handle append mode for a file.
    ///
    /// Returns `Some(data)` with the append-only tail data if the provider
    /// handled the append. Returns `None` to fall through to full transfer.
    fn handle_append(
        &mut self,
        _index: i32,
        _entry: &FileEntry,
        _dest_path: &Path,
        _basis: &[u8],
    ) -> impl std::future::Future<
        Output = std::result::Result<Option<AppendResult>, crate::FerrosyncError>,
    > + Send {
        async { Ok(None) }
    }
}

/// Result of an append operation.
pub enum AppendResult {
    /// Data was appended successfully.
    Appended {
        /// Number of literal bytes appended.
        literal_bytes: u64,
        /// Number of existing bytes that were kept (matched).
        matched_bytes: u64,
    },
    /// Source is same size or smaller -- skip the file.
    Skip,
}

/// Context for [`ReceiverEngine::process_entries()`].
///
/// Holds mutable state that the caller provides: statistics, progress
/// tracker, filters, and optional deleter for `--delete-during`.
pub struct ProcessContext<'a> {
    pub stats: &'a mut TransferStats,
    pub progress: &'a mut ProgressTracker,
    pub filters: &'a FilterRuleList,
    pub deleter: Option<&'a delete::Deleter<'a>>,
    pub protocol_ctx: &'a ProtocolContext,
}

// ---------------------------------------------------------------------------
// ReceiverEngine
// ---------------------------------------------------------------------------

/// Unified receiver that handles all destination-side file operations.
///
/// Used by both the local transfer engine (`transfer.rs`) and the wire
/// transfer receiver (`wire_transfer.rs` via `LocalFileOps`).
pub struct ReceiverEngine {
    fs: Arc<dyn FileSystem>,
    dest: PathBuf,
    options: TransferOptions,
    chmod_spec: Option<ChmodSpec>,
    resolved_link_dests: Vec<PathBuf>,
    /// Backup directory resolved relative to dest (if relative path given).
    resolved_backup_dir: Option<PathBuf>,
}

impl ReceiverEngine {
    /// Create a new receiver engine.
    ///
    /// Resolves `--link-dest` directories, `--backup-dir` path, and
    /// parses `--chmod` specs upfront.
    pub fn new(fs: Arc<dyn FileSystem>, dest: PathBuf, options: TransferOptions) -> Self {
        let resolved_link_dests = file_decision::resolve_link_dest_dirs(options.link_dest(), &dest);
        let chmod_spec = if !options.chmod().is_empty() {
            ChmodSpec::parse(&options.chmod().join(",")).ok()
        } else {
            None
        };
        let resolved_backup_dir = options.backup_dir().map(|bd| {
            if bd.is_relative() {
                dest.join(bd)
            } else {
                bd.clone()
            }
        });
        Self {
            fs,
            dest,
            options,
            chmod_spec,
            resolved_link_dests,
            resolved_backup_dir,
        }
    }

    /// Resolved backup directory (relative paths joined to dest).
    pub fn backup_dir(&self) -> Option<&Path> {
        self.resolved_backup_dir.as_deref()
    }

    /// Resolve the destination path for an entry.
    pub fn dest_path(&self, entry: &FileEntry) -> PathBuf {
        self.dest.join(entry.path())
    }

    /// Check if a file should be skipped based on all skip criteria.
    ///
    /// Combines: `--existing`, `--ignore-existing`, `--max-size`, `--min-size`,
    /// `--compare-dest`, quick-check (size+mtime), `--update`, `--size-only`,
    /// `--ignore-times`, `--modify-window`.
    pub fn should_skip_file(&self, entry: &FileEntry) -> bool {
        should_skip_impl(&*self.fs, entry, &self.dest, &self.options)
    }

    /// Attempt to satisfy a file via hard link from a `--link-dest` dir.
    ///
    /// Returns `true` if the file was successfully hard-linked (no data
    /// transfer needed).
    pub fn try_link_dest(&self, entry: &FileEntry) -> bool {
        if self.resolved_link_dests.is_empty() || self.options.dry_run() {
            return false;
        }
        if let Some(alt_path) = file_decision::check_alt_dest(
            &*self.fs,
            entry,
            &self.resolved_link_dests,
            &self.options,
        ) {
            let dest_path = self.dest_path(entry);
            // Remove existing dest if present (rsync does this before hard-linking).
            let _ = self.fs.remove_file(&dest_path);
            if self.fs.hard_link(&alt_path, &dest_path).is_ok() {
                return true;
            }
        }
        false
    }

    /// Attempt to copy from a `--copy-dest` dir.
    ///
    /// Returns `true` if the file was successfully copied (no delta transfer
    /// needed).
    pub fn try_copy_dest(&self, entry: &FileEntry) -> bool {
        if self.options.copy_dest().is_empty() || self.options.dry_run() {
            return false;
        }
        if let Some(alt_path) =
            file_decision::check_alt_dest(&*self.fs, entry, self.options.copy_dest(), &self.options)
        {
            let dest_path = self.dest_path(entry);
            if self.fs.copy_file(&alt_path, &dest_path).is_ok() {
                return true;
            }
        }
        false
    }

    /// Write reconstructed file data to the destination with all options.
    ///
    /// Handles `--backup`, `--partial-dir`, sparse/inplace/streaming write
    /// modes, metadata setting, and `--remove-source-files`.
    pub fn receive_file(
        &self,
        entry: &FileEntry,
        data: &[u8],
        source_path: Option<&Path>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);

        // --backup: create backup before overwriting.
        if self.options.backup() && self.fs.lexists(&dest_path) {
            file_decision::create_backup(
                &*self.fs,
                &dest_path,
                self.options.suffix(),
                self.backup_dir(),
            )?;
        }

        // Choose write target (--partial-dir writes to temp location first).
        let write_path = if let Some(partial_dir) = self.options.partial_dir() {
            let partial = partial_dir.join(dest_path.file_name().unwrap_or_default());
            self.fs.mkdir(partial_dir, 0o755)?;
            partial
        } else {
            dest_path.clone()
        };

        // Write the file (choosing method based on options: sparse/inplace/streaming).
        file_decision::write_file_with_options(
            &*self.fs,
            &write_path,
            data,
            entry,
            &self.options,
            self.chmod_spec.as_ref(),
        )?;

        // --partial-dir: move from partial dir to final destination.
        if self.options.partial_dir().is_some() && write_path != dest_path {
            self.fs.rename(&write_path, &dest_path)?;
        }

        // Set metadata (times, owner, permissions).
        file_decision::set_file_metadata(&*self.fs, &dest_path, entry, &self.options);

        // --remove-source-files: delete source after successful transfer.
        if let Some(src) = source_path {
            if self.options.remove_source_files() && !self.options.dry_run() {
                if let Err(e) = self.fs.remove_file(src) {
                    tracing::warn!(
                        path = %src.display(),
                        error = %e,
                        "failed to remove source file"
                    );
                }
            }
        }

        Ok(())
    }

    /// Create a streaming writer for wire transfers.
    ///
    /// Handles `--inplace` and `--partial-dir` write targets.
    pub fn create_writer(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn std::io::Write + Send>, crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);

        // --append: open file in append mode, preserving existing content.
        // The remote sender sends only the tail portion as literal data;
        // we append it after the existing bytes.
        if self.options.append() || self.options.append_verify() {
            // Ensure parent directory exists.
            if let Some(parent) = dest_path.parent() {
                if !self.fs.lexists(parent) {
                    self.fs.mkdir(parent, 0o755)?;
                }
            }
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&dest_path)
                .map_err(|e| {
                    crate::FerrosyncError::Fs(crate::error::FsError::Io {
                        path: dest_path.clone(),
                        source: std::sync::Arc::new(e),
                    })
                })?;
            return Ok(Box::new(std::io::BufWriter::new(file)));
        }

        // --backup: create backup BEFORE writing (before AtomicFileWriter
        // renames the temp file to dest on drop).
        if self.options.backup() && self.fs.lexists(&dest_path) {
            file_decision::create_backup(
                &*self.fs,
                &dest_path,
                self.options.suffix(),
                self.backup_dir(),
            )?;
        }

        let write_path = if self.options.inplace() {
            dest_path.clone()
        } else if let Some(partial_dir) = self.options.partial_dir() {
            // --partial-dir: write to partial_dir/basename, rename in finish_file.
            self.fs.mkdir(partial_dir, 0o755)?;
            partial_dir.join(
                entry
                    .path()
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("partial")),
            )
        } else {
            // --partial or default: write directly to final destination.
            dest_path
        };

        let mode = if self.options.preserve_perms() {
            let mut m = entry.mode & 0o7777;
            if let Some(ref spec) = self.chmod_spec {
                m = spec.apply(m, false);
            }
            Some(m)
        } else {
            None
        };

        if self.options.inplace() {
            Ok(self.fs.write_file_inplace_stream(&write_path, mode)?)
        } else {
            Ok(self.fs.write_file_stream(&write_path, mode)?)
        }
    }

    /// Finalize a file after streaming write.
    ///
    /// Handles `--backup`, `--partial-dir` rename, metadata setting, and
    /// `--remove-source-files`.
    pub fn finish_file(
        &self,
        entry: &FileEntry,
        source_path: Option<&Path>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);

        // Backup was already created in create_writer() (before the write).
        // Proceed with partial-dir rename and metadata.

        // --partial-dir rename (this overwrites dest with the new content).
        if let Some(partial_dir) = self.options.partial_dir() {
            let partial_path = partial_dir.join(
                dest_path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("partial")),
            );
            if partial_path != dest_path {
                self.fs.rename(&partial_path, &dest_path)?;
            }
        }

        // Set metadata.
        file_decision::set_file_metadata(&*self.fs, &dest_path, entry, &self.options);

        // --remove-source-files
        if let Some(src) = source_path {
            if self.options.remove_source_files() && !self.options.dry_run() {
                let _ = self.fs.remove_file(src);
            }
        }

        Ok(())
    }

    /// Create a destination directory with all options.
    ///
    /// Handles `--keep-dirlinks`, `--preserve-perms`, and `--chmod`.
    pub fn create_directory(&self, entry: &FileEntry) -> std::result::Result<(), FsError> {
        let dest_path = self.dest_path(entry);

        // --keep-dirlinks: preserve existing symlink-to-directory.
        let dir_exists_as_symlink = self.options.keep_dirlinks()
            && !self.options.dry_run()
            && self
                .fs
                .lstat(&dest_path)
                .map(|m| m.mode & S_IFMT == S_IFLNK)
                .unwrap_or(false)
            && self
                .fs
                .stat(&dest_path)
                .map(|m| m.mode & S_IFMT == S_IFDIR)
                .unwrap_or(false);

        if !dir_exists_as_symlink && !self.options.dry_run() {
            let mut mode = if self.options.preserve_perms() {
                entry.mode & 0o7777
            } else {
                0o755
            };
            if let Some(ref spec) = self.chmod_spec {
                mode = spec.apply(mode, true);
            }
            self.fs.mkdir(&dest_path, mode)?;
        }

        Ok(())
    }

    /// Create a symlink with `--safe-links` check.
    ///
    /// Returns `Ok(false)` if the symlink was skipped (unsafe), `Ok(true)`
    /// if it was created successfully (or dry-run).
    pub fn create_symlink(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<bool, crate::FerrosyncError> {
        if self.options.safe_links() && file_decision::is_unsafe_symlink(&entry.link_target) {
            tracing::warn!(
                path = %self.dest_path(entry).display(),
                "skipping unsafe symlink"
            );
            return Ok(false);
        }
        if !self.options.dry_run() && !entry.link_target.is_empty() {
            let dest_path = self.dest_path(entry);
            self.fs.create_symlink(&entry.link_target, &dest_path)?;
        }
        Ok(true)
    }

    /// Create parent directories for a file entry if needed.
    pub fn ensure_parent(&self, entry: &FileEntry) -> std::result::Result<(), FsError> {
        let dest_path = self.dest_path(entry);
        if let Some(parent) = dest_path.parent() {
            if !self.fs.lexists(parent) {
                self.fs.mkdir(parent, 0o755)?;
            }
        }
        Ok(())
    }

    /// Access the underlying filesystem.
    pub fn fs(&self) -> &dyn FileSystem {
        &*self.fs
    }

    /// Access the transfer options.
    pub fn options(&self) -> &TransferOptions {
        &self.options
    }

    /// Access the destination path.
    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// Returns true if the buffered receive path should be used instead of streaming.
    ///
    /// Some features (like `--sparse`) require the full file data in memory
    /// to write correctly, so the streaming path cannot be used.
    pub fn needs_buffered_receive(&self) -> bool {
        self.options.sparse()
    }

    /// Run the unified receiver dispatch loop over a set of file entries.
    ///
    /// See [`process_entries_impl`] for the full dispatch order.
    pub async fn process_entries<P: DataProvider + Send>(
        &self,
        entries: &[(i32, FileEntry)],
        provider: &mut P,
        ctx: &mut ProcessContext<'_>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        process_entries_impl(
            &*self.fs,
            &self.dest,
            &self.options,
            self.chmod_spec.as_ref(),
            &self.resolved_link_dests,
            self.resolved_backup_dir.as_deref(),
            entries,
            provider,
            ctx,
        )
        .await
    }
}

/// Shared skip logic used by both `ReceiverEngine` and `ReceiverRef`.
///
/// Checks all skip criteria: `--existing`, `--ignore-existing`, `--max-size`,
/// `--min-size`, `--compare-dest`, quick-check (size+mtime), `--update`,
/// `--size-only`, `--ignore-times`, `--modify-window`.
fn should_skip_impl(
    fs: &dyn FileSystem,
    entry: &FileEntry,
    dest: &Path,
    options: &TransferOptions,
) -> bool {
    let dest_path = dest.join(entry.path());

    // --existing / --ignore-existing
    if file_decision::check_existence_skip(fs, &dest_path, options) {
        return true;
    }

    // --max-size / --min-size
    if file_decision::check_size_limits(entry, options) {
        return true;
    }

    // --compare-dest: skip if identical file exists in any compare-dest dir.
    if !options.compare_dest().is_empty()
        && file_decision::check_alt_dest(fs, entry, options.compare_dest(), options).is_some()
    {
        return true;
    }

    // Quick check: size+mtime comparison (unless --checksum mode).
    if !options.checksum_mode() {
        return file_decision::quick_check_skip(fs, entry, &dest_path, options);
    }

    false
}

/// Borrowed receiver engine for the local transfer path.
///
/// Wraps a borrowed `&dyn FileSystem` and the destination/options state
/// needed for receiver-side operations. All methods delegate to the same
/// logic as [`ReceiverEngine`] but without requiring `Arc`.
pub struct ReceiverRef<'a> {
    fs: &'a dyn FileSystem,
    dest: &'a Path,
    options: &'a TransferOptions,
    chmod_spec: Option<ChmodSpec>,
    resolved_link_dests: Vec<PathBuf>,
    resolved_backup_dir: Option<PathBuf>,
}

impl<'a> ReceiverRef<'a> {
    /// Create a borrowed receiver engine from references.
    pub fn new(fs: &'a dyn FileSystem, dest: &'a Path, options: &'a TransferOptions) -> Self {
        let resolved_link_dests = file_decision::resolve_link_dest_dirs(options.link_dest(), dest);
        let chmod_spec = if !options.chmod().is_empty() {
            ChmodSpec::parse(&options.chmod().join(",")).ok()
        } else {
            None
        };
        let resolved_backup_dir = options.backup_dir().map(|bd| {
            if bd.is_relative() {
                dest.join(bd)
            } else {
                bd.clone()
            }
        });
        Self {
            fs,
            dest,
            options,
            chmod_spec,
            resolved_link_dests,
            resolved_backup_dir,
        }
    }

    /// Resolved backup directory.
    pub fn backup_dir(&self) -> Option<&Path> {
        self.resolved_backup_dir.as_deref()
    }

    /// Resolve the destination path for an entry.
    pub fn dest_path(&self, entry: &FileEntry) -> PathBuf {
        self.dest.join(entry.path())
    }

    /// Check if a file should be skipped based on all skip criteria.
    pub fn should_skip_file(&self, entry: &FileEntry) -> bool {
        should_skip_impl(self.fs, entry, self.dest, self.options)
    }

    /// Attempt to satisfy a file via hard link from a `--link-dest` dir.
    pub fn try_link_dest(&self, entry: &FileEntry) -> bool {
        if self.resolved_link_dests.is_empty() || self.options.dry_run() {
            return false;
        }
        if let Some(alt_path) =
            file_decision::check_alt_dest(self.fs, entry, &self.resolved_link_dests, self.options)
        {
            let dest_path = self.dest_path(entry);
            let _ = self.fs.remove_file(&dest_path);
            if self.fs.hard_link(&alt_path, &dest_path).is_ok() {
                return true;
            }
        }
        false
    }

    /// Attempt to copy from a `--copy-dest` dir.
    pub fn try_copy_dest(&self, entry: &FileEntry) -> bool {
        if self.options.copy_dest().is_empty() || self.options.dry_run() {
            return false;
        }
        if let Some(alt_path) =
            file_decision::check_alt_dest(self.fs, entry, self.options.copy_dest(), self.options)
        {
            let dest_path = self.dest_path(entry);
            if self.fs.copy_file(&alt_path, &dest_path).is_ok() {
                return true;
            }
        }
        false
    }

    /// Write reconstructed file data to the destination with all options.
    pub fn receive_file(
        &self,
        entry: &FileEntry,
        data: &[u8],
        source_path: Option<&Path>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);

        if self.options.backup() && self.fs.lexists(&dest_path) {
            file_decision::create_backup(
                self.fs,
                &dest_path,
                self.options.suffix(),
                self.backup_dir(),
            )?;
        }

        let write_path = if let Some(partial_dir) = self.options.partial_dir() {
            let partial = partial_dir.join(dest_path.file_name().unwrap_or_default());
            self.fs.mkdir(partial_dir, 0o755)?;
            partial
        } else {
            dest_path.clone()
        };

        file_decision::write_file_with_options(
            self.fs,
            &write_path,
            data,
            entry,
            self.options,
            self.chmod_spec.as_ref(),
        )?;

        if self.options.partial_dir().is_some() && write_path != dest_path {
            self.fs.rename(&write_path, &dest_path)?;
        }

        file_decision::set_file_metadata(self.fs, &dest_path, entry, self.options);

        if let Some(src) = source_path {
            if self.options.remove_source_files() && !self.options.dry_run() {
                if let Err(e) = self.fs.remove_file(src) {
                    tracing::warn!(
                        path = %src.display(),
                        error = %e,
                        "failed to remove source file"
                    );
                }
            }
        }

        Ok(())
    }

    /// Create a destination directory with all options.
    pub fn create_directory(&self, entry: &FileEntry) -> std::result::Result<(), FsError> {
        let dest_path = self.dest_path(entry);

        let dir_exists_as_symlink = self.options.keep_dirlinks()
            && !self.options.dry_run()
            && self
                .fs
                .lstat(&dest_path)
                .map(|m| m.mode & S_IFMT == S_IFLNK)
                .unwrap_or(false)
            && self
                .fs
                .stat(&dest_path)
                .map(|m| m.mode & S_IFMT == S_IFDIR)
                .unwrap_or(false);

        if !dir_exists_as_symlink && !self.options.dry_run() {
            let mut mode = if self.options.preserve_perms() {
                entry.mode & 0o7777
            } else {
                0o755
            };
            if let Some(ref spec) = self.chmod_spec {
                mode = spec.apply(mode, true);
            }
            self.fs.mkdir(&dest_path, mode)?;
        }

        Ok(())
    }

    /// Create a symlink with `--safe-links` check.
    pub fn create_symlink(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<bool, crate::FerrosyncError> {
        if self.options.safe_links() && file_decision::is_unsafe_symlink(&entry.link_target) {
            tracing::warn!(
                path = %self.dest_path(entry).display(),
                "skipping unsafe symlink"
            );
            return Ok(false);
        }
        if !self.options.dry_run() && !entry.link_target.is_empty() {
            let dest_path = self.dest_path(entry);
            self.fs.create_symlink(&entry.link_target, &dest_path)?;
        }
        Ok(true)
    }

    /// Create parent directories for a file entry if needed.
    pub fn ensure_parent(&self, entry: &FileEntry) -> std::result::Result<(), FsError> {
        let dest_path = self.dest_path(entry);
        if let Some(parent) = dest_path.parent() {
            if !self.fs.lexists(parent) {
                self.fs.mkdir(parent, 0o755)?;
            }
        }
        Ok(())
    }

    /// Run the unified receiver dispatch loop over a set of file entries.
    ///
    /// See [`process_entries_impl`] for the full dispatch order.
    pub async fn process_entries<P: DataProvider + Send>(
        &self,
        entries: &[(i32, FileEntry)],
        provider: &mut P,
        ctx: &mut ProcessContext<'_>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        process_entries_impl(
            self.fs,
            self.dest,
            self.options,
            self.chmod_spec.as_ref(),
            &self.resolved_link_dests,
            self.resolved_backup_dir.as_deref(),
            entries,
            provider,
            ctx,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Shared process_entries implementation
// ---------------------------------------------------------------------------

/// Unified receiver dispatch loop.
///
/// This is the single implementation of the per-file dispatch logic used by
/// both `ReceiverEngine::process_entries()` and `ReceiverRef::process_entries()`.
///
/// The loop handles (in order):
/// 1. Directory creation with `--delete-during`
/// 2. Symlink creation (`-l`)
/// 3. Hard link deferral (`-H`)
/// 4. Skip checks (`--existing`, `--ignore-existing`, `--max-size`, etc.)
/// 5. `--link-dest` and `--copy-dest` satisfaction
/// 6. `--checksum` file-level comparison
/// 7. Itemized changes (`-i`)
/// 8. Dry-run accounting
/// 9. Append mode handling
/// 10. Data transfer via provider
/// 11. Deferred hard link creation
/// 12. `--delete-after`
#[allow(clippy::too_many_arguments)]
async fn process_entries_impl<P: DataProvider + Send>(
    fs: &dyn FileSystem,
    dest: &Path,
    options: &TransferOptions,
    chmod_spec: Option<&ChmodSpec>,
    resolved_link_dests: &[PathBuf],
    backup_dir: Option<&Path>,
    entries: &[(i32, FileEntry)],
    provider: &mut P,
    ctx: &mut ProcessContext<'_>,
) -> std::result::Result<(), crate::FerrosyncError> {
    let mut deferred_hardlinks: Vec<(&FileEntry, &[u8])> = Vec::new();

    for (index, entry) in entries {
        let index = *index;
        let dest_path = dest.join(entry.path());

        // --- Directories ---
        if entry.is_dir() {
            create_directory_impl(fs, &dest_path, entry, options, chmod_spec)?;
            ctx.stats.directories_created += 1;

            // --delete-during: remove extraneous files in this directory.
            if options.delete() == DeleteMode::During {
                if let Some(deleter) = ctx.deleter {
                    let deleted = deleter.delete_extraneous_in_dir(
                        &dest_path,
                        entries.iter().map(|(_, e)| e),
                        &entry.name,
                    )?;
                    ctx.stats.files_deleted += deleted;
                }
            }

            continue;
        }

        // --- Symlinks ---
        if entry.is_symlink() && options.preserve_links() {
            if !create_symlink_impl(fs, dest, entry, options)? {
                ctx.stats.files_skipped += 1;
                continue;
            }
            ctx.stats.symlinks += 1;
            ctx.progress.emit(ProgressEvent::FileComplete {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
                literal_bytes: 0,
                matched_bytes: 0,
            });
            continue;
        }

        // --- Non-regular files: skip ---
        if !entry.is_file() {
            continue;
        }

        // --- Hardlink duplicate: defer until first occurrences are on disk ---
        if let Some(ref source_name) = entry.hlink_source {
            deferred_hardlinks.push((entry, source_name.as_slice()));
            continue;
        }

        // --- Skip checks ---
        if should_skip_impl(fs, entry, dest, options) {
            ctx.stats.files_skipped += 1;
            ctx.progress.emit(ProgressEvent::FileSkipped {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
            });
            continue;
        }

        // --- link-dest ---
        if try_link_dest_impl(fs, entry, dest, resolved_link_dests, options) {
            ctx.stats.files_transferred += 1;
            ctx.progress.emit(ProgressEvent::FileComplete {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
                literal_bytes: 0,
                matched_bytes: entry.len as u64,
            });
            continue;
        }

        // --- copy-dest ---
        if try_copy_dest_impl(fs, entry, dest, options) {
            ctx.stats.files_transferred += 1;
            ctx.progress.emit(ProgressEvent::FileComplete {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
                literal_bytes: 0,
                matched_bytes: entry.len as u64,
            });
            continue;
        }

        // --- Checksum mode: file-level comparison ---
        if options.checksum_mode() {
            if let Ok(dest_data) = fs.map_file(&dest_path) {
                if let Some(src_sum) = provider.source_checksum(entry, ctx.protocol_ctx) {
                    let dst_sum = checksum::file_checksum(&dest_data, ctx.protocol_ctx);
                    if src_sum == dst_sum {
                        ctx.stats.files_skipped += 1;
                        ctx.progress.emit(ProgressEvent::FileSkipped {
                            index,
                            name: super::progress::name_to_pathbuf(&entry.name),
                        });
                        continue;
                    }
                }
            }
        }

        // --- Itemized changes ---
        if options.itemize_changes() {
            let changes = file_decision::compute_itemized(fs, entry, &dest_path, options);
            ctx.progress.emit(ProgressEvent::FileItemized {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
                changes,
            });
        }

        ctx.progress.emit(ProgressEvent::FileStart {
            index,
            name: super::progress::name_to_pathbuf(&entry.name),
            size: entry.len,
        });

        // --- Dry run ---
        if options.dry_run() {
            ctx.stats.files_transferred += 1;
            ctx.stats.total_size += entry.len as u64;
            ctx.progress.emit(ProgressEvent::FileComplete {
                index,
                name: super::progress::name_to_pathbuf(&entry.name),
                literal_bytes: entry.len as u64,
                matched_bytes: 0,
            });
            continue;
        }

        // --- Read basis file ---
        let basis_data = fs.map_file(&dest_path).unwrap_or_default();

        // --- Append mode ---
        if (options.append() || options.append_verify()) && !basis_data.is_empty() {
            match provider
                .handle_append(index, entry, &dest_path, &basis_data)
                .await?
            {
                Some(AppendResult::Appended {
                    literal_bytes,
                    matched_bytes,
                }) => {
                    ctx.stats.files_transferred += 1;
                    ctx.stats.total_size += entry.len as u64;
                    ctx.stats.literal_data += literal_bytes;
                    ctx.stats.bytes_sent += literal_bytes;
                    ctx.progress.emit(ProgressEvent::FileComplete {
                        index,
                        name: super::progress::name_to_pathbuf(&entry.name),
                        literal_bytes,
                        matched_bytes,
                    });
                    continue;
                }
                Some(AppendResult::Skip) => {
                    ctx.stats.files_skipped += 1;
                    ctx.progress.emit(ProgressEvent::FileSkipped {
                        index,
                        name: super::progress::name_to_pathbuf(&entry.name),
                    });
                    continue;
                }
                None => {
                    // Fall through to full transfer.
                    // This happens for append-verify mismatch.
                }
            }
        }

        // --- Data transfer via provider ---
        let data = provider.provide_data(index, entry, &basis_data).await?;
        let literal_bytes = data.len() as u64;

        // Write to destination with backup, metadata, etc.
        let source_path = provider.source_path(entry);
        receive_file_impl(
            fs,
            dest,
            entry,
            &data,
            source_path.as_deref(),
            options,
            chmod_spec,
            backup_dir,
        )?;

        ctx.stats.files_transferred += 1;
        ctx.stats.total_size += entry.len as u64;
        ctx.stats.literal_data += literal_bytes;
        ctx.stats.bytes_sent += literal_bytes;

        ctx.progress.emit(ProgressEvent::FileComplete {
            index,
            name: super::progress::name_to_pathbuf(&entry.name),
            literal_bytes,
            matched_bytes: 0,
        });

        // --- Bandwidth limiting ---
        if let Some(limit) = options.bwlimit() {
            if limit > 0 {
                let sleep_secs = literal_bytes as f64 / limit as f64;
                if sleep_secs > 0.001 {
                    tokio::time::sleep(Duration::from_secs_f64(sleep_secs)).await;
                }
            }
        }
    }

    // Create deferred hardlinks now that first occurrences are on disk.
    for (dup_entry, source_name) in &deferred_hardlinks {
        if let Some((_, source)) = entries.iter().find(|(_, e)| e.name == *source_name) {
            let source_path = dest.join(source.path());
            let link_path = dest.join(dup_entry.path());
            if !options.dry_run() {
                let _ = fs.remove_file(&link_path);
                if let Err(e) = fs.hard_link(&source_path, &link_path) {
                    tracing::warn!(
                        source = %String::from_utf8_lossy(source_name),
                        link = %String::from_utf8_lossy(&dup_entry.name),
                        error = %e,
                        "deferred hardlink creation failed"
                    );
                } else {
                    ctx.stats.files_transferred += 1;
                }
            } else {
                ctx.stats.files_transferred += 1;
            }
        }
    }

    // --- delete-after ---
    if options.delete() == DeleteMode::After {
        if let Some(deleter) = ctx.deleter {
            let deleted = deleter.delete_extraneous(dest, entries.iter().map(|(_, e)| e))?;
            ctx.stats.files_deleted = deleted;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helper functions for process_entries_impl
// ---------------------------------------------------------------------------

/// Create a directory (shared between ReceiverEngine, ReceiverRef, and process_entries_impl).
fn create_directory_impl(
    fs: &dyn FileSystem,
    dest_path: &Path,
    entry: &FileEntry,
    options: &TransferOptions,
    chmod_spec: Option<&ChmodSpec>,
) -> std::result::Result<(), FsError> {
    let dir_exists_as_symlink = options.keep_dirlinks()
        && !options.dry_run()
        && fs
            .lstat(dest_path)
            .map(|m| m.mode & S_IFMT == S_IFLNK)
            .unwrap_or(false)
        && fs
            .stat(dest_path)
            .map(|m| m.mode & S_IFMT == S_IFDIR)
            .unwrap_or(false);

    if !dir_exists_as_symlink && !options.dry_run() {
        let mut mode = if options.preserve_perms() {
            entry.mode & 0o7777
        } else {
            0o755
        };
        if let Some(spec) = chmod_spec {
            mode = spec.apply(mode, true);
        }
        fs.mkdir(dest_path, mode)?;
    }

    Ok(())
}

/// Create a symlink (shared between ReceiverEngine, ReceiverRef, and process_entries_impl).
fn create_symlink_impl(
    fs: &dyn FileSystem,
    dest: &Path,
    entry: &FileEntry,
    options: &TransferOptions,
) -> std::result::Result<bool, crate::FerrosyncError> {
    if options.safe_links() && file_decision::is_unsafe_symlink(&entry.link_target) {
        tracing::warn!(
            path = %dest.join(entry.path()).display(),
            "skipping unsafe symlink"
        );
        return Ok(false);
    }
    if !options.dry_run() && !entry.link_target.is_empty() {
        let dest_path = dest.join(entry.path());
        fs.create_symlink(&entry.link_target, &dest_path)?;
    }
    Ok(true)
}

/// Try link-dest (shared).
fn try_link_dest_impl(
    fs: &dyn FileSystem,
    entry: &FileEntry,
    dest: &Path,
    resolved_link_dests: &[PathBuf],
    options: &TransferOptions,
) -> bool {
    if resolved_link_dests.is_empty() || options.dry_run() {
        return false;
    }
    if let Some(alt_path) = file_decision::check_alt_dest(fs, entry, resolved_link_dests, options) {
        let dest_path = dest.join(entry.path());
        let _ = fs.remove_file(&dest_path);
        if fs.hard_link(&alt_path, &dest_path).is_ok() {
            return true;
        }
    }
    false
}

/// Try copy-dest (shared).
fn try_copy_dest_impl(
    fs: &dyn FileSystem,
    entry: &FileEntry,
    dest: &Path,
    options: &TransferOptions,
) -> bool {
    if options.copy_dest().is_empty() || options.dry_run() {
        return false;
    }
    if let Some(alt_path) = file_decision::check_alt_dest(fs, entry, options.copy_dest(), options) {
        let dest_path = dest.join(entry.path());
        if fs.copy_file(&alt_path, &dest_path).is_ok() {
            return true;
        }
    }
    false
}

/// Write file data to destination (shared).
#[allow(clippy::too_many_arguments)]
fn receive_file_impl(
    fs: &dyn FileSystem,
    dest: &Path,
    entry: &FileEntry,
    data: &[u8],
    source_path: Option<&Path>,
    options: &TransferOptions,
    chmod_spec: Option<&ChmodSpec>,
    backup_dir: Option<&Path>,
) -> std::result::Result<(), crate::FerrosyncError> {
    let dest_path = dest.join(entry.path());

    if options.backup() && fs.lexists(&dest_path) {
        file_decision::create_backup(fs, &dest_path, options.suffix(), backup_dir)?;
    }

    let write_path = if let Some(partial_dir) = options.partial_dir() {
        let partial = partial_dir.join(dest_path.file_name().unwrap_or_default());
        fs.mkdir(partial_dir, 0o755)?;
        partial
    } else {
        dest_path.clone()
    };

    file_decision::write_file_with_options(fs, &write_path, data, entry, options, chmod_spec)?;

    if options.partial_dir().is_some() && write_path != dest_path {
        fs.rename(&write_path, &dest_path)?;
    }

    file_decision::set_file_metadata(fs, &dest_path, entry, options);

    if let Some(src) = source_path {
        if options.remove_source_files() && !options.dry_run() {
            if let Err(e) = fs.remove_file(src) {
                tracing::warn!(
                    path = %src.display(),
                    error = %e,
                    "failed to remove source file"
                );
            }
        }
    }

    Ok(())
}
