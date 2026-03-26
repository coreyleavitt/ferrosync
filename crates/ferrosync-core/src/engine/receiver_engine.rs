//! Unified receiver engine for destination-side file operations.
//!
//! Extracts all destination-side logic (skip checks, backup, file writing,
//! metadata setting) into a single struct used by both the local transfer
//! engine and the wire transfer receiver. This eliminates the feature gap
//! where flags work locally but not over SSH.
//!
//! The engine stores an `Arc<dyn FileSystem>` for owned usage (wire transfers).
//! For borrowed usage (local transfer engine, streaming), callers construct a
//! `ReceiverRef` which borrows references without requiring `Arc`.
//!
//! ## dispatch_entry architecture
//!
//! [`ReceiverEngine::dispatch_entry()`] separates file dispatch decisions
//! from data transfer I/O. Each entry is dispatched to one of:
//! - [`EntryAction::Handled`] -- directory created, symlink created, link-dest, etc.
//! - [`EntryAction::Skipped`] -- up to date, filtered, size limits.
//! - [`EntryAction::DeferredHardlink`] -- defer until first occurrences are on disk.
//! - [`EntryAction::NeedsTransfer`] -- needs data transfer with basis for delta.
//!
//! The caller (local engine or wire generator) handles stats, progress, and
//! the actual data transfer based on the returned action.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::chmod::ChmodSpec;
use crate::engine::file_decision;
use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFLNK, S_IFMT};
use crate::fs::{FileData, FileSystem};
use crate::options::TransferConfig;

// ---------------------------------------------------------------------------
// dispatch_entry types
// ---------------------------------------------------------------------------

/// What kind of non-transfer handling occurred.
#[derive(Debug, Clone, Copy)]
pub enum HandledKind {
    Directory,
    Symlink,
    LinkDest,
    CopyDest,
    DryRun,
}

/// Result of dispatching a single file entry.
///
/// Separates the file dispatch decision from data transfer I/O.
/// The caller uses this to determine what action to take for each entry.
pub enum EntryAction {
    /// Fully handled (dir created, symlink created, link-dest linked, etc.)
    Handled { kind: HandledKind },
    /// Skipped (up to date, filtered, size limits).
    Skipped,
    /// Hardlink duplicate -- defer until first occurrences are on disk.
    DeferredHardlink { source_name: Vec<u8> },
    /// Needs data transfer. Basis data for delta computation.
    NeedsTransfer { basis: FileData },
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
    options: TransferConfig,
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
    pub fn new(fs: Arc<dyn FileSystem>, dest: PathBuf, options: TransferConfig) -> Self {
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

    /// Access the transfer configuration.
    pub fn options(&self) -> &TransferConfig {
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

    /// Dispatch a single entry through the full decision pipeline.
    ///
    /// Creates dirs, symlinks, hard links for non-transfer outcomes.
    /// Returns what the caller should do about data. The caller is
    /// responsible for delete-during (which needs the full entry list),
    /// stats tracking, and progress emission.
    pub fn dispatch_entry(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<EntryAction, crate::FerrosyncError> {
        dispatch_entry_impl(
            &*self.fs,
            &self.dest,
            entry,
            &self.options,
            self.chmod_spec.as_ref(),
            &self.resolved_link_dests,
        )
    }

    /// Apply a completed data transfer (write file, set metadata).
    ///
    /// Delegates to `receive_file` which handles backup, partial-dir, etc.
    pub fn apply_transfer(
        &self,
        entry: &FileEntry,
        data: &[u8],
        source_path: Option<&Path>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        self.receive_file(entry, data, source_path)
    }

    /// Create deferred hardlinks. Returns count of links created.
    pub fn create_deferred_hardlinks(
        &self,
        deferred: &[(&FileEntry, Vec<u8>)],
        all_entries: &[FileEntry],
    ) -> std::result::Result<u64, crate::FerrosyncError> {
        create_deferred_hardlinks_impl(&*self.fs, &self.dest, &self.options, deferred, all_entries)
    }

    /// Search for a similar file to use as delta basis (`--fuzzy`).
    ///
    /// When the destination file doesn't exist, searches the same directory
    /// for files with matching size+mtime (exact match) or similar names
    /// (fuzzy match) to use as a delta basis.
    pub fn find_fuzzy_basis(&self, entry: &FileEntry) -> Option<FileData> {
        find_fuzzy_basis_impl(&*self.fs, entry, &self.dest, &self.options)
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
    options: &TransferConfig,
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
    options: &'a TransferConfig,
    chmod_spec: Option<ChmodSpec>,
    resolved_link_dests: Vec<PathBuf>,
    resolved_backup_dir: Option<PathBuf>,
}

impl<'a> ReceiverRef<'a> {
    /// Create a borrowed receiver engine from references.
    pub fn new(fs: &'a dyn FileSystem, dest: &'a Path, options: &'a TransferConfig) -> Self {
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

    /// Dispatch a single entry through the full decision pipeline.
    ///
    /// See [`ReceiverEngine::dispatch_entry`] for details.
    pub fn dispatch_entry(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<EntryAction, crate::FerrosyncError> {
        dispatch_entry_impl(
            self.fs,
            self.dest,
            entry,
            self.options,
            self.chmod_spec.as_ref(),
            &self.resolved_link_dests,
        )
    }

    /// Apply a completed data transfer (write file, set metadata).
    pub fn apply_transfer(
        &self,
        entry: &FileEntry,
        data: &[u8],
        source_path: Option<&Path>,
    ) -> std::result::Result<(), crate::FerrosyncError> {
        self.receive_file(entry, data, source_path)
    }

    /// Create deferred hardlinks. Returns count of links created.
    pub fn create_deferred_hardlinks(
        &self,
        deferred: &[(&FileEntry, Vec<u8>)],
        all_entries: &[FileEntry],
    ) -> std::result::Result<u64, crate::FerrosyncError> {
        create_deferred_hardlinks_impl(self.fs, self.dest, self.options, deferred, all_entries)
    }
}

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

/// Create a directory (shared between ReceiverEngine, ReceiverRef, and dispatch_entry).
fn create_directory_impl(
    fs: &dyn FileSystem,
    dest_path: &Path,
    entry: &FileEntry,
    options: &TransferConfig,
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
    options: &TransferConfig,
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
    options: &TransferConfig,
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
    options: &TransferConfig,
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

// ---------------------------------------------------------------------------
// Shared dispatch_entry implementation
// ---------------------------------------------------------------------------

/// Dispatch a single file entry through the full decision pipeline.
///
/// This is the shared implementation used by both `ReceiverEngine::dispatch_entry()`
/// and `ReceiverRef::dispatch_entry()`. It determines what action is needed for
/// each entry without performing any data transfer I/O.
///
/// The decision order:
/// 1. Directory -> create it, return `Handled(Directory)`
/// 2. Symlink -> create it, return `Handled(Symlink)` or `Skipped` (unsafe)
/// 3. Non-regular file -> `Skipped`
/// 4. Hardlink duplicate -> `DeferredHardlink`
/// 5. Skip checks -> `Skipped`
/// 6. Link-dest -> `Handled(LinkDest)`
/// 7. Copy-dest -> `Handled(CopyDest)`
/// 8. Dry-run -> `Handled(DryRun)`
/// 9. Read basis -> `NeedsTransfer { basis }`
#[allow(clippy::too_many_arguments)]
fn dispatch_entry_impl(
    fs: &dyn FileSystem,
    dest: &Path,
    entry: &FileEntry,
    options: &TransferConfig,
    chmod_spec: Option<&ChmodSpec>,
    resolved_link_dests: &[PathBuf],
) -> std::result::Result<EntryAction, crate::FerrosyncError> {
    let dest_path = dest.join(entry.path());

    // 1. Directory
    if entry.is_dir() {
        create_directory_impl(fs, &dest_path, entry, options, chmod_spec)?;
        return Ok(EntryAction::Handled {
            kind: HandledKind::Directory,
        });
    }

    // 2. Symlink
    if entry.is_symlink() && options.preserve_links() {
        let created = create_symlink_impl(fs, dest, entry, options)?;
        if !created {
            return Ok(EntryAction::Skipped);
        }
        return Ok(EntryAction::Handled {
            kind: HandledKind::Symlink,
        });
    }

    // 3. Non-regular file
    if !entry.is_file() {
        return Ok(EntryAction::Skipped);
    }

    // 4. Hardlink duplicate
    if let Some(ref source_name) = entry.hlink_source {
        return Ok(EntryAction::DeferredHardlink {
            source_name: source_name.clone(),
        });
    }

    // 5. Skip checks
    if should_skip_impl(fs, entry, dest, options) {
        return Ok(EntryAction::Skipped);
    }

    // 6. Link-dest
    if try_link_dest_impl(fs, entry, dest, resolved_link_dests, options) {
        return Ok(EntryAction::Handled {
            kind: HandledKind::LinkDest,
        });
    }

    // 7. Copy-dest
    if try_copy_dest_impl(fs, entry, dest, options) {
        return Ok(EntryAction::Handled {
            kind: HandledKind::CopyDest,
        });
    }

    // 8. Dry-run
    if options.dry_run() {
        return Ok(EntryAction::Handled {
            kind: HandledKind::DryRun,
        });
    }

    // 9. Read basis, return NeedsTransfer
    let basis = fs.map_file(&dest_path).unwrap_or_default();
    Ok(EntryAction::NeedsTransfer { basis })
}

/// Create deferred hardlinks (shared implementation).
///
/// Links each deferred entry to its source entry's destination path.
/// Returns the count of successfully created links.
fn create_deferred_hardlinks_impl(
    fs: &dyn FileSystem,
    dest: &Path,
    options: &TransferConfig,
    deferred: &[(&FileEntry, Vec<u8>)],
    all_entries: &[FileEntry],
) -> std::result::Result<u64, crate::FerrosyncError> {
    let mut count = 0;
    for (dup_entry, source_name) in deferred {
        if let Some(source) = all_entries.iter().find(|e| e.name == *source_name) {
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
                    continue;
                }
            }
            count += 1;
        }
    }
    Ok(count)
}

/// Search for a similar file to use as delta basis (`--fuzzy`).
fn find_fuzzy_basis_impl(
    fs: &dyn FileSystem,
    entry: &FileEntry,
    dest: &Path,
    options: &TransferConfig,
) -> Option<FileData> {
    if !options.fuzzy() {
        return None;
    }
    let dest_path = dest.join(entry.path());
    let parent = dest_path.parent()?;
    let target_name = dest_path.file_name()?;

    let dir_entries = fs.read_dir(parent).ok()?;

    // Pass 1: find file with same size and mtime.
    for e in &dir_entries {
        if e.metadata.len == entry.len && e.metadata.mtime == entry.mtime {
            let path = parent.join(FileEntry::name_to_pathbuf(&e.name));
            if let Ok(data) = fs.map_file(&path) {
                return Some(data);
            }
        }
    }

    // Pass 2: find file with most similar name.
    let target_bytes = target_name.as_encoded_bytes();
    let mut best_score = 0.5f64;
    let mut best_path: Option<PathBuf> = None;

    for e in &dir_entries {
        let score = file_decision::fuzzy_score(target_bytes, &e.name);
        if score > best_score {
            best_score = score;
            best_path = Some(parent.join(FileEntry::name_to_pathbuf(&e.name)));
        }
    }

    best_path.and_then(|p| fs.map_file(&p).ok())
}
