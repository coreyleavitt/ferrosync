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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::chmod::ChmodSpec;
use crate::engine::file_decision;
use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFLNK, S_IFMT};
use crate::fs::FileSystem;
use crate::options::TransferOptions;

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
}

impl ReceiverEngine {
    /// Create a new receiver engine.
    ///
    /// Resolves `--link-dest` directories and parses `--chmod` specs upfront.
    pub fn new(fs: Arc<dyn FileSystem>, dest: PathBuf, options: TransferOptions) -> Self {
        let resolved_link_dests = file_decision::resolve_link_dest_dirs(options.link_dest(), &dest);
        let chmod_spec = if !options.chmod().is_empty() {
            ChmodSpec::parse(&options.chmod().join(",")).ok()
        } else {
            None
        };
        Self {
            fs,
            dest,
            options,
            chmod_spec,
            resolved_link_dests,
        }
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
                self.options.backup_dir().map(|p| p.as_path()),
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

        // FIRST: create backup of existing dest file before any overwrite/rename.
        if self.options.backup() && self.fs.lexists(&dest_path) {
            file_decision::create_backup(
                &*self.fs,
                &dest_path,
                self.options.suffix(),
                self.options.backup_dir().map(|p| p.as_path()),
            )?;
        }

        // THEN: --partial-dir rename (this overwrites dest with the new content).
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
        Self {
            fs,
            dest,
            options,
            chmod_spec,
            resolved_link_dests,
        }
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
                self.options.backup_dir().map(|p| p.as_path()),
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
}
