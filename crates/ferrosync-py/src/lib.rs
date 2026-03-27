//! Python bindings for ferrosync.
//!
//! Exposes the ferrosync-core library to Python via PyO3. Provides:
//! - `TransferOptions` (kwargs constructor mapping to Rust builder)
//! - `SyncResult` / `TransferStats` (transfer output)
//! - `FileEntry` (read-only file metadata)
//! - `sync_files()` (blocking transfer entry point)
//! - Enum types: `DeleteMode`, `Verbosity`, `ChecksumType`
//! - Exception hierarchy: `FerrosyncError` with subtypes

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use ferrosync_core::engine::progress::{ProgressCallback, ProgressEvent, ProgressTracker};
use ferrosync_core::engine::transfer;
use ferrosync_core::filelist::entry::FileEntry;
use ferrosync_core::options::{
    DeleteMode as RustDeleteMode, TransferOptions as RustTransferOptions,
    Verbosity as RustVerbosity,
};
use ferrosync_core::protocol::handshake::ChecksumType as RustChecksumType;
use ferrosync_core::stats::TransferStats as RustTransferStats;

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Exception hierarchy
// ---------------------------------------------------------------------------

pyo3::create_exception!(ferrosync._ferrosync, FerrosyncError, PyException);
pyo3::create_exception!(ferrosync._ferrosync, ProtocolError, FerrosyncError);
pyo3::create_exception!(ferrosync._ferrosync, TransportError, FerrosyncError);
pyo3::create_exception!(ferrosync._ferrosync, FilesystemError, FerrosyncError);
pyo3::create_exception!(ferrosync._ferrosync, FilterError, FerrosyncError);
pyo3::create_exception!(ferrosync._ferrosync, ChecksumMismatchError, ProtocolError);

fn to_py_err(e: ferrosync_core::FerrosyncError) -> PyErr {
    use ferrosync_core::error;
    match e {
        ferrosync_core::FerrosyncError::Protocol(ref pe) => match pe {
            error::ProtocolError::ChecksumMismatch { .. } => {
                ChecksumMismatchError::new_err(e.to_string())
            }
            _ => ProtocolError::new_err(e.to_string()),
        },
        ferrosync_core::FerrosyncError::Transport(_) => TransportError::new_err(e.to_string()),
        ferrosync_core::FerrosyncError::Fs(_) => FilesystemError::new_err(e.to_string()),
        ferrosync_core::FerrosyncError::Filter(_) => FilterError::new_err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Enum wrappers
// ---------------------------------------------------------------------------

/// Delete mode for handling extraneous files on the receiver.
#[pyclass(module = "ferrosync._ferrosync", eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// No deletion.
    None = 0,
    /// Delete before transfer.
    Before = 1,
    /// Delete during transfer (default for --delete).
    During = 2,
    /// Delete after transfer.
    After = 3,
    /// Delete excluded files too.
    Excluded = 4,
}

impl From<DeleteMode> for RustDeleteMode {
    fn from(v: DeleteMode) -> Self {
        match v {
            DeleteMode::None => RustDeleteMode::None,
            DeleteMode::Before => RustDeleteMode::Before,
            DeleteMode::During => RustDeleteMode::During,
            DeleteMode::After => RustDeleteMode::After,
            DeleteMode::Excluded => RustDeleteMode::Excluded,
        }
    }
}

impl From<RustDeleteMode> for DeleteMode {
    fn from(v: RustDeleteMode) -> Self {
        match v {
            RustDeleteMode::None => DeleteMode::None,
            RustDeleteMode::Before => DeleteMode::Before,
            RustDeleteMode::During => DeleteMode::During,
            RustDeleteMode::After => DeleteMode::After,
            RustDeleteMode::Excluded => DeleteMode::Excluded,
        }
    }
}

/// Verbosity level.
#[pyclass(module = "ferrosync._ferrosync", eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet = 0,
    Normal = 1,
    Verbose = 2,
    VeryVerbose = 3,
    Debug = 4,
}

impl From<Verbosity> for RustVerbosity {
    fn from(v: Verbosity) -> Self {
        match v {
            Verbosity::Quiet => RustVerbosity::Quiet,
            Verbosity::Normal => RustVerbosity::Normal,
            Verbosity::Verbose => RustVerbosity::Verbose,
            Verbosity::VeryVerbose => RustVerbosity::VeryVerbose,
            Verbosity::Debug => RustVerbosity::Debug,
        }
    }
}

impl From<RustVerbosity> for Verbosity {
    fn from(v: RustVerbosity) -> Self {
        match v {
            RustVerbosity::Quiet => Verbosity::Quiet,
            RustVerbosity::Normal => Verbosity::Normal,
            RustVerbosity::Verbose => Verbosity::Verbose,
            RustVerbosity::VeryVerbose => Verbosity::VeryVerbose,
            RustVerbosity::Debug => Verbosity::Debug,
        }
    }
}

/// Checksum algorithm for strong verification.
#[pyclass(module = "ferrosync._ferrosync", eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType {
    None = 0,
    Md4 = 1,
    Md5 = 2,
    Blake3 = 3,
    Xxh3 = 4,
    Xxh128 = 5,
}

impl From<ChecksumType> for RustChecksumType {
    fn from(v: ChecksumType) -> Self {
        match v {
            ChecksumType::None => RustChecksumType::None,
            ChecksumType::Md4 => RustChecksumType::Md4,
            ChecksumType::Md5 => RustChecksumType::Md5,
            ChecksumType::Blake3 => RustChecksumType::Blake3,
            ChecksumType::Xxh3 => RustChecksumType::Xxh3,
            ChecksumType::Xxh128 => RustChecksumType::Xxh128,
        }
    }
}

impl From<RustChecksumType> for ChecksumType {
    fn from(v: RustChecksumType) -> Self {
        match v {
            RustChecksumType::None => ChecksumType::None,
            RustChecksumType::Md4 => ChecksumType::Md4,
            RustChecksumType::Md5 => ChecksumType::Md5,
            RustChecksumType::Blake3 => ChecksumType::Blake3,
            RustChecksumType::Xxh3 => ChecksumType::Xxh3,
            RustChecksumType::Xxh128 => ChecksumType::Xxh128,
        }
    }
}

// ---------------------------------------------------------------------------
// TransferOptions
// ---------------------------------------------------------------------------

/// Transfer options controlling rsync behavior.
///
/// All parameters are keyword-only with sensible defaults.
///
/// Example::
///
///     opts = TransferOptions(
///         source=["/src/dir"],
///         dest="/dst/dir",
///         archive=True,
///         dry_run=True,
///     )
#[pyclass(module = "ferrosync._ferrosync", from_py_object)]
#[derive(Debug, Clone)]
pub struct TransferOptions {
    inner: RustTransferOptions,
}

#[pymethods]
impl TransferOptions {
    #[new]
    #[pyo3(signature = (
        *,
        source = vec![],
        dest = None,
        archive = false,
        recursive = false,
        preserve_links = false,
        preserve_perms = false,
        preserve_times = false,
        preserve_group = false,
        preserve_owner = false,
        preserve_devices = false,
        preserve_specials = false,
        checksum_mode = false,
        whole_file = false,
        update = false,
        inplace = false,
        delete = DeleteMode::None,
        compress = false,
        compress_level = 6,
        verbosity = Verbosity::Normal,
        progress = false,
        stats = false,
        dry_run = false,
        itemize_changes = false,
        exclude = vec![],
        include = vec![],
        filter = vec![],
        bwlimit = None,
        max_size = None,
        min_size = None,
        timeout = None,
        link_dest = vec![],
        copy_dest = vec![],
        compare_dest = vec![],
        backup = false,
        backup_dir = None,
        suffix = String::from("~"),
        partial = false,
        partial_dir = None,
        relative = false,
        append = false,
        files_from = None,
        one_file_system = false,
        numeric_ids = false,
        sparse = false,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        source: Vec<String>,
        dest: Option<String>,
        archive: bool,
        recursive: bool,
        preserve_links: bool,
        preserve_perms: bool,
        preserve_times: bool,
        preserve_group: bool,
        preserve_owner: bool,
        preserve_devices: bool,
        preserve_specials: bool,
        checksum_mode: bool,
        whole_file: bool,
        update: bool,
        inplace: bool,
        delete: DeleteMode,
        compress: bool,
        compress_level: u32,
        verbosity: Verbosity,
        progress: bool,
        stats: bool,
        dry_run: bool,
        itemize_changes: bool,
        exclude: Vec<String>,
        include: Vec<String>,
        filter: Vec<String>,
        bwlimit: Option<u64>,
        max_size: Option<u64>,
        min_size: Option<u64>,
        timeout: Option<u64>,
        link_dest: Vec<String>,
        copy_dest: Vec<String>,
        compare_dest: Vec<String>,
        backup: bool,
        backup_dir: Option<String>,
        suffix: String,
        partial: bool,
        partial_dir: Option<String>,
        relative: bool,
        append: bool,
        files_from: Option<String>,
        one_file_system: bool,
        numeric_ids: bool,
        sparse: bool,
    ) -> Self {
        let mut builder = RustTransferOptions::builder();

        if archive {
            builder = builder.archive();
        } else {
            builder = builder
                .recursive(recursive)
                .preserve_links(preserve_links)
                .preserve_perms(preserve_perms)
                .preserve_times(preserve_times)
                .preserve_group(preserve_group)
                .preserve_owner(preserve_owner)
                .preserve_devices(preserve_devices)
                .preserve_specials(preserve_specials);
        }

        builder = builder
            .checksum_mode(checksum_mode)
            .whole_file(whole_file)
            .update(update)
            .inplace(inplace)
            .delete(delete.into())
            .compress(compress)
            .compress_level(compress_level)
            .verbosity(verbosity.into())
            .progress(progress)
            .stats(stats)
            .dry_run(dry_run)
            .itemize_changes(itemize_changes)
            .excludes(exclude)
            .includes(include)
            .filters(filter)
            .sources(source.into_iter().map(PathBuf::from).collect())
            .backup(backup)
            .suffix(suffix)
            .append(append)
            .one_file_system(one_file_system)
            .numeric_ids(numeric_ids)
            .sparse(sparse)
            .link_dests(link_dest.into_iter().map(PathBuf::from).collect())
            .copy_dests(copy_dest.into_iter().map(PathBuf::from).collect())
            .compare_dests(compare_dest.into_iter().map(PathBuf::from).collect());

        if let Some(d) = dest {
            builder = builder.dest(PathBuf::from(d));
        }
        if let Some(v) = bwlimit {
            builder = builder.bwlimit(v);
        }
        if let Some(v) = max_size {
            builder = builder.max_size(v);
        }
        if let Some(v) = min_size {
            builder = builder.min_size(v);
        }
        if let Some(v) = timeout {
            builder = builder.timeout(v);
        }
        if let Some(v) = backup_dir {
            builder = builder.backup_dir(PathBuf::from(v));
        }
        builder = builder.partial(partial);
        if let Some(v) = partial_dir {
            builder = builder.partial_dir(PathBuf::from(v));
        }
        builder = builder.relative(relative);
        if let Some(v) = files_from {
            builder = builder.files_from(PathBuf::from(v));
        }

        Self {
            inner: builder.build(),
        }
    }

    #[getter]
    fn recursive(&self) -> bool {
        self.inner.recursive()
    }
    #[getter]
    fn preserve_links(&self) -> bool {
        self.inner.preserve_links()
    }
    #[getter]
    fn preserve_perms(&self) -> bool {
        self.inner.preserve_perms()
    }
    #[getter]
    fn preserve_times(&self) -> bool {
        self.inner.preserve_times()
    }
    #[getter]
    fn preserve_group(&self) -> bool {
        self.inner.preserve_group()
    }
    #[getter]
    fn preserve_owner(&self) -> bool {
        self.inner.preserve_owner()
    }
    #[getter]
    fn preserve_devices(&self) -> bool {
        self.inner.preserve_devices()
    }
    #[getter]
    fn preserve_specials(&self) -> bool {
        self.inner.preserve_specials()
    }
    #[getter]
    fn checksum_mode(&self) -> bool {
        self.inner.checksum_mode()
    }
    #[getter]
    fn whole_file(&self) -> bool {
        self.inner.whole_file()
    }
    #[getter]
    fn update(&self) -> bool {
        self.inner.update()
    }
    #[getter]
    fn inplace(&self) -> bool {
        self.inner.inplace()
    }
    #[getter]
    fn delete(&self) -> DeleteMode {
        self.inner.delete().into()
    }
    #[getter]
    fn compress(&self) -> bool {
        self.inner.compress()
    }
    #[getter]
    fn compress_level(&self) -> u32 {
        self.inner.compress_level()
    }
    #[getter]
    fn verbosity(&self) -> Verbosity {
        self.inner.verbosity().into()
    }
    #[getter]
    fn progress(&self) -> bool {
        self.inner.progress()
    }
    #[getter]
    fn stats(&self) -> bool {
        self.inner.stats()
    }
    #[getter]
    fn dry_run(&self) -> bool {
        self.inner.dry_run()
    }
    #[getter]
    fn itemize_changes(&self) -> bool {
        self.inner.itemize_changes()
    }
    #[getter]
    fn exclude(&self) -> Vec<String> {
        self.inner.exclude().to_vec()
    }
    #[getter]
    fn include(&self) -> Vec<String> {
        self.inner.include().to_vec()
    }
    #[getter]
    fn filter(&self) -> Vec<String> {
        self.inner.filter().to_vec()
    }
    #[getter]
    fn source(&self) -> Vec<String> {
        self.inner
            .source()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
    #[getter]
    fn dest(&self) -> Option<String> {
        self.inner.dest().map(|p| p.to_string_lossy().into_owned())
    }
    #[getter]
    fn bwlimit(&self) -> Option<u64> {
        self.inner.bwlimit()
    }
    #[getter]
    fn max_size(&self) -> Option<u64> {
        self.inner.max_size()
    }
    #[getter]
    fn min_size(&self) -> Option<u64> {
        self.inner.min_size()
    }
    #[getter]
    fn timeout(&self) -> Option<u64> {
        self.inner.timeout()
    }
    #[getter]
    fn link_dest(&self) -> Vec<String> {
        self.inner
            .link_dest()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
    #[getter]
    fn copy_dest(&self) -> Vec<String> {
        self.inner
            .copy_dest()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
    #[getter]
    fn compare_dest(&self) -> Vec<String> {
        self.inner
            .compare_dest()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
    #[getter]
    fn backup(&self) -> bool {
        self.inner.backup()
    }
    #[getter]
    fn backup_dir(&self) -> Option<String> {
        self.inner
            .backup_dir()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[getter]
    fn suffix(&self) -> String {
        self.inner.suffix().to_owned()
    }
    #[getter]
    fn partial(&self) -> bool {
        self.inner.partial()
    }
    #[getter]
    fn partial_dir(&self) -> Option<String> {
        self.inner
            .partial_dir()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[getter]
    fn relative(&self) -> bool {
        self.inner.relative()
    }
    #[getter]
    fn append(&self) -> bool {
        self.inner.append()
    }
    #[getter]
    fn files_from(&self) -> Option<String> {
        self.inner
            .files_from()
            .map(|p| p.to_string_lossy().into_owned())
    }
    #[getter]
    fn one_file_system(&self) -> bool {
        self.inner.one_file_system()
    }
    #[getter]
    fn numeric_ids(&self) -> bool {
        self.inner.numeric_ids()
    }
    #[getter]
    fn sparse(&self) -> bool {
        self.inner.sparse()
    }

    fn is_archive(&self) -> bool {
        self.inner.is_archive()
    }

    fn __repr__(&self) -> String {
        let sources: Vec<_> = self
            .inner
            .source()
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect();
        format!(
            "TransferOptions(source=[{}], dest={}, recursive={}, dry_run={})",
            sources.join(", "),
            self.inner
                .dest()
                .map(|p| format!("'{}'", p.display()))
                .unwrap_or_else(|| "None".to_string()),
            self.inner.recursive(),
            self.inner.dry_run(),
        )
    }
}

// ---------------------------------------------------------------------------
// SyncResult / TransferStats
// ---------------------------------------------------------------------------

/// Statistics from a completed transfer.
#[pyclass(module = "ferrosync._ferrosync", from_py_object)]
#[derive(Debug, Clone)]
pub struct SyncResult {
    stats: RustTransferStats,
}

#[pymethods]
impl SyncResult {
    #[getter]
    fn files_transferred(&self) -> u64 {
        self.stats.files_transferred
    }
    #[getter]
    fn total_files(&self) -> u64 {
        self.stats.total_files
    }
    #[getter]
    fn bytes_sent(&self) -> u64 {
        self.stats.bytes_sent
    }
    #[getter]
    fn bytes_received(&self) -> u64 {
        self.stats.bytes_received
    }
    #[getter]
    fn total_size(&self) -> u64 {
        self.stats.total_size
    }
    #[getter]
    fn matched_data(&self) -> u64 {
        self.stats.matched_data
    }
    #[getter]
    fn literal_data(&self) -> u64 {
        self.stats.literal_data
    }
    #[getter]
    fn files_skipped(&self) -> u64 {
        self.stats.files_skipped
    }
    #[getter]
    fn files_deleted(&self) -> u64 {
        self.stats.files_deleted
    }
    #[getter]
    fn symlinks(&self) -> u64 {
        self.stats.symlinks
    }
    #[getter]
    fn directories_created(&self) -> u64 {
        self.stats.directories_created
    }
    #[getter]
    fn elapsed_secs(&self) -> f64 {
        self.stats.elapsed.as_secs_f64()
    }
    #[getter]
    fn transfer_rate(&self) -> f64 {
        self.stats.transfer_rate()
    }
    #[getter]
    fn speedup(&self) -> f64 {
        self.stats.speedup()
    }

    fn __repr__(&self) -> String {
        format!(
            "SyncResult(files_transferred={}, files_skipped={}, bytes_sent={}, elapsed={:.3}s)",
            self.stats.files_transferred,
            self.stats.files_skipped,
            self.stats.bytes_sent,
            self.stats.elapsed.as_secs_f64(),
        )
    }
}

// ---------------------------------------------------------------------------
// PyFileEntry
// ---------------------------------------------------------------------------

/// Read-only file entry metadata.
#[pyclass(name = "FileEntry", module = "ferrosync._ferrosync", from_py_object)]
#[derive(Debug, Clone)]
pub struct PyFileEntry {
    inner: FileEntry,
}

#[pymethods]
impl PyFileEntry {
    #[getter]
    fn name(&self) -> String {
        String::from_utf8_lossy(&self.inner.name).into_owned()
    }
    #[getter]
    fn name_bytes(&self) -> Vec<u8> {
        self.inner.name.clone()
    }
    #[getter]
    fn size(&self) -> i64 {
        self.inner.len.bytes()
    }
    #[getter]
    fn mtime(&self) -> i64 {
        self.inner.mtime.secs()
    }
    #[getter]
    fn mtime_nsec(&self) -> u32 {
        self.inner.mtime_nsec
    }
    #[getter]
    fn mode(&self) -> u32 {
        self.inner.mode
    }
    #[getter]
    fn uid(&self) -> u32 {
        self.inner.uid
    }
    #[getter]
    fn gid(&self) -> u32 {
        self.inner.gid
    }
    #[getter]
    fn is_file(&self) -> bool {
        self.inner.is_file()
    }
    #[getter]
    fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }
    #[getter]
    fn is_symlink(&self) -> bool {
        self.inner.is_symlink()
    }
    #[getter]
    fn is_device(&self) -> bool {
        self.inner.is_device()
    }
    #[getter]
    fn link_target(&self) -> Option<String> {
        if self.inner.link_target.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&self.inner.link_target).into_owned())
        }
    }

    fn __repr__(&self) -> String {
        let kind = if self.inner.is_file() {
            "file"
        } else if self.inner.is_dir() {
            "dir"
        } else if self.inner.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        format!(
            "FileEntry(name='{}', type={}, size={}, mode={:#o})",
            String::from_utf8_lossy(&self.inner.name),
            kind,
            self.inner.len,
            self.inner.mode,
        )
    }
}

// ---------------------------------------------------------------------------
// Progress callback bridge
// ---------------------------------------------------------------------------

/// Convert a ProgressEvent to a Python dict for the callback.
fn event_to_pydict(py: Python<'_>, event: &ProgressEvent) -> Py<PyAny> {
    let dict = PyDict::new(py);
    match event {
        ProgressEvent::FileStart { index, name, size } => {
            let _ = dict.set_item("type", "file_start");
            let _ = dict.set_item("index", *index);
            let _ = dict.set_item("name", name.to_string_lossy().as_ref());
            let _ = dict.set_item("size", *size);
        }
        ProgressEvent::FileComplete {
            index,
            name,
            literal_bytes,
            matched_bytes,
        } => {
            let _ = dict.set_item("type", "file_complete");
            let _ = dict.set_item("index", *index);
            let _ = dict.set_item("name", name.to_string_lossy().as_ref());
            let _ = dict.set_item("literal_bytes", *literal_bytes);
            let _ = dict.set_item("matched_bytes", *matched_bytes);
        }
        ProgressEvent::FileSkipped { index, name } => {
            let _ = dict.set_item("type", "file_skipped");
            let _ = dict.set_item("index", *index);
            let _ = dict.set_item("name", name.to_string_lossy().as_ref());
        }
        ProgressEvent::FileDeleted { name } => {
            let _ = dict.set_item("type", "file_deleted");
            let _ = dict.set_item("name", name.to_string_lossy().as_ref());
        }
        ProgressEvent::FileItemized {
            index,
            name,
            changes,
        } => {
            let _ = dict.set_item("type", "file_itemized");
            let _ = dict.set_item("index", *index);
            let _ = dict.set_item("name", name.to_string_lossy().as_ref());
            let _ = dict.set_item("changes", changes.to_string());
        }
        ProgressEvent::OverallProgress {
            files_done,
            files_total,
            bytes_transferred,
            bytes_total,
        } => {
            let _ = dict.set_item("type", "overall_progress");
            let _ = dict.set_item("files_done", *files_done);
            let _ = dict.set_item("files_total", *files_total);
            let _ = dict.set_item("bytes_transferred", *bytes_transferred);
            let _ = dict.set_item("bytes_total", *bytes_total);
        }
    }
    dict.into_any().unbind()
}

fn make_progress_callback(py_callback: Py<PyAny>) -> ProgressCallback {
    Box::new(move |event: &ProgressEvent| {
        Python::attach(|py| {
            let py_event = event_to_pydict(py, event);
            if let Err(e) = py_callback.call1(py, (py_event,)) {
                e.write_unraisable(py, Some(py_callback.bind(py)));
            }
        });
    })
}

// ---------------------------------------------------------------------------
// sync_files()
// ---------------------------------------------------------------------------

/// Synchronize files from source(s) to destination.
///
/// This is the main entry point for performing an rsync-style transfer.
///
/// Args:
///     options: Transfer options controlling the sync behavior.
///     progress_callback: Optional callable receiving progress event dicts.
///         Each dict has a ``"type"`` key (``"file_start"``, ``"file_complete"``,
///         ``"file_skipped"``, ``"file_progress"``, ``"file_deleted"``,
///         ``"overall_progress"``) and event-specific fields.
///     checksum_seed: Checksum seed for block matching (default: 0).
///     checksum_type: Checksum algorithm (default: ``ChecksumType.Md5``).
///
/// Returns:
///     SyncResult with transfer statistics.
///
/// Raises:
///     FerrosyncError: On any transfer failure.
///     ProtocolError: On protocol-level errors.
///     FilesystemError: On filesystem I/O errors.
///     FilterError: On invalid filter rules.
#[pyfunction]
#[pyo3(signature = (
    options,
    *,
    progress_callback = None,
    checksum_seed = 0,
    checksum_type = ChecksumType::Md5,
))]
fn sync_files(
    py: Python<'_>,
    options: &TransferOptions,
    progress_callback: Option<Py<PyAny>>,
    checksum_seed: i32,
    checksum_type: ChecksumType,
) -> PyResult<SyncResult> {
    let rust_opts = options.inner.clone();
    let rust_checksum = RustChecksumType::from(checksum_type);

    let callback = progress_callback.map(make_progress_callback);

    // Release the GIL while running the transfer.
    py.detach(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| FilesystemError::new_err(format!("failed to create runtime: {e}")))?;

        rt.block_on(async {
            #[cfg(unix)]
            let fs = ferrosync_core::fs::unix::UnixFileSystem::new();
            #[cfg(windows)]
            let fs = ferrosync_core::fs::windows::WindowsFileSystem::new();
            let mut progress = match callback {
                Some(cb) => ProgressTracker::with_callback(cb),
                None => ProgressTracker::new(),
            };

            let ctx = ferrosync_core::delta::ProtocolContext {
                seed: checksum_seed,
                checksum_type: rust_checksum,
                char_offset: 0,
                proper_seed_order: true,
                block_size_override: None,
            };
            let result = transfer::execute_transfer(&fs, &rust_opts, &ctx, &mut progress)
                .await
                .map_err(to_py_err)?;

            Ok(SyncResult {
                stats: result.stats,
            })
        })
    })
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

/// ferrosync Python bindings.
#[pymodule]
fn _ferrosync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Exception classes.
    m.add("FerrosyncError", m.py().get_type::<FerrosyncError>())?;
    m.add("ProtocolError", m.py().get_type::<ProtocolError>())?;
    m.add("TransportError", m.py().get_type::<TransportError>())?;
    m.add("FilesystemError", m.py().get_type::<FilesystemError>())?;
    m.add("FilterError", m.py().get_type::<FilterError>())?;
    m.add(
        "ChecksumMismatchError",
        m.py().get_type::<ChecksumMismatchError>(),
    )?;

    // Enum classes.
    m.add_class::<DeleteMode>()?;
    m.add_class::<Verbosity>()?;
    m.add_class::<ChecksumType>()?;

    // Data classes.
    m.add_class::<TransferOptions>()?;
    m.add_class::<SyncResult>()?;
    m.add_class::<PyFileEntry>()?;

    // Functions.
    m.add_function(wrap_pyfunction!(sync_files, m)?)?;

    Ok(())
}
