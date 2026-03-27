//! Shared atomic file writer used by both Unix and Windows filesystem
//! implementations.
//!
//! Writes go to a temporary file, which is atomically renamed to the
//! destination on successful completion. If the writer is dropped without
//! a successful finish, the temporary file is removed as a best-effort
//! cleanup.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counter for generating unique temp file names.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique temp file name to avoid collisions from concurrent writes.
pub(crate) fn unique_tmp_name(suffix: &str) -> String {
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".ferrosync.{}.{}{}.tmp", std::process::id(), seq, suffix)
}

/// Platform-specific permission-setting function type.
///
/// Called with the file path and the Unix-style mode value. Each platform
/// translates the mode into the appropriate permission model (e.g., Unix
/// uses `PermissionsExt::from_mode`, Windows maps to read-only).
type SetPermissionsFn = fn(&std::path::Path, u32) -> io::Result<()>;

/// Writer that writes to a temp file and atomically renames on close.
///
/// Shared between Unix and Windows implementations. The only
/// platform-specific behavior is how file permissions are applied,
/// which is injected via a function pointer at construction time.
pub(crate) struct AtomicFileWriter {
    inner: BufWriter<fs::File>,
    tmp_path: PathBuf,
    dest_path: PathBuf,
    mode: Option<u32>,
    set_permissions: SetPermissionsFn,
    finished: bool,
}

impl AtomicFileWriter {
    /// Create a new `AtomicFileWriter`.
    ///
    /// - `file`: the already-created temp file to write into
    /// - `tmp_path`: path of the temp file
    /// - `dest_path`: final destination path (renamed to on finish)
    /// - `mode`: optional Unix-style permission mode
    /// - `set_permissions`: platform-specific function to apply permissions
    pub(crate) fn new(
        file: fs::File,
        tmp_path: PathBuf,
        dest_path: PathBuf,
        mode: Option<u32>,
        set_permissions: SetPermissionsFn,
    ) -> Self {
        Self {
            inner: BufWriter::new(file),
            tmp_path,
            dest_path,
            mode,
            set_permissions,
            finished: false,
        }
    }

    fn finish_inner(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.inner.flush()?;

        if let Some(m) = self.mode {
            (self.set_permissions)(&self.tmp_path, m)?;
        }

        fs::rename(&self.tmp_path, &self.dest_path)?;
        Ok(())
    }
}

impl Write for AtomicFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for AtomicFileWriter {
    fn drop(&mut self) {
        if self.finish_inner().is_err() {
            // Best-effort cleanup of temp file on failure.
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}
