//! Unified wire-level sender/receiver loops.
//!
//! Shared protocol mechanics for both client (SyncSession) and server
//! (ServerSession) sides. The loops are parameterized by traits that
//! abstract away the differences in file I/O between the two sides.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::delta::{checksum, matcher, sum, token};
use crate::engine::progress::{ProgressEvent, ProgressTracker};
use crate::engine::receiver;
use crate::error::ProtocolError;
use crate::filelist::entry::{FileEntry, S_IFMT, S_IFREG};
use crate::fs::FileSystem;
use crate::protocol::handshake::NegotiatedProtocol;
use crate::protocol::multiplex::MplexWriter;
use crate::protocol::varint;
use crate::stats::TransferStats;

type Result<T> = std::result::Result<T, WireError>;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from wire-level transfer loops.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Fs(#[from] crate::error::FsError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<crate::FerrosyncError> for WireError {
    fn from(e: crate::FerrosyncError) -> Self {
        match e {
            crate::FerrosyncError::Protocol(p) => WireError::Protocol(p),
            crate::FerrosyncError::Fs(f) => WireError::Fs(f),
            other => WireError::Protocol(ProtocolError::Handshake {
                message: other.to_string(),
            }),
        }
    }
}

impl From<WireError> for crate::FerrosyncError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Protocol(p) => crate::FerrosyncError::Protocol(p),
            WireError::Fs(f) => crate::FerrosyncError::Fs(f),
            WireError::Io(io) => crate::FerrosyncError::Protocol(ProtocolError::from(io)),
        }
    }
}

// ---------------------------------------------------------------------------
// FileReader trait (sender side)
// ---------------------------------------------------------------------------

/// Source file access abstraction for the sender loop.
///
/// Client push uses local filesystem + TransferOptions to locate source files.
/// Server send uses module path to locate files.
pub trait FileReader: Send + Sync {
    /// Read the source data for a file entry.
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<Vec<u8>, crate::error::FsError>;
}

/// Reads source files from local filesystem using TransferOptions paths.
pub struct LocalFileReader<'a> {
    fs: &'a dyn FileSystem,
    source_paths: &'a [PathBuf],
}

impl<'a> LocalFileReader<'a> {
    pub fn new(fs: &'a dyn FileSystem, source_paths: &'a [PathBuf]) -> Self {
        Self { fs, source_paths }
    }
}

impl FileReader for LocalFileReader<'_> {
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<Vec<u8>, crate::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        for source in self.source_paths {
            let path = if self.source_paths.len() == 1
                && self
                    .fs
                    .lstat(source)
                    .is_ok_and(|m| m.mode & S_IFMT == crate::filelist::entry::S_IFDIR)
            {
                source.join(name_str.as_ref())
            } else {
                source.clone()
            };
            if let Ok(data) = self.fs.read_file(&path) {
                return Ok(data);
            }
        }
        Ok(Vec::new())
    }
}

/// Reads source files from a module directory.
pub struct ModuleFileReader<'a> {
    fs: &'a dyn FileSystem,
    module_path: &'a Path,
}

impl<'a> ModuleFileReader<'a> {
    pub fn new(fs: &'a dyn FileSystem, module_path: &'a Path) -> Self {
        Self { fs, module_path }
    }
}

impl FileReader for ModuleFileReader<'_> {
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<Vec<u8>, crate::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        let path = self.module_path.join(name_str.as_ref());
        Ok(self.fs.read_file(&path).unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// FileOps trait (receiver side)
// ---------------------------------------------------------------------------

/// Receiver-side file operations abstraction.
///
/// Client pull uses local filesystem + TransferOptions for writing, metadata,
/// and skip decisions. Server receive uses module path.
pub trait FileOps: Send + Sync {
    /// Read the existing basis file at the destination (for delta).
    fn read_basis(&self, entry: &FileEntry) -> Vec<u8>;

    /// Write the reconstructed file data to the destination.
    fn write_file(
        &self,
        entry: &FileEntry,
        data: &[u8],
    ) -> std::result::Result<(), crate::FerrosyncError>;

    /// Set file metadata (times, ownership, permissions) after writing.
    fn set_metadata(&self, entry: &FileEntry);

    /// Create the destination directory for a directory entry.
    fn mkdir(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError>;

    /// Check if a file should be skipped (quick check).
    fn should_skip(&self, entry: &FileEntry) -> bool;

    /// Create parent directories for a file entry if needed.
    fn ensure_parent(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError>;

    /// Resolve the destination path for a file entry.
    fn dest_path(&self, entry: &FileEntry) -> PathBuf;
}

/// Receiver-side operations using local filesystem with TransferOptions.
pub struct LocalFileOps {
    fs: Arc<dyn FileSystem>,
    dest: PathBuf,
    options: crate::options::TransferOptions,
}

impl LocalFileOps {
    pub fn new(
        fs: Arc<dyn FileSystem>,
        dest: PathBuf,
        options: crate::options::TransferOptions,
    ) -> Self {
        Self { fs, dest, options }
    }
}

impl FileOps for LocalFileOps {
    fn read_basis(&self, entry: &FileEntry) -> Vec<u8> {
        let dest_path = self.dest_path(entry);
        self.fs.read_file(&dest_path).unwrap_or_default()
    }

    fn write_file(
        &self,
        entry: &FileEntry,
        data: &[u8],
    ) -> std::result::Result<(), crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);
        super::file_decision::write_file_with_options(
            &*self.fs, &dest_path, data, entry, &self.options,
        )
    }

    fn set_metadata(&self, entry: &FileEntry) {
        let dest_path = self.dest_path(entry);
        super::file_decision::set_file_metadata(&*self.fs, &dest_path, entry, &self.options);
    }

    fn mkdir(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError> {
        let dest_path = self.dest_path(entry);
        let mode = if self.options.preserve_perms() {
            entry.mode & 0o7777
        } else {
            0o755
        };
        self.fs.mkdir(&dest_path, mode)
    }

    fn should_skip(&self, entry: &FileEntry) -> bool {
        if self.options.dry_run() {
            return false; // handled separately
        }
        // Quick check: skip files that are already up-to-date.
        if self.options.preserve_times() && !self.options.checksum_mode() {
            let dest_path = self.dest_path(entry);
            if let Ok(dest_meta) = self.fs.lstat(&dest_path) {
                if dest_meta.len == entry.len && dest_meta.mtime == entry.mtime {
                    return true;
                }
            }
        }
        false
    }

    fn ensure_parent(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError> {
        let dest_path = self.dest_path(entry);
        if let Some(parent) = dest_path.parent() {
            if !self.fs.lexists(parent) {
                self.fs.mkdir(parent, 0o755)?;
            }
        }
        Ok(())
    }

    fn dest_path(&self, entry: &FileEntry) -> PathBuf {
        let name_str = String::from_utf8_lossy(&entry.name);
        self.dest.join(name_str.as_ref())
    }
}

/// Receiver-side operations using module directory (server side).
pub struct ModuleFileOps {
    fs: Arc<dyn FileSystem>,
    module_path: PathBuf,
}

impl ModuleFileOps {
    pub fn new(fs: Arc<dyn FileSystem>, module_path: PathBuf) -> Self {
        Self { fs, module_path }
    }
}

impl FileOps for ModuleFileOps {
    fn read_basis(&self, entry: &FileEntry) -> Vec<u8> {
        let dest_path = self.dest_path(entry);
        self.fs.read_file(&dest_path).unwrap_or_default()
    }

    fn write_file(
        &self,
        entry: &FileEntry,
        data: &[u8],
    ) -> std::result::Result<(), crate::FerrosyncError> {
        let dest_path = self.dest_path(entry);
        Ok(self.fs.write_file(&dest_path, data, None)?)
    }

    fn set_metadata(&self, _entry: &FileEntry) {
        // Server doesn't set metadata by default (no TransferOptions).
    }

    fn mkdir(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError> {
        let dest_path = self.dest_path(entry);
        self.fs.mkdir(&dest_path, 0o755)
    }

    fn should_skip(&self, _entry: &FileEntry) -> bool {
        false
    }

    fn ensure_parent(&self, entry: &FileEntry) -> std::result::Result<(), crate::error::FsError> {
        let dest_path = self.dest_path(entry);
        if let Some(parent) = dest_path.parent() {
            if !self.fs.lexists(parent) {
                self.fs.mkdir(parent, 0o755)?;
            }
        }
        Ok(())
    }

    fn dest_path(&self, entry: &FileEntry) -> PathBuf {
        let name_str = String::from_utf8_lossy(&entry.name);
        self.module_path.join(name_str.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Sender loop
// ---------------------------------------------------------------------------

/// Run the sender loop: read NDX requests from the generator, match blocks,
/// and send delta data.
///
/// Used by both client push (run_push) and server send (handle_send_impl).
#[allow(clippy::too_many_arguments)]
pub async fn sender_loop<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    entries: &[FileEntry],
    ndx_map: &HashMap<i32, usize>,
    file_reader: &dyn FileReader,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let seed = protocol.seed;
    let checksum_type = protocol.checksum;
    let proto_ver = protocol.version;

    let mut gen_ndx_state = varint::NdxState::default();
    let mut send_ndx_state = varint::NdxState::default();
    let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
    let mut phase: u32 = 0;

    loop {
        let ndx = varint::read_ndx(demux_read, &mut gen_ndx_state, proto_ver).await?;

        if ndx == varint::NDX_DONE {
            phase += 1;
            if phase > max_phase {
                break;
            }
            // Respond with NDX_DONE (phase transition).
            let mut done_buf = Vec::new();
            varint::write_ndx(
                &mut done_buf,
                varint::NDX_DONE,
                &mut send_ndx_state,
                proto_ver,
            )
            .await?;
            mplex_out.write_data(&done_buf).await?;
            mplex_out.flush().await?;
            continue;
        }

        // NDX_FLIST_EOF (-2) or NDX_DEL_STATS (-3): skip.
        if ndx < -1 {
            continue;
        }

        // Read iflags from generator (proto >= 29).
        let mut iflags: u16 = 0;
        if proto_ver >= 29 {
            let mut iflags_buf = [0u8; 2];
            demux_read.read_exact(&mut iflags_buf).await?;
            iflags = u16::from_le_bytes(iflags_buf);

            // ITEM_BASIS_TYPE_FOLLOWS (1<<11 = 0x0800)
            if iflags & 0x0800 != 0 {
                let mut bt = [0u8; 1];
                demux_read.read_exact(&mut bt).await?;
            }
            // ITEM_XNAME_FOLLOWS (1<<12 = 0x1000)
            if iflags & 0x1000 != 0 {
                let name_len = varint::read_varint(demux_read).await?;
                if name_len > 0x10000 {
                    return Err(WireError::Protocol(ProtocolError::WireValueOutOfRange {
                        field: "xname_len",
                        value: name_len as i64,
                        max: 0x10000,
                    }));
                }
                let mut name_buf = vec![0u8; name_len as usize];
                demux_read.read_exact(&mut name_buf).await?;
            }
        }

        // Look up the entry for this NDX.
        let entry_idx = match ndx_map.get(&ndx) {
            Some(&idx) => idx,
            None => {
                tracing::warn!(ndx, "generator requested unknown NDX, skipping");
                continue;
            }
        };
        let entry = &entries[entry_idx];

        // Non-regular files don't have file data.
        if entry.mode & S_IFMT != S_IFREG {
            continue;
        }

        // Read block signatures from generator.
        let sums = sum::read_sums(demux_read).await?;

        progress.emit(ProgressEvent::FileStart {
            index: ndx,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            size: entry.len,
        });

        // Read local source data.
        let source_data = file_reader.read_file(entry)?;

        // Match blocks and compute delta.
        let ops = matcher::match_blocks(
            &source_data,
            &sums,
            seed,
            checksum_type,
            checksum::CHAR_OFFSET_V30,
            protocol.proper_seed_order,
        );

        // Stream sender response: NDX + iflags + sum_head (small header),
        // then tokens individually, then file checksum.
        // Each piece goes to the wire as its own MUX frame(s), avoiding
        // an O(file_size) intermediate buffer.

        // 1. Small header: NDX + iflags + sum_head (~20 bytes).
        let mut hdr = Vec::with_capacity(64);
        varint::write_ndx(&mut hdr, ndx, &mut send_ndx_state, proto_ver).await?;
        if proto_ver >= 29 {
            varint::write_shortint(&mut hdr, iflags).await?;
        }
        let resp_sum_head = if sums.head.count == 0 {
            sum::SumHead {
                count: 0,
                blength: 0,
                s2length: 0,
                remainder: 0,
            }
        } else {
            sum::SumHead {
                count: sums.head.count,
                blength: sums.head.blength,
                s2length: sums.head.s2length,
                remainder: sums.head.remainder,
            }
        };
        sum::write_sum_head(&mut hdr, &resp_sum_head).await?;
        mplex_out.write_data(&hdr).await?;

        // 2. Stream delta tokens directly to the wire.
        let mut literal_bytes = 0u64;
        let mut matched_bytes = 0u64;
        for op in &ops {
            match op {
                matcher::MatchOp::Data(data) => {
                    let mut tok_buf = Vec::with_capacity(data.len() + 4);
                    token::send_data(&mut tok_buf, data).await?;
                    mplex_out.write_data(&tok_buf).await?;
                    literal_bytes += data.len() as u64;
                }
                matcher::MatchOp::BlockMatch(block_idx) => {
                    let mut tok_buf = Vec::with_capacity(8);
                    token::send_block_match(&mut tok_buf, *block_idx).await?;
                    mplex_out.write_data(&tok_buf).await?;
                    if sums.head.blength > 0 {
                        matched_bytes += sums.head.blength as u64;
                    }
                }
            }
        }
        let mut eof_buf = Vec::with_capacity(8);
        token::send_eof(&mut eof_buf).await?;
        mplex_out.write_data(&eof_buf).await?;

        // 3. File-level checksum.
        let file_sum = checksum::file_checksum(&source_data, seed, checksum_type);
        mplex_out.write_data(&file_sum).await?;
        mplex_out.flush().await?;

        stats.files_transferred += 1;
        stats.total_size += entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.matched_data += matched_bytes;
        stats.bytes_sent += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: ndx,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            literal_bytes,
            matched_bytes,
        });
    }

    // Post-loop: write final NDX_DONE.
    let mut done_buf = Vec::new();
    varint::write_ndx(
        &mut done_buf,
        varint::NDX_DONE,
        &mut send_ndx_state,
        proto_ver,
    )
    .await?;
    mplex_out.write_data(&done_buf).await?;
    mplex_out.flush().await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Receiver loop
// ---------------------------------------------------------------------------

/// Run the receiver loop: send block signatures to the sender, read delta
/// data, and reconstruct files.
///
/// Used by both client pull (run_pull) and server receive (handle_receive_impl).
#[allow(clippy::too_many_arguments)]
pub async fn receiver_loop<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    entries: &[FileEntry],
    entry_ndx: &[i32],
    file_ops: &dyn FileOps,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let seed = protocol.seed;
    let checksum_type = protocol.checksum;
    let proto_ver = protocol.version;

    let mut gen_ndx_state = varint::NdxState::default();
    let mut recv_ndx_state = varint::NdxState::default();

    // Create directories first.
    for entry in entries {
        if !entry.is_dir() {
            continue;
        }
        file_ops.mkdir(entry)?;
        stats.directories_created += 1;
    }

    // Per-file receiver loop.
    for (idx, entry) in entries.iter().enumerate() {
        if !entry.is_file() {
            continue;
        }

        progress.emit(ProgressEvent::FileStart {
            index: idx as i32,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            size: entry.len,
        });

        // Ensure parent directories exist.
        file_ops.ensure_parent(entry)?;

        // Quick check: skip files that are already up-to-date.
        if file_ops.should_skip(entry) {
            continue;
        }

        // Read existing basis file (if any).
        let basis_data = file_ops.read_basis(entry);

        // Send generator output: NDX + iflags + sum_head + block sigs.
        let file_ndx = entry_ndx[idx];
        let mut sig_buf = Vec::new();
        varint::write_ndx(&mut sig_buf, file_ndx, &mut gen_ndx_state, proto_ver).await?;
        // iflags: ITEM_TRANSFER (1<<15) signals data transfer needed.
        if proto_ver >= 29 {
            const ITEM_TRANSFER: u16 = 1 << 15;
            varint::write_shortint(&mut sig_buf, ITEM_TRANSFER).await?;
        }
        let sigs = sum::compute_signatures(
            &basis_data,
            seed,
            checksum_type,
            checksum::CHAR_OFFSET_V30,
            protocol.proper_seed_order,
        );
        sum::write_sums(&mut sig_buf, &sigs).await?;
        mplex_out.write_data(&sig_buf).await?;
        mplex_out.flush().await?;

        // Read sender's response.
        let _file_ndx = varint::read_ndx(demux_read, &mut recv_ndx_state, proto_ver).await?;

        // Read iflags (protocol >= 29).
        if proto_ver >= 29 {
            let mut iflags_buf = [0u8; 2];
            demux_read.read_exact(&mut iflags_buf).await?;
            let iflags = u16::from_le_bytes(iflags_buf);

            if iflags & 0x0800 != 0 {
                let mut bt = [0u8; 1];
                demux_read.read_exact(&mut bt).await?;
            }
            if iflags & 0x1000 != 0 {
                let name_len = varint::read_varint(demux_read).await?;
                if name_len > 0x10000 {
                    return Err(WireError::Protocol(ProtocolError::WireValueOutOfRange {
                        field: "xname_len",
                        value: name_len as i64,
                        max: 0x10000,
                    }));
                }
                let mut name_buf = vec![0u8; name_len as usize];
                demux_read.read_exact(&mut name_buf).await?;
            }
        }

        // Read sum_head from sender.
        let sum_head = sum::read_sum_head(demux_read).await?;
        let blength = if sum_head.blength > 0 {
            sum_head.blength as usize
        } else {
            700
        };

        // Read tokens, reconstruct file via streaming writer, verify checksum.
        let mut output = Vec::new();
        let bytes_written = receiver::recv_file_delta_to_writer(
            demux_read,
            &basis_data,
            blength,
            seed,
            checksum_type,
            &mut output,
        )
        .await?;

        let literal_bytes = bytes_written;

        // Write reconstructed file.
        file_ops.write_file(entry, &output)?;

        // Set metadata.
        file_ops.set_metadata(entry);

        stats.files_transferred += 1;
        stats.total_size += entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.bytes_received += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: idx as i32,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            literal_bytes,
            matched_bytes: 0,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pipelined receiver loop
// ---------------------------------------------------------------------------

/// Message from the generator task to the receiver task.
enum GeneratorItem {
    /// A file is being requested from the sender.
    File {
        entry_idx: usize,
        basis_data: Vec<u8>,
        blength: usize,
    },
    /// All phases are complete.
    Done,
}

/// Run the receiver loop with pipelined generator/receiver tasks.
///
/// The generator task sends block signatures to the remote sender while
/// the receiver task concurrently processes delta responses. This allows
/// the generator to request file N+1 while the receiver is still
/// reconstructing file N, matching rsync's 3-process architecture.
///
/// The `mplex_out` writer is owned exclusively by the generator task.
/// The `demux_read` reader is owned exclusively by the receiver task.
/// A bounded mpsc channel carries [`GeneratorItem`] messages from the
/// generator to the receiver so it knows which file to expect next.
#[allow(clippy::too_many_arguments)]
pub async fn receiver_loop_pipelined<R, W>(
    demux_read: R,
    mplex_out: MplexWriter<W>,
    entries: &[FileEntry],
    entry_ndx: &[i32],
    file_ops: Arc<dyn FileOps>,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
) -> Result<(R, MplexWriter<W>)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let seed = protocol.seed;
    let checksum_type = protocol.checksum;
    let proto_ver = protocol.version;
    let proper_seed_order = protocol.proper_seed_order;

    // Create directories first (same as sequential loop).
    for entry in entries {
        if !entry.is_dir() {
            continue;
        }
        file_ops.mkdir(entry)?;
        stats.directories_created += 1;
    }

    // Pre-compute file items: (entry_idx, file_ndx, entry_clone).
    // We clone entries that need transferring so they can be moved
    // into the spawned tasks.
    let mut file_items: Vec<(usize, i32, FileEntry)> = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        if !entry.is_file() {
            continue;
        }
        if file_ops.should_skip(entry) {
            continue;
        }
        file_ops.ensure_parent(entry)?;
        file_items.push((idx, entry_ndx[idx], entry.clone()));
    }

    // Bounded channel: generator -> receiver. Capacity of 4 provides
    // enough pipelining without unbounded memory growth.
    let (gen_tx, mut gen_rx) = tokio::sync::mpsc::channel::<GeneratorItem>(4);

    // Clone data needed by the generator task.
    let gen_file_items = file_items.clone();
    let gen_file_ops = Arc::clone(&file_ops);

    // --- Generator task ---
    // Owns mplex_out exclusively. Reads basis files, computes signatures,
    // sends them to the wire, and tells the receiver what's coming.
    let generator_handle = tokio::spawn(async move {
        let mut mplex_out = mplex_out;
        let mut gen_ndx_state = varint::NdxState::default();

        for (idx, file_ndx, entry) in &gen_file_items {
            // Read existing basis file for delta computation.
            let basis_data = gen_file_ops.read_basis(entry);

            // Compute block signatures.
            let sigs = sum::compute_signatures(
                &basis_data,
                seed,
                checksum_type,
                checksum::CHAR_OFFSET_V30,
                proper_seed_order,
            );

            let blength = if sigs.head.blength > 0 {
                sigs.head.blength as usize
            } else {
                700
            };

            // Send generator output to wire: NDX + iflags + sum_head + block sigs.
            let mut sig_buf = Vec::new();
            varint::write_ndx(&mut sig_buf, *file_ndx, &mut gen_ndx_state, proto_ver).await?;
            if proto_ver >= 29 {
                const ITEM_TRANSFER: u16 = 1 << 15;
                varint::write_shortint(&mut sig_buf, ITEM_TRANSFER).await?;
            }
            sum::write_sums(&mut sig_buf, &sigs).await?;
            mplex_out.write_data(&sig_buf).await?;
            mplex_out.flush().await?;

            // Tell receiver task what file to expect.
            let item = GeneratorItem::File {
                entry_idx: *idx,
                basis_data,
                blength,
            };
            if gen_tx.send(item).await.is_err() {
                // Receiver dropped -- it hit an error.
                break;
            }
        }

        // Signal completion.
        let _ = gen_tx.send(GeneratorItem::Done).await;

        Ok::<MplexWriter<W>, WireError>(mplex_out)
    });

    // --- Receiver task (runs on current task) ---
    // Owns demux_read exclusively. Reads GeneratorItems from the channel,
    // then reads the sender's delta response from the wire.
    let mut demux_read = demux_read;
    let mut recv_ndx_state = varint::NdxState::default();

    while let Some(item) = gen_rx.recv().await {
        match item {
            GeneratorItem::File {
                entry_idx,
                basis_data,
                blength,
            } => {
                let entry = &entries[entry_idx];

                progress.emit(ProgressEvent::FileStart {
                    index: entry_idx as i32,
                    name: crate::engine::progress::name_to_pathbuf(&entry.name),
                    size: entry.len,
                });

                // Read sender's response NDX.
                let _file_ndx =
                    varint::read_ndx(&mut demux_read, &mut recv_ndx_state, proto_ver).await?;

                // Read iflags (protocol >= 29).
                if proto_ver >= 29 {
                    let mut iflags_buf = [0u8; 2];
                    demux_read.read_exact(&mut iflags_buf).await?;
                    let iflags = u16::from_le_bytes(iflags_buf);

                    if iflags & 0x0800 != 0 {
                        let mut bt = [0u8; 1];
                        demux_read.read_exact(&mut bt).await?;
                    }
                    if iflags & 0x1000 != 0 {
                        let name_len = varint::read_varint(&mut demux_read).await?;
                        if name_len > 0x10000 {
                            return Err(WireError::Protocol(
                                ProtocolError::WireValueOutOfRange {
                                    field: "xname_len",
                                    value: name_len as i64,
                                    max: 0x10000,
                                },
                            ));
                        }
                        let mut name_buf = vec![0u8; name_len as usize];
                        demux_read.read_exact(&mut name_buf).await?;
                    }
                }

                // Read sum_head from sender.
                let sum_head = sum::read_sum_head(&mut demux_read).await?;
                let blength_actual = if sum_head.blength > 0 {
                    sum_head.blength as usize
                } else {
                    blength
                };

                // Reconstruct file via streaming writer.
                let mut output = Vec::new();
                let bytes_written = receiver::recv_file_delta_to_writer(
                    &mut demux_read,
                    &basis_data,
                    blength_actual,
                    seed,
                    checksum_type,
                    &mut output,
                )
                .await?;

                let literal_bytes = bytes_written;

                // Write reconstructed file.
                file_ops.write_file(entry, &output)?;
                file_ops.set_metadata(entry);

                stats.files_transferred += 1;
                stats.total_size += entry.len as u64;
                stats.literal_data += literal_bytes;
                stats.bytes_received += literal_bytes;

                progress.emit(ProgressEvent::FileComplete {
                    index: entry_idx as i32,
                    name: crate::engine::progress::name_to_pathbuf(&entry.name),
                    literal_bytes,
                    matched_bytes: 0,
                });
            }
            GeneratorItem::Done => break,
        }
    }

    // Wait for generator task to complete and recover mplex_out.
    // We need mplex_out back for the phase exchange that follows.
    let mplex_out = generator_handle.await.map_err(|e| {
        WireError::Protocol(ProtocolError::Handshake {
            message: format!("generator task panicked: {e}"),
        })
    })??;

    Ok((demux_read, mplex_out))
}

// ---------------------------------------------------------------------------
// Shared protocol helpers
// ---------------------------------------------------------------------------

/// Build the NDX-to-entry-index mapping.
pub fn build_ndx_map(
    entries: &[FileEntry],
    protocol: &NegotiatedProtocol,
    is_recursive: bool,
) -> HashMap<i32, usize> {
    let ndx_start: i32 =
        if protocol.incremental_flist && protocol.version >= 30 && is_recursive {
            1
        } else {
            0
        };
    entries
        .iter()
        .enumerate()
        .map(|(i, _)| (ndx_start + i as i32, i))
        .collect()
}

/// Write transfer stats (5 varlong30 values).
pub async fn write_stats<W: AsyncWrite + Unpin + Send>(
    mplex_out: &mut MplexWriter<W>,
    stats: &TransferStats,
    proto_ver: u8,
) -> Result<()> {
    let mut stats_buf = Vec::new();
    varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
    varint::write_varlong30(&mut stats_buf, stats.bytes_sent as i64, 3, proto_ver).await?;
    varint::write_varlong30(&mut stats_buf, stats.total_size as i64, 3, proto_ver).await?;
    if proto_ver >= 29 {
        varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
        varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
    }
    mplex_out.write_data(&stats_buf).await?;
    mplex_out.flush().await?;
    Ok(())
}

/// Read transfer stats from the sender.
pub async fn read_stats<R: AsyncRead + Unpin + Send>(
    demux_read: &mut R,
    proto_ver: u8,
) -> Result<()> {
    let _total_read = varint::read_varlong30(demux_read, 3, proto_ver).await?;
    let _total_written = varint::read_varlong30(demux_read, 3, proto_ver).await?;
    let _total_size = varint::read_varlong30(demux_read, 3, proto_ver).await?;
    if proto_ver >= 29 {
        let _flist_buildtime = varint::read_varlong30(demux_read, 3, proto_ver).await?;
        let _flist_xfertime = varint::read_varlong30(demux_read, 3, proto_ver).await?;
    }
    Ok(())
}

/// Sender goodbye exchange (proto >= 24).
///
/// C ref: read_final_goodbye (main.c:875-905)
///
/// For proto >= 31, the receiver sends an NDX_DONE, the sender must
/// acknowledge with its own NDX_DONE, then read one more NDX_DONE
/// (error-exit sync). For proto 24-30, just read the final NDX_DONE.
pub async fn sender_goodbye<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    if proto_ver >= 24 {
        let mut read_state = varint::NdxState::default();
        let mut write_state = varint::NdxState::default();

        if proto_ver >= 31 {
            // Read first goodbye NDX_DONE from receiver.
            let _ = varint::read_ndx(demux_read, &mut read_state, proto_ver).await;

            // Acknowledge with our own NDX_DONE.
            write_goodbye_done(mplex_out, &mut write_state, proto_ver).await;

            // Read error-exit sync NDX_DONE.
            let _ = varint::read_ndx(demux_read, &mut read_state, proto_ver).await;
        } else {
            // Proto 24-30: just read the final NDX_DONE.
            let _ = varint::read_ndx(demux_read, &mut read_state, proto_ver).await;
        }
    }
    Ok(())
}

/// Receiver-side phase exchange.
///
/// Sends NDX_DONEs for each phase, reads sender responses.
pub async fn receiver_phase_exchange<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
    num_flists: usize,
    incremental_flist: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
    let flist_cleanup_rounds: u32 = if incremental_flist && proto_ver >= 30 {
        (num_flists as u32).saturating_sub(1)
    } else {
        0
    };
    let total_ndx_rounds = flist_cleanup_rounds + max_phase + 1;

    let mut gen_ndx_state = varint::NdxState::default();
    let mut recv_ndx_state = varint::NdxState::default();

    for _round in 0..total_ndx_rounds {
        let mut done_buf = Vec::new();
        varint::write_ndx(
            &mut done_buf,
            varint::NDX_DONE,
            &mut gen_ndx_state,
            proto_ver,
        )
        .await?;
        mplex_out.write_data(&done_buf).await?;
        mplex_out.flush().await?;

        // Read sender's NDX_DONE response.
        let resp = varint::read_ndx(demux_read, &mut recv_ndx_state, proto_ver).await?;
        if resp != varint::NDX_DONE {
            tracing::warn!(
                ndx = resp,
                "expected NDX_DONE from sender during phase exchange"
            );
        }
    }

    Ok(())
}

/// Write a best-effort NDX_DONE to the MUX output.
///
/// Used during goodbye exchanges where the remote may have already
/// disconnected. Errors are silently ignored.
async fn write_goodbye_done<W: AsyncWrite + Unpin>(
    out: &mut MplexWriter<W>,
    st: &mut varint::NdxState,
    pv: u8,
) {
    let mut buf = Vec::new();
    let _ = varint::write_ndx(&mut buf, varint::NDX_DONE, st, pv).await;
    let _ = out.write_data(&buf).await;
    let _ = out.flush().await;
}

/// Receiver goodbye exchange (proto >= 24).
///
/// Sends goodbye NDX_DONEs that the sender expects to read.
pub async fn receiver_goodbye<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    if proto_ver >= 24 {
        let mut gen_ndx_state = varint::NdxState::default();
        let mut recv_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut gen_ndx_state, proto_ver).await;
        let _ = varint::read_ndx(demux_read, &mut recv_ndx_state, proto_ver).await;
        write_goodbye_done(mplex_out, &mut gen_ndx_state, proto_ver).await;

        if proto_ver >= 31 {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, proto_ver).await;
        }
    }
    Ok(())
}

/// Server-side sender goodbye exchange (proto >= 24).
///
/// The server sender writes a goodbye NDX_DONE and reads goodbyes from
/// the receiver. Slightly different sequence from the client sender.
pub async fn server_sender_goodbye<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    if proto_ver >= 24 {
        let mut send_ndx_state = varint::NdxState::default();
        let mut gen_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut send_ndx_state, proto_ver).await;

        // Read goodbye NDX_DONEs from receiver (best-effort).
        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, proto_ver).await;
        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, proto_ver).await;
        if proto_ver >= 31 {
            let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, proto_ver).await;
        }
    }
    Ok(())
}

/// Server-side receiver phase exchange.
///
/// Slightly different from client: server sends (max_phase + 1) NDX_DONEs
/// and reads responses, then reads the sender's final NDX_DONE.
pub async fn server_receiver_phase_exchange<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
    let mut gen_ndx_state = varint::NdxState::default();
    let mut recv_ndx_state = varint::NdxState::default();

    // Send (max_phase + 1) NDX_DONEs to the sender.
    for phase in 0..=max_phase {
        let mut done_buf = Vec::new();
        varint::write_ndx(
            &mut done_buf,
            varint::NDX_DONE,
            &mut gen_ndx_state,
            proto_ver,
        )
        .await?;
        mplex_out.write_data(&done_buf).await?;
        mplex_out.flush().await?;

        // The sender responds with NDX_DONE for each phase except the last.
        if phase < max_phase {
            let resp = varint::read_ndx(demux_read, &mut recv_ndx_state, proto_ver).await?;
            if resp != varint::NDX_DONE {
                tracing::warn!(ndx = resp, phase, "expected NDX_DONE from sender");
            }
        }
    }

    // Read the sender's final NDX_DONE.
    let final_ndx = varint::read_ndx(demux_read, &mut recv_ndx_state, proto_ver).await?;
    if final_ndx != varint::NDX_DONE {
        tracing::warn!(ndx = final_ndx, "expected final NDX_DONE from sender");
    }

    Ok(())
}

/// Server-side receiver goodbye exchange (proto >= 24).
pub async fn server_receiver_goodbye<W: AsyncWrite + Unpin + Send>(
    mplex_out: &mut MplexWriter<W>,
    proto_ver: u8,
) -> Result<()> {
    if proto_ver >= 24 {
        let mut gen_ndx_state = varint::NdxState::default();
        write_goodbye_done(mplex_out, &mut gen_ndx_state, proto_ver).await;
        if proto_ver >= 31 {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, proto_ver).await;
        }
    }
    Ok(())
}
