//! Unified wire-level sender/receiver loops.
//!
//! Shared protocol mechanics for both client (SyncSession) and server
//! (ServerSession) sides. The loops are parameterized by traits that
//! abstract away the differences in file I/O between the two sides.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::delta::ops::DiffOp;
use crate::delta::token::TokenWriter;
use crate::delta::{checksum, matcher, sum, token, ProtocolContext};
use crate::engine::progress::{ProgressEvent, ProgressTracker};
use crate::engine::receiver;
use crate::error::ProtocolError;
use crate::filelist::entry::{FileEntry, S_IFMT, S_IFREG};
use crate::fs::{FileData, FileSystem};
use crate::protocol::compress::{Compressor, Decompressor};
use crate::protocol::handshake::{CompressType, NegotiatedProtocol};
use crate::protocol::multiplex::MplexWriter;
use crate::protocol::varint;
use crate::protocol::wire_format::IntCodec;
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
            // Transport and Filter errors should not occur in wire transfer
            // context; convert losslessly via the Display representation.
            crate::FerrosyncError::Transport(t) => WireError::Protocol(ProtocolError::Handshake {
                message: t.to_string(),
            }),
            crate::FerrosyncError::Filter(f) => WireError::Protocol(ProtocolError::Handshake {
                message: f.to_string(),
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
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<FileData, crate::error::FsError>;

    /// Open a streaming reader for a file entry.
    ///
    /// Returns a `Read` handle that reads the file without loading it
    /// entirely into memory. Used by the streaming sender for large files.
    fn open_stream(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn Read + Send>, crate::error::FsError> {
        // Default: fall back to read_file + Cursor.
        let data = self.read_file(entry)?;
        let vec: Vec<u8> = data.to_vec();
        Ok(Box::new(std::io::Cursor::new(vec)))
    }
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
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<FileData, crate::error::FsError> {
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
            if let Ok(data) = self.fs.map_file(&path) {
                return Ok(data);
            }
        }
        Ok(FileData::Empty)
    }

    fn open_stream(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn Read + Send>, crate::error::FsError> {
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
            if let Ok(reader) = self.fs.read_file_stream(&path) {
                return Ok(reader);
            }
        }
        // Empty file fallback
        Ok(Box::new(std::io::Cursor::new(Vec::new())))
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
    fn read_file(&self, entry: &FileEntry) -> std::result::Result<FileData, crate::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        let path = self.module_path.join(name_str.as_ref());
        Ok(self.fs.map_file(&path).unwrap_or_default())
    }

    fn open_stream(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn Read + Send>, crate::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        let path = self.module_path.join(name_str.as_ref());
        match self.fs.read_file_stream(&path) {
            Ok(reader) => Ok(reader),
            Err(_) => Ok(Box::new(std::io::Cursor::new(Vec::new()))),
        }
    }
}

// ---------------------------------------------------------------------------
// Polymorphic token writer (enum dispatch for sender loop)
// ---------------------------------------------------------------------------

/// Enum dispatch over plain and compressed token writers.
///
/// `TokenWriter` is not object-safe (generic async methods), so we use
/// enum dispatch to select the writer at runtime.
enum AnyTokenWriter {
    Plain(token::PlainTokenWriter),
    Compressed(token::CompressedTokenWriter),
}

impl AnyTokenWriter {
    async fn write_data<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        data: &[u8],
    ) -> std::result::Result<(), ProtocolError> {
        match self {
            Self::Plain(tw) => tw.write_data(w, data).await,
            Self::Compressed(tw) => tw.write_data(w, data).await,
        }
    }

    async fn write_block_match<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        index: i32,
    ) -> std::result::Result<(), ProtocolError> {
        match self {
            Self::Plain(tw) => tw.write_block_match(w, index).await,
            Self::Compressed(tw) => tw.write_block_match(w, index).await,
        }
    }

    async fn write_eof<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
    ) -> std::result::Result<(), ProtocolError> {
        match self {
            Self::Plain(tw) => tw.write_eof(w).await,
            Self::Compressed(tw) => tw.write_eof(w).await,
        }
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
    block_size_override: Option<i32>,
    dry_run: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = block_size_override;
    let int_codec = protocol.wire.int_codec;
    let wire = &protocol.wire;

    let mut gen_ndx_state = varint::NdxState::default();
    let mut send_ndx_state = varint::NdxState::default();
    let max_phase: u32 = wire.phase_count as u32;
    let mut phase: u32 = 0;

    loop {
        let ndx = varint::read_ndx(demux_read, &mut gen_ndx_state, int_codec).await?;

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
                int_codec,
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
        if wire.has_iflags {
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

        // If ITEM_TRANSFER is not set, the generator is just notifying us
        // about a file (e.g., a hardlink duplicate that was created without
        // data transfer, or a file that is already up-to-date). Echo the
        // NDX + iflags back to the receiver and continue without reading
        // signatures.
        const ITEM_TRANSFER: u16 = 1 << 15;
        if wire.has_iflags && (iflags & ITEM_TRANSFER) == 0 {
            let mut echo_buf = Vec::new();
            varint::write_ndx(&mut echo_buf, ndx, &mut send_ndx_state, int_codec).await?;
            varint::write_shortint(&mut echo_buf, iflags).await?;
            // ITEM_BASIS_TYPE_FOLLOWS
            if iflags & 0x0800 != 0 {
                echo_buf.push(0); // basis_type byte
            }
            // ITEM_XNAME_FOLLOWS
            if iflags & 0x1000 != 0 {
                varint::write_varint(&mut echo_buf, 0).await?; // empty xname
            }
            mplex_out.write_data(&echo_buf).await?;
            mplex_out.flush().await?;
            continue;
        }

        // Dry-run: remote generator sends NDX + iflags but skips sum_head
        // and block signatures (rsync generator.c: if (!do_xfers) goto cleanup).
        // Don't try to read sums -- just count the file and continue.
        if dry_run {
            stats.files_transferred += 1;
            stats.total_size += entry.len as u64;
            progress.emit(ProgressEvent::FileComplete {
                index: ndx,
                name: crate::engine::progress::name_to_pathbuf(&entry.name),
                literal_bytes: entry.len as u64,
                matched_bytes: 0,
            });
            continue;
        }

        // Read block signatures from generator.
        let sums = sum::read_sums(demux_read).await?;

        progress.emit(ProgressEvent::FileStart {
            index: ndx,
            name: crate::engine::progress::name_to_pathbuf(&entry.name),
            size: entry.len,
        });

        // Stream sender response: NDX + iflags + sum_head (small header),
        // then tokens individually, then file checksum.
        // Each piece goes to the wire as its own MUX frame(s), avoiding
        // an O(file_size) intermediate buffer.

        // 1. Small header: NDX + iflags + sum_head (~20 bytes).
        let mut hdr = Vec::with_capacity(64);
        varint::write_ndx(&mut hdr, ndx, &mut send_ndx_state, int_codec).await?;
        if wire.has_iflags {
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

        // 2. Read source data and stream delta tokens directly to the wire.
        let mut literal_bytes = 0u64;
        let mut matched_bytes = 0u64;

        let use_compress = protocol.compress != CompressType::None;
        let mut tok_writer = if use_compress {
            let compressor = Compressor::from_type(protocol.compress, 6)?;
            AnyTokenWriter::Compressed(token::CompressedTokenWriter::new(compressor))
        } else {
            AnyTokenWriter::Plain(token::PlainTokenWriter::new())
        };

        if entry.len >= crate::fs::STREAMING_THRESHOLD {
            // Streaming path: process in chunks to avoid O(file_size) memory.
            let mut stream_reader = file_reader.open_stream(entry)?;
            let mut smatcher =
                matcher::StreamingMatcher::new(&sums, &ctx, matcher::DEFAULT_STREAM_CHUNK);
            let mut file_hash = checksum::IncrementalChecksum::new(ctx.checksum_type);

            loop {
                let (ops, done) = smatcher
                    .process_chunk(&mut *stream_reader, &mut file_hash)
                    .map_err(WireError::Io)?;
                for op in &ops {
                    match op {
                        DiffOp::Literal(ref data) => {
                            let mut tok_buf = Vec::with_capacity(data.len() + 4);
                            tok_writer.write_data(&mut tok_buf, data).await?;
                            mplex_out.write_data(&tok_buf).await?;
                            literal_bytes += data.len() as u64;
                        }
                        DiffOp::Copy(bref) => {
                            let mut tok_buf = Vec::with_capacity(8);
                            tok_writer
                                .write_block_match(
                                    &mut tok_buf,
                                    bref.block_index(sums.head.blength as u32),
                                )
                                .await?;
                            mplex_out.write_data(&tok_buf).await?;
                            matched_bytes += bref.length as u64;
                        }
                    }
                }
                if done {
                    break;
                }
            }
            let mut eof_buf = Vec::with_capacity(8);
            tok_writer.write_eof(&mut eof_buf).await?;
            mplex_out.write_data(&eof_buf).await?;

            let file_sum = file_hash.finalize();
            mplex_out.write_data(&file_sum).await?;
            mplex_out.flush().await?;
        } else {
            // Existing mmap path for small/medium files.
            let source_data = file_reader.read_file(entry)?;

            let ops = matcher::match_blocks(&source_data, &sums, &ctx);

            for op in &ops {
                match op {
                    DiffOp::Literal(data) => {
                        let mut tok_buf = Vec::with_capacity(data.len() + 4);
                        tok_writer.write_data(&mut tok_buf, data).await?;
                        mplex_out.write_data(&tok_buf).await?;
                        literal_bytes += data.len() as u64;
                    }
                    DiffOp::Copy(bref) => {
                        let mut tok_buf = Vec::with_capacity(8);
                        tok_writer
                            .write_block_match(
                                &mut tok_buf,
                                bref.block_index(sums.head.blength as u32),
                            )
                            .await?;
                        mplex_out.write_data(&tok_buf).await?;
                        matched_bytes += bref.length as u64;
                    }
                }
            }
            let mut eof_buf = Vec::with_capacity(8);
            tok_writer.write_eof(&mut eof_buf).await?;
            mplex_out.write_data(&eof_buf).await?;

            let file_sum = checksum::file_checksum(&source_data, &ctx);
            mplex_out.write_data(&file_sum).await?;
            mplex_out.flush().await?;
        }

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
        int_codec,
    )
    .await?;
    mplex_out.write_data(&done_buf).await?;
    mplex_out.flush().await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Pipelined receiver loop
// ---------------------------------------------------------------------------

use super::receiver_engine::{EntryAction, HandledKind, ReceiverEngine};

/// Message from the generator task to the receiver task.
enum GeneratorItem {
    /// Entry was fully handled by dispatch_entry (dir, symlink, link-dest, etc.)
    Handled { entry_idx: usize, kind: HandledKind },
    /// Hardlink duplicate -- deferred until first occurrences are on disk.
    DeferredHardlink {
        entry_idx: usize,
        source_name: Vec<u8>,
    },
    /// A file needs data transfer from the sender.
    Transfer {
        entry_idx: usize,
        basis_data: FileData,
        blength: usize,
    },
    /// All phases are complete.
    Done,
}

/// Run the receiver loop with pipelined generator/receiver tasks.
///
/// The generator task iterates all entries, calling `dispatch_entry()` for
/// each to determine what action to take. For entries that need data
/// transfer, it sends block signatures to the remote sender and a
/// [`GeneratorItem::Transfer`] on the channel. The receiver task reads
/// delta responses from the wire and writes them via the engine.
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
    engine: Arc<ReceiverEngine>,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
    block_size_override: Option<i32>,
) -> Result<(R, MplexWriter<W>)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = block_size_override;
    let int_codec = protocol.wire.int_codec;
    let has_iflags = protocol.wire.has_iflags;

    // Clone entries so they can be sent into the spawned generator task.
    let gen_entries: Vec<(usize, i32, FileEntry)> = entries
        .iter()
        .enumerate()
        .map(|(idx, e)| (idx, entry_ndx[idx], e.clone()))
        .collect();

    // Bounded channel: generator -> receiver. Capacity of 4 provides
    // enough pipelining without unbounded memory growth.
    let (gen_tx, mut gen_rx) = tokio::sync::mpsc::channel::<GeneratorItem>(4);

    let gen_engine = Arc::clone(&engine);

    // --- Generator task ---
    // Owns mplex_out exclusively. Dispatches each entry through
    // dispatch_entry(), sends wire protocol for NeedsTransfer entries,
    // and tells the receiver task what's coming.
    let generator_handle = tokio::spawn(async move {
        let mut mplex_out = mplex_out;
        let mut gen_ndx_state = varint::NdxState::default();

        for (idx, file_ndx, entry) in &gen_entries {
            // Ensure parent directories exist for regular files.
            if entry.is_file() {
                if let Err(e) = gen_engine.ensure_parent(entry) {
                    tracing::warn!(
                        path = %String::from_utf8_lossy(&entry.name),
                        error = %e,
                        "failed to create parent directory"
                    );
                }
            }

            let action = match gen_engine.dispatch_entry(entry) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(
                        path = %String::from_utf8_lossy(&entry.name),
                        error = %e,
                        "dispatch_entry failed"
                    );
                    continue;
                }
            };

            match action {
                EntryAction::Handled { kind } => {
                    if gen_tx
                        .send(GeneratorItem::Handled {
                            entry_idx: *idx,
                            kind,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                EntryAction::Skipped => {
                    // Nothing to send to receiver for skipped entries.
                }
                EntryAction::DeferredHardlink { source_name } => {
                    if gen_tx
                        .send(GeneratorItem::DeferredHardlink {
                            entry_idx: *idx,
                            source_name,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                EntryAction::NeedsTransfer { basis } => {
                    // Fuzzy fallback if basis is empty.
                    let basis_data = if basis.is_empty() {
                        gen_engine.find_fuzzy_basis(entry).unwrap_or(basis)
                    } else {
                        basis
                    };

                    // Compute block signatures.
                    let sigs = sum::compute_signatures(&basis_data, &ctx);

                    let blength = if sigs.head.blength > 0 {
                        sigs.head.blength as usize
                    } else {
                        700
                    };

                    // Send generator output to wire: NDX + iflags + sum_head + block sigs.
                    let mut sig_buf = Vec::new();
                    varint::write_ndx(&mut sig_buf, *file_ndx, &mut gen_ndx_state, int_codec)
                        .await?;
                    if has_iflags {
                        const ITEM_TRANSFER: u16 = 1 << 15;
                        varint::write_shortint(&mut sig_buf, ITEM_TRANSFER).await?;
                    }
                    let is_append =
                        gen_engine.options().append() || gen_engine.options().append_verify();
                    if is_append {
                        sum::write_sum_head(&mut sig_buf, &sigs.head).await?;
                    } else {
                        sum::write_sums(&mut sig_buf, &sigs).await?;
                    }
                    mplex_out.write_data(&sig_buf).await?;
                    mplex_out.flush().await?;

                    // Tell receiver task what file to expect.
                    let item = GeneratorItem::Transfer {
                        entry_idx: *idx,
                        basis_data,
                        blength,
                    };
                    if gen_tx.send(item).await.is_err() {
                        break;
                    }
                }
            }
        }

        // Signal completion.
        let _ = gen_tx.send(GeneratorItem::Done).await;

        Ok::<MplexWriter<W>, WireError>(mplex_out)
    });

    // --- Receiver task (runs on current task) ---
    // Owns demux_read exclusively. Reads GeneratorItems from the channel,
    // then reads the sender's delta response from the wire for Transfer items.
    let mut demux_read = demux_read;
    let mut recv_ndx_state = varint::NdxState::default();
    let mut deferred_hardlinks: Vec<(usize, Vec<u8>)> = Vec::new();

    while let Some(item) = gen_rx.recv().await {
        match item {
            GeneratorItem::Handled { entry_idx, kind } => {
                let entry = &entries[entry_idx];
                match kind {
                    HandledKind::Directory => {
                        stats.directories_created += 1;
                    }
                    HandledKind::Symlink => {
                        stats.symlinks += 1;
                        progress.emit(ProgressEvent::FileComplete {
                            index: entry_idx as i32,
                            name: crate::engine::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: 0,
                            matched_bytes: 0,
                        });
                    }
                    HandledKind::LinkDest | HandledKind::CopyDest => {
                        stats.files_transferred += 1;
                        stats.matched_data += entry.len as u64;
                        progress.emit(ProgressEvent::FileComplete {
                            index: entry_idx as i32,
                            name: crate::engine::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: 0,
                            matched_bytes: entry.len as u64,
                        });
                    }
                    HandledKind::DryRun => {
                        stats.files_transferred += 1;
                        stats.total_size += entry.len as u64;
                        progress.emit(ProgressEvent::FileComplete {
                            index: entry_idx as i32,
                            name: crate::engine::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: entry.len as u64,
                            matched_bytes: 0,
                        });
                    }
                }
            }
            GeneratorItem::DeferredHardlink {
                entry_idx,
                source_name,
            } => {
                deferred_hardlinks.push((entry_idx, source_name));
            }
            GeneratorItem::Transfer {
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
                    varint::read_ndx(&mut demux_read, &mut recv_ndx_state, int_codec).await?;

                // Read iflags (when wire format includes them).
                if has_iflags {
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
                let sum_head = sum::read_sum_head(&mut demux_read).await?;
                let blength_actual = if sum_head.blength > 0 {
                    sum_head.blength as usize
                } else {
                    blength
                };

                // Reconstruct file: buffered for sparse, streaming otherwise.
                let use_compress = protocol.compress != CompressType::None;
                let literal_bytes = if engine.needs_buffered_receive() {
                    let data = receiver::recv_file_delta(
                        &mut demux_read,
                        &basis_data,
                        blength_actual,
                        &ctx,
                    )
                    .await?;
                    let len = data.len() as u64;
                    engine.apply_transfer(entry, &data, None)?;
                    len
                } else {
                    let mut writer = engine.create_writer(entry)?;
                    let bytes_written = if use_compress {
                        let decompressor = Decompressor::from_type(protocol.compress)?;
                        receiver::recv_file_delta_compressed_to_writer(
                            &mut demux_read,
                            &basis_data,
                            blength_actual,
                            &ctx,
                            &mut writer,
                            decompressor,
                        )
                        .await?
                    } else {
                        receiver::recv_file_delta_to_writer(
                            &mut demux_read,
                            &basis_data,
                            blength_actual,
                            &ctx,
                            &mut writer,
                        )
                        .await?
                    };
                    drop(writer);
                    engine.finish_file(entry, None)?;
                    bytes_written
                };

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

    // Create deferred hardlinks now that first occurrences are on disk.
    for (entry_idx, source_name) in &deferred_hardlinks {
        let dup_entry = &entries[*entry_idx];
        if let Some(source) = entries.iter().find(|e| e.name == *source_name) {
            let source_path = engine.dest_path(source);
            let link_path = engine.dest_path(dup_entry);
            if !engine.options().dry_run() {
                let _ = engine.fs().remove_file(&link_path);
                if let Err(e) = engine.fs().hard_link(&source_path, &link_path) {
                    tracing::warn!(
                        source = %String::from_utf8_lossy(source_name),
                        link = %String::from_utf8_lossy(&dup_entry.name),
                        error = %e,
                        "deferred hardlink creation failed"
                    );
                } else {
                    stats.files_transferred += 1;
                }
            } else {
                stats.files_transferred += 1;
            }
        }
    }

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
    let ndx_start: i32 = if protocol.wire.supports_incremental_flist && is_recursive {
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
    protocol: &NegotiatedProtocol,
) -> Result<()> {
    let int_codec = protocol.wire.int_codec;
    let mut stats_buf = Vec::new();
    varint::write_varlong30(&mut stats_buf, 0, 3, int_codec).await?;
    varint::write_varlong30(&mut stats_buf, stats.bytes_sent as i64, 3, int_codec).await?;
    varint::write_varlong30(&mut stats_buf, stats.total_size as i64, 3, int_codec).await?;
    if protocol.wire.has_iflags {
        varint::write_varlong30(&mut stats_buf, 0, 3, int_codec).await?;
        varint::write_varlong30(&mut stats_buf, 0, 3, int_codec).await?;
    }
    mplex_out.write_data(&stats_buf).await?;
    mplex_out.flush().await?;
    Ok(())
}

/// Read transfer stats from the sender.
pub async fn read_stats<R: AsyncRead + Unpin + Send>(
    demux_read: &mut R,
    protocol: &NegotiatedProtocol,
) -> Result<()> {
    let int_codec = protocol.wire.int_codec;
    let _total_read = varint::read_varlong30(demux_read, 3, int_codec).await?;
    let _total_written = varint::read_varlong30(demux_read, 3, int_codec).await?;
    let _total_size = varint::read_varlong30(demux_read, 3, int_codec).await?;
    if protocol.wire.has_iflags {
        let _flist_buildtime = varint::read_varlong30(demux_read, 3, int_codec).await?;
        let _flist_xfertime = varint::read_varlong30(demux_read, 3, int_codec).await?;
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
    protocol: &NegotiatedProtocol,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let int_codec = protocol.wire.int_codec;
    {
        let mut read_state = varint::NdxState::default();
        let mut write_state = varint::NdxState::default();

        if protocol.wire.has_error_exit_sync {
            // Read first goodbye NDX_DONE from receiver.
            let _ = varint::read_ndx(demux_read, &mut read_state, int_codec).await;

            // Acknowledge with our own NDX_DONE.
            write_goodbye_done(mplex_out, &mut write_state, int_codec).await;

            // Read error-exit sync NDX_DONE.
            let _ = varint::read_ndx(demux_read, &mut read_state, int_codec).await;
        } else {
            // Proto 24-30: just read the final NDX_DONE.
            let _ = varint::read_ndx(demux_read, &mut read_state, int_codec).await;
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
    protocol: &NegotiatedProtocol,
    num_flists: usize,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let int_codec = protocol.wire.int_codec;
    let max_phase: u32 = protocol.wire.phase_count as u32;
    let flist_cleanup_rounds: u32 = if protocol.wire.supports_incremental_flist {
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
            int_codec,
        )
        .await?;
        mplex_out.write_data(&done_buf).await?;
        mplex_out.flush().await?;

        // Read sender's NDX_DONE response.
        let resp = varint::read_ndx(demux_read, &mut recv_ndx_state, int_codec).await?;
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
    codec: IntCodec,
) {
    let mut buf = Vec::new();
    let _ = varint::write_ndx(&mut buf, varint::NDX_DONE, st, codec).await;
    let _ = out.write_data(&buf).await;
    let _ = out.flush().await;
}

/// Receiver goodbye exchange (proto >= 24).
///
/// Sends goodbye NDX_DONEs that the sender expects to read.
pub async fn receiver_goodbye<R, W>(
    demux_read: &mut R,
    mplex_out: &mut MplexWriter<W>,
    protocol: &NegotiatedProtocol,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let int_codec = protocol.wire.int_codec;
    {
        let mut gen_ndx_state = varint::NdxState::default();
        let mut recv_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut gen_ndx_state, int_codec).await;
        let _ = varint::read_ndx(demux_read, &mut recv_ndx_state, int_codec).await;
        write_goodbye_done(mplex_out, &mut gen_ndx_state, int_codec).await;

        if protocol.wire.has_error_exit_sync {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, int_codec).await;
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
    protocol: &NegotiatedProtocol,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let int_codec = protocol.wire.int_codec;
    {
        let mut send_ndx_state = varint::NdxState::default();
        let mut gen_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut send_ndx_state, int_codec).await;

        // Read goodbye NDX_DONEs from receiver (best-effort).
        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, int_codec).await;
        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, int_codec).await;
        if protocol.wire.has_error_exit_sync {
            let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, int_codec).await;
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
    protocol: &NegotiatedProtocol,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let int_codec = protocol.wire.int_codec;
    let max_phase: u32 = protocol.wire.phase_count as u32;
    let mut gen_ndx_state = varint::NdxState::default();
    let mut recv_ndx_state = varint::NdxState::default();

    // Send (max_phase + 1) NDX_DONEs to the sender.
    for phase in 0..=max_phase {
        let mut done_buf = Vec::new();
        varint::write_ndx(
            &mut done_buf,
            varint::NDX_DONE,
            &mut gen_ndx_state,
            int_codec,
        )
        .await?;
        mplex_out.write_data(&done_buf).await?;
        mplex_out.flush().await?;

        // The sender responds with NDX_DONE for each phase except the last.
        if phase < max_phase {
            let resp = varint::read_ndx(demux_read, &mut recv_ndx_state, int_codec).await?;
            if resp != varint::NDX_DONE {
                tracing::warn!(ndx = resp, phase, "expected NDX_DONE from sender");
            }
        }
    }

    // Read the sender's final NDX_DONE.
    let final_ndx = varint::read_ndx(demux_read, &mut recv_ndx_state, int_codec).await?;
    if final_ndx != varint::NDX_DONE {
        tracing::warn!(ndx = final_ndx, "expected final NDX_DONE from sender");
    }

    Ok(())
}

/// Server-side receiver goodbye exchange (proto >= 24).
pub async fn server_receiver_goodbye<W: AsyncWrite + Unpin + Send>(
    mplex_out: &mut MplexWriter<W>,
    protocol: &NegotiatedProtocol,
) -> Result<()> {
    let int_codec = protocol.wire.int_codec;
    {
        let mut gen_ndx_state = varint::NdxState::default();
        write_goodbye_done(mplex_out, &mut gen_ndx_state, int_codec).await;
        if protocol.wire.has_error_exit_sync {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, int_codec).await;
        }
    }
    Ok(())
}
