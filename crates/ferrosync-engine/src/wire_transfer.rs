//! Unified wire-level sender/receiver loops.
//!
//! Shared protocol mechanics for both client (SyncSession) and server
//! (ServerSession) sides. The loops are parameterized by traits that
//! abstract away the differences in file I/O between the two sides.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::progress::{ProgressEvent, ProgressTracker};
use crate::receiver;
use ferrosync_codec::entry::{FileEntry, S_IFMT, S_IFREG};
use ferrosync_delta::ops::DiffOp;
use ferrosync_delta::token::TokenWriter;
use ferrosync_delta::{checksum, matcher, sum, token, ProtocolContext};
use ferrosync_fs::{FileData, FileSystem};
use ferrosync_protocol::compress::{Compressor, Decompressor};
use ferrosync_protocol::handshake::{CompressType, NegotiatedProtocol};
use ferrosync_protocol::multiplex::{BufferedMplexReader, MplexWriter, MuxConnection};
use ferrosync_protocol::varint;
use ferrosync_types::error::ProtocolError;
use ferrosync_types::stats::TransferStats;

type Result<T> = std::result::Result<T, ferrosync_types::FerrosyncError>;

// ---------------------------------------------------------------------------
// FileReader trait (sender side)
// ---------------------------------------------------------------------------

/// Source file access abstraction for the sender loop.
///
/// Client push uses local filesystem + TransferOptions to locate source files.
/// Server send uses module path to locate files.
pub trait FileReader: Send + Sync {
    /// Read the source data for a file entry.
    fn read_file(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<FileData, ferrosync_types::error::FsError>;

    /// Open a streaming reader for a file entry.
    ///
    /// Returns a `Read` handle that reads the file without loading it
    /// entirely into memory. Used by the streaming sender for large files.
    fn open_stream(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn Read + Send>, ferrosync_types::error::FsError> {
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
    fn read_file(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<FileData, ferrosync_types::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        for source in self.source_paths {
            let path = if self.source_paths.len() == 1
                && self
                    .fs
                    .lstat(source)
                    .is_ok_and(|m| m.mode & S_IFMT == ferrosync_codec::entry::S_IFDIR)
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
    ) -> std::result::Result<Box<dyn Read + Send>, ferrosync_types::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        for source in self.source_paths {
            let path = if self.source_paths.len() == 1
                && self
                    .fs
                    .lstat(source)
                    .is_ok_and(|m| m.mode & S_IFMT == ferrosync_codec::entry::S_IFDIR)
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
    fn read_file(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<FileData, ferrosync_types::error::FsError> {
        let name_str = String::from_utf8_lossy(&entry.name);
        let path = self.module_path.join(name_str.as_ref());
        Ok(self.fs.map_file(&path).unwrap_or_default())
    }

    fn open_stream(
        &self,
        entry: &FileEntry,
    ) -> std::result::Result<Box<dyn Read + Send>, ferrosync_types::error::FsError> {
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
    mux: &mut MuxConnection<R, W>,
    entries: &[FileEntry],
    ndx_map: &HashMap<i32, usize>,
    file_reader: &dyn FileReader,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
    block_size_override: Option<i32>,
    dry_run: bool,
    mut pending_flists: Option<ferrosync_codec::incremental::PendingSubFlists<'_>>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = block_size_override;
    let int_codec = protocol.wire().int_codec;
    let wire = protocol.wire();

    let mut gen_ndx_state = varint::NdxState::default();
    let mut send_ndx_state = varint::NdxState::default();
    let max_phase: u32 = wire.phase_count as u32;
    let mut phase: u32 = 0;

    loop {
        // Inject pending sub-flists before reading the next generator request.
        // rsync's sender loop calls send_extra_file_list() at this point to
        // keep the receiver fed with directory entries during the transfer.
        if let Some(ref mut pending) = pending_flists {
            if !pending.is_done() {
                let mut flist_buf = Vec::new();
                pending.send_pending(&mut flist_buf, 1).await?;
                if !flist_buf.is_empty() {
                    mux.write_data(&flist_buf).await?;
                    mux.flush().await?;
                }
            }
        }

        let ndx = varint::read_ndx(mux, &mut gen_ndx_state, int_codec).await?;

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
            mux.write_data(&done_buf).await?;
            mux.flush().await?;
            continue;
        }

        // NDX_FLIST_EOF (-2) or NDX_DEL_STATS (-3): skip.
        if ndx < -1 {
            continue;
        }

        // Read iflags from generator (proto >= 29).
        let iflags = wire.read_iflags(mux).await?;

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
            wire.write_iflags_echo(&mut echo_buf, iflags).await?;
            mux.write_data(&echo_buf).await?;
            mux.flush().await?;
            continue;
        }

        // Dry-run: remote generator sends NDX + iflags but skips sum_head
        // and block signatures (rsync generator.c: if (!do_xfers) goto cleanup).
        // Don't try to read sums -- just count the file and continue.
        if dry_run {
            stats.files_transferred += 1;
            stats.total_size += entry.len.as_u64();
            progress.emit(ProgressEvent::FileComplete {
                index: ndx,
                name: crate::progress::name_to_pathbuf(&entry.name),
                literal_bytes: entry.len.as_u64(),
                matched_bytes: 0,
            });
            continue;
        }

        // Read block signatures from generator.
        let sums = sum::read_sums(mux).await?;

        progress.emit(ProgressEvent::FileStart {
            index: ndx,
            name: crate::progress::name_to_pathbuf(&entry.name),
            size: entry.len.bytes(),
        });

        // Stream sender response: NDX + iflags + sum_head (small header),
        // then tokens individually, then file checksum.
        // Each piece goes to the wire as its own MUX frame(s), avoiding
        // an O(file_size) intermediate buffer.

        // 1. Small header: NDX + iflags + sum_head (~20 bytes).
        let mut hdr = Vec::with_capacity(64);
        varint::write_ndx(&mut hdr, ndx, &mut send_ndx_state, int_codec).await?;
        wire.write_iflags(&mut hdr, iflags).await?;
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
        mux.write_data(&hdr).await?;

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

        if entry.len.bytes() >= ferrosync_fs::STREAMING_THRESHOLD {
            // Streaming path: process in chunks to avoid O(file_size) memory.
            let mut stream_reader = file_reader.open_stream(entry)?;
            let mut smatcher =
                matcher::StreamingMatcher::new(&sums, &ctx, matcher::DEFAULT_STREAM_CHUNK);
            let mut file_hash = checksum::IncrementalChecksum::new(ctx.checksum_type);

            loop {
                let (ops, done) = smatcher
                    .process_chunk(&mut *stream_reader, &mut file_hash)
                    .map_err(ferrosync_types::FerrosyncError::from)?;
                for op in &ops {
                    match op {
                        DiffOp::Literal(ref data) => {
                            let mut tok_buf = Vec::with_capacity(data.len() + 4);
                            tok_writer.write_data(&mut tok_buf, data).await?;
                            mux.write_data(&tok_buf).await?;
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
                            mux.write_data(&tok_buf).await?;
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
            mux.write_data(&eof_buf).await?;

            let file_sum = file_hash.finalize();
            mux.write_data(&file_sum).await?;
            mux.flush().await?;
        } else {
            // Existing mmap path for small/medium files.
            let source_data = file_reader.read_file(entry)?;

            let ops = matcher::match_blocks(&source_data, &sums, &ctx);

            for op in &ops {
                match op {
                    DiffOp::Literal(data) => {
                        let mut tok_buf = Vec::with_capacity(data.len() + 4);
                        tok_writer.write_data(&mut tok_buf, data).await?;
                        mux.write_data(&tok_buf).await?;
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
                        mux.write_data(&tok_buf).await?;
                        matched_bytes += bref.length as u64;
                    }
                }
            }
            let mut eof_buf = Vec::with_capacity(8);
            tok_writer.write_eof(&mut eof_buf).await?;
            mux.write_data(&eof_buf).await?;

            let file_sum = checksum::file_checksum(&source_data, &ctx);
            mux.write_data(&file_sum).await?;
            mux.flush().await?;
        }

        stats.files_transferred += 1;
        stats.total_size += entry.len.as_u64();
        stats.literal_data += literal_bytes;
        stats.matched_data += matched_bytes;
        stats.bytes_sent += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: ndx,
            name: crate::progress::name_to_pathbuf(&entry.name),
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
    mux.write_data(&done_buf).await?;
    mux.flush().await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Pipelined receiver loop
// ---------------------------------------------------------------------------

use crate::receiver_engine::{EntryAction, HandledKind, ReceiverEngine};

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
    demux_read: BufferedMplexReader<R>,
    mplex_out: MplexWriter<W>,
    entries: &[FileEntry],
    entry_ndx: &[i32],
    engine: Arc<ReceiverEngine>,
    protocol: &NegotiatedProtocol,
    stats: &mut TransferStats,
    progress: &mut ProgressTracker,
    block_size_override: Option<i32>,
) -> Result<(BufferedMplexReader<R>, MplexWriter<W>)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut ctx = ProtocolContext::from_protocol(protocol);
    ctx.block_size_override = block_size_override;
    let int_codec = protocol.wire().int_codec;
    let has_iflags = protocol.wire().has_iflags;

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

        Ok::<MplexWriter<W>, ferrosync_types::FerrosyncError>(mplex_out)
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
                            name: crate::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: 0,
                            matched_bytes: 0,
                        });
                    }
                    HandledKind::LinkDest | HandledKind::CopyDest => {
                        stats.files_transferred += 1;
                        stats.matched_data += entry.len.as_u64();
                        progress.emit(ProgressEvent::FileComplete {
                            index: entry_idx as i32,
                            name: crate::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: 0,
                            matched_bytes: entry.len.as_u64(),
                        });
                    }
                    HandledKind::DryRun => {
                        stats.files_transferred += 1;
                        stats.total_size += entry.len.as_u64();
                        progress.emit(ProgressEvent::FileComplete {
                            index: entry_idx as i32,
                            name: crate::progress::name_to_pathbuf(&entry.name),
                            literal_bytes: entry.len.as_u64(),
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
                    name: crate::progress::name_to_pathbuf(&entry.name),
                    size: entry.len.bytes(),
                });

                // Read sender's response NDX.
                let _file_ndx =
                    varint::read_ndx(&mut demux_read, &mut recv_ndx_state, int_codec).await?;

                // Read iflags (when wire format includes them).
                let _iflags = protocol.wire().read_iflags(&mut demux_read).await?;

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
                stats.total_size += entry.len.as_u64();
                stats.literal_data += literal_bytes;
                stats.bytes_received += literal_bytes;

                progress.emit(ProgressEvent::FileComplete {
                    index: entry_idx as i32,
                    name: crate::progress::name_to_pathbuf(&entry.name),
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
        ferrosync_types::FerrosyncError::Protocol(ProtocolError::Handshake {
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

/// Build a map from NDX value to entry index.
///
/// Accepts the NDX assignments produced by `send_file_list` or computed
/// from `recv_file_list`. For batch mode these are contiguous (0, 1, 2, ...);
/// for incremental mode there are gaps between sub-flists.
pub fn build_ndx_map(ndx_values: &[i32]) -> HashMap<i32, usize> {
    ndx_values
        .iter()
        .enumerate()
        .map(|(i, &ndx)| (ndx, i))
        .collect()
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
    let int_codec = protocol.wire().int_codec;
    let max_phase: u32 = protocol.wire().phase_count as u32;
    let flist_cleanup_rounds: u32 = if protocol.wire().supports_incremental_flist {
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
    let int_codec = protocol.wire().int_codec;
    let max_phase: u32 = protocol.wire().phase_count as u32;
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
