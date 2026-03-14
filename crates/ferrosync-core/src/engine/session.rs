//! Sync session: end-to-end wire-level transfer orchestration.
//!
//! [`SyncSession`] connects the transport, protocol handshake, file list
//! exchange, and per-file delta transfer into a complete rsync session.
//!
//! ```text
//! Transport::connect() -> TransportStreams
//!     -> client_handshake() -> NegotiatedProtocol
//!         -> send/recv file list
//!             -> per-file delta transfer (generator/sender/receiver over wire)
//! ```

use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::delta::checksum;
use crate::delta::sum;
use crate::engine::progress::{ProgressEvent, ProgressTracker};
use crate::engine::receiver;
use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT};
use crate::filelist::exchange;
use crate::filter::FilterRuleList;
use crate::fs::{DirEntry, FileSystem};
use crate::options::{DeleteMode, TransferOptions};
use crate::protocol::handshake::{self, build_capability_string, NegotiatedProtocol};
use crate::protocol::multiplex::{MplexMessage, MplexReader, MplexWriter};
use crate::stats::TransferStats;
use crate::transport::{Transport, TransportStreams};

use super::transfer::TransferResult;

type Result<T> = std::result::Result<T, crate::FerrosyncError>;

// ---------------------------------------------------------------------------
// Sync direction
// ---------------------------------------------------------------------------

/// Direction of the sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    /// Push local files to remote (we are the sender).
    Push,
    /// Pull remote files to local (we are the receiver).
    Pull,
}

// ---------------------------------------------------------------------------
// Server option string builder
// ---------------------------------------------------------------------------

/// Build the condensed option string for `rsync --server`.
///
/// This is the flag string rsync passes to the remote side, e.g.
/// `-logDtprze.iLsfxCIvu`. The remote uses it to configure its behavior.
pub fn build_server_options(opts: &TransferOptions, _am_sender: bool) -> String {
    let mut s = String::from("-");

    // Single-char flags MUST come before the capability string, because
    // rsync's option parser treats `e` as consuming the rest of the arg
    // as its value.
    if opts.preserve_links {
        s.push('l');
    }
    if opts.preserve_owner {
        s.push('o');
    }
    if opts.preserve_group {
        s.push('g');
    }
    if opts.preserve_devices || opts.preserve_specials {
        s.push('D');
    }
    if opts.preserve_times {
        s.push('t');
    }
    if opts.preserve_perms {
        s.push('p');
    }
    if opts.recursive {
        s.push('r');
    }
    if opts.compress {
        s.push('z');
    }
    if opts.checksum_mode {
        s.push('c');
    }
    if opts.update {
        s.push('u');
    }
    if opts.dry_run {
        s.push('n');
    }
    if opts.whole_file {
        s.push('W');
    }
    if opts.one_file_system {
        s.push('x');
    }
    if opts.sparse {
        s.push('S');
    }
    match opts.verbosity {
        crate::options::Verbosity::Quiet => s.push('q'),
        crate::options::Verbosity::Verbose => s.push('v'),
        crate::options::Verbosity::VeryVerbose => {
            s.push('v');
            s.push('v');
        }
        crate::options::Verbosity::Debug => {
            s.push('v');
            s.push('v');
            s.push('v');
        }
        _ => {}
    }

    // Capability string MUST be last in the condensed options, since `e`
    // consumes the remainder of the argument as its value.
    //
    // For push (am_sender=true), don't advertise incremental recursion ('i')
    // because our sender doesn't implement per-directory sub-list generation.
    // For pull, 'i' is fine since rsync's sender handles incremental sub-lists.
    let use_inc_recurse = opts.recursive && !_am_sender;
    let caps = build_capability_string(use_inc_recurse, true, false);
    s.push('e');
    s.push_str(&caps);

    // Long-form options are separate arguments appended after the
    // condensed string.
    if opts.inplace {
        s.push_str(" --inplace");
    }
    if opts.numeric_ids {
        s.push_str(" --numeric-ids");
    }
    if opts.append {
        s.push_str(" --append");
    }

    match opts.delete {
        DeleteMode::Before => s.push_str(" --delete-before"),
        DeleteMode::During => s.push_str(" --delete-during"),
        DeleteMode::After => s.push_str(" --delete-after"),
        DeleteMode::Excluded => s.push_str(" --delete-excluded"),
        DeleteMode::None => {}
    }

    s
}

// ---------------------------------------------------------------------------
// SyncSession
// ---------------------------------------------------------------------------

/// A complete sync session over a transport.
///
/// Orchestrates the full rsync wire protocol: transport connection, version
/// handshake, file list exchange, and per-file delta transfer.
///
/// # Example
///
/// ```ignore
/// let transport = LocalTransport::new(None, true, &options_str, path);
/// let session = SyncSession::new(transport, options, fs, SyncDirection::Push);
/// let result = session.run().await?;
/// println!("transferred {} files", result.stats.files_transferred);
/// ```
pub struct SyncSession<T: Transport> {
    transport: T,
    options: TransferOptions,
    fs: Box<dyn FileSystem>,
    direction: SyncDirection,
    progress: ProgressTracker,
}

impl<T: Transport> SyncSession<T> {
    /// Create a new sync session.
    pub fn new(
        transport: T,
        options: TransferOptions,
        fs: Box<dyn FileSystem>,
        direction: SyncDirection,
    ) -> Self {
        Self {
            transport,
            options,
            fs,
            direction,
            progress: ProgressTracker::new(),
        }
    }

    /// Set a custom progress tracker.
    pub fn with_progress(mut self, progress: ProgressTracker) -> Self {
        self.progress = progress;
        self
    }

    /// Execute the sync session.
    ///
    /// Connects the transport, performs the protocol handshake, exchanges
    /// file lists, and transfers files over the wire.
    pub async fn run(self) -> Result<TransferResult> {
        let SyncSession {
            transport,
            options,
            fs,
            direction,
            mut progress,
        } = self;

        // 1. Connect transport.
        let TransportStreams {
            mut reader,
            mut writer,
        } = Box::new(transport).connect().await?;

        let am_sender = direction == SyncDirection::Push;

        // 2. Protocol handshake (non-multiplexed phase).
        let protocol = handshake::client_handshake(
            &mut reader,
            &mut writer,
            am_sender,
            options.compress,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

        tracing::info!(
            version = protocol.version,
            checksum = ?protocol.checksum,
            compress = ?protocol.compress,
            incremental = protocol.incremental_flist,
            seed = protocol.seed,
            "handshake complete"
        );

        // 3. Exchange file lists and transfer.
        if am_sender {
            run_push(reader, writer, &protocol, &options, &*fs, &mut progress).await
        } else {
            run_pull(reader, writer, &protocol, &options, &*fs, &mut progress).await
        }
    }
}

// ---------------------------------------------------------------------------
// Push (sender) flow
// ---------------------------------------------------------------------------

/// Push local files to remote (we are sender).
///
/// Protocol flow (proto >= 30):
/// 1. Both sides enable MUX after handshake
/// 2. We send filter list (MUX DATA)
/// 3. We send file list (MUX DATA)
/// 4. Remote generator sends NDX + iflags + block sigs for each file
/// 5. We match blocks, send NDX + iflags + sum_head + delta tokens + checksum
/// 6. Phase exchange: read NDX_DONE from generator, respond with NDX_DONE
/// 7. Write stats (5 varlong30)
/// 8. Goodbye exchange
async fn run_push(
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    protocol: &NegotiatedProtocol,
    options: &TransferOptions,
    fs: &dyn FileSystem,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    let seed = protocol.seed;
    let checksum_type = protocol.checksum;
    let proto_ver = protocol.version;

    // Both sides enable MUX after handshake (proto >= 30).
    let (demux_write, mut demux_read) = tokio::io::duplex(64 * 1024);
    let demux_handle = tokio::spawn(demux_task(reader, demux_write));
    let mut mplex_out = MplexWriter::new(writer);

    // 1. Send filter list (only for non-local connections).
    //
    // rsync's recv_filter_list skips reading when local_server=true (the
    // server was spawned locally, not over SSH/daemon). For LocalTransport
    // we must NOT send filter data, otherwise the 4-byte terminator ends
    // up in the file list stream, causing recv_file_list to see flags=0
    // (end-of-list) immediately.
    //
    // TODO: For SSH/daemon transports, send filter list here.

    // 2. Build and send file list.
    let entries = build_source_entries(fs, options)?;
    stats.total_files = entries.len() as u64;
    let total_bytes: i64 = entries.iter().map(|e| e.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    let mut flist_buf = Vec::new();
    exchange::send_file_list(&mut flist_buf, &entries, protocol, options)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    mplex_out
        .write_data(&flist_buf)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .flush()
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    // Compute NDX -> entry index mapping.
    // With inc_recurse (proto >= 30 AND recursive), ndx_start = 1; otherwise 0.
    let ndx_start: i32 =
        if protocol.incremental_flist && proto_ver >= 30 && options.recursive {
            1
        } else {
            0
        };
    let ndx_to_entry: std::collections::HashMap<i32, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, _)| (ndx_start + i as i32, i))
        .collect();

    // 3. Sender loop: read NDX from generator, send delta data.
    let mut gen_ndx_state = crate::protocol::varint::NdxState::default();
    let mut send_ndx_state = crate::protocol::varint::NdxState::default();
    // rsync's sender.c: max_phase = protocol_version >= 29 ? 2 : 1
    let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
    let mut phase: u32 = 0;

    loop {
        let ndx = crate::protocol::varint::read_ndx(
            &mut demux_read,
            &mut gen_ndx_state,
            proto_ver,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

        if ndx == crate::protocol::varint::NDX_DONE {
            phase += 1;
            if phase > max_phase {
                break;
            }
            // Respond with NDX_DONE (phase transition).
            let mut done_buf = Vec::new();
            crate::protocol::varint::write_ndx(
                &mut done_buf,
                crate::protocol::varint::NDX_DONE,
                &mut send_ndx_state,
                proto_ver,
            )
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
            mplex_out
                .write_data(&done_buf)
                .await
                .map_err(crate::FerrosyncError::Protocol)?;
            mplex_out
                .flush()
                .await
                .map_err(crate::FerrosyncError::Protocol)?;
            continue;
        }

        // NDX_FLIST_EOF (-2) or NDX_DEL_STATS (-3): generator signals from
        // incremental flist or delete stats. Ignore in non-incremental mode.
        if ndx < -1 {
            continue;
        }

        // Read iflags from generator (proto >= 29).
        let mut iflags: u16 = 0;
        if proto_ver >= 29 {
            use tokio::io::AsyncReadExt;
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
                let name_len = crate::protocol::varint::read_varint(&mut demux_read)
                    .await
                    .map_err(crate::FerrosyncError::Protocol)?;
                if name_len > 0x10000 {
                    return Err(crate::FerrosyncError::Protocol(
                        crate::error::ProtocolError::WireValueOutOfRange {
                            field: "xname_len",
                            value: name_len as i64,
                            max: 0x10000,
                        },
                    ));
                }
                let mut name_buf = vec![0u8; name_len as usize];
                use tokio::io::AsyncReadExt;
                demux_read.read_exact(&mut name_buf).await?;
            }
        }

        // Look up the entry for this NDX.
        let entry_idx = match ndx_to_entry.get(&ndx) {
            Some(&idx) => idx,
            None => {
                tracing::warn!(ndx, "generator requested unknown NDX, skipping");
                continue;
            }
        };
        let entry = &entries[entry_idx];

        // Non-regular files (directories, symlinks, etc.) don't have file data.
        // The generator handles them locally; the sender just skips them.
        if entry.mode & S_IFMT != crate::filelist::entry::S_IFREG {
            continue;
        }

        // Read block signatures from generator (only for regular files).
        let sums = sum::read_sums(&mut demux_read)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        progress.emit(ProgressEvent::FileStart {
            index: ndx,
            name: entry.name.clone(),
            size: entry.len,
        });

        // Read local source data.
        let source_data = read_source_file(fs, entry, options)?;

        // Match blocks and compute delta.
        let ops = crate::delta::matcher::match_blocks(
            &source_data,
            &sums,
            seed,
            checksum_type,
        );

        // Build sender response: NDX + iflags + sum_head + tokens + checksum.
        let mut resp_buf = Vec::new();

        // NDX + iflags.
        crate::protocol::varint::write_ndx(
            &mut resp_buf,
            ndx,
            &mut send_ndx_state,
            proto_ver,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
        if proto_ver >= 29 {
            crate::protocol::varint::write_shortint(&mut resp_buf, iflags)
                .await
                .map_err(crate::FerrosyncError::Protocol)?;
        }

        // sum_head: echo back the generator's sum head. For new files
        // (count=0), rsync's sender writes all zeros (NULL sum).
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
        sum::write_sum_head(&mut resp_buf, &resp_sum_head)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        // Delta tokens.
        let mut literal_bytes = 0u64;
        let mut matched_bytes = 0u64;
        for op in &ops {
            match op {
                crate::delta::matcher::MatchOp::Data(data) => {
                    crate::delta::token::send_data(&mut resp_buf, data)
                        .await
                        .map_err(crate::FerrosyncError::Protocol)?;
                    literal_bytes += data.len() as u64;
                }
                crate::delta::matcher::MatchOp::BlockMatch(block_idx) => {
                    crate::delta::token::send_block_match(&mut resp_buf, *block_idx)
                        .await
                        .map_err(crate::FerrosyncError::Protocol)?;
                    if sums.head.blength > 0 {
                        matched_bytes += sums.head.blength as u64;
                    }
                }
            }
        }
        crate::delta::token::send_eof(&mut resp_buf)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        // File-level checksum.
        let file_sum = checksum::file_checksum(&source_data, seed, checksum_type);
        resp_buf.extend_from_slice(&file_sum);

        // Send the complete response as a MUX DATA frame.
        mplex_out
            .write_data(&resp_buf)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out
            .flush()
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        stats.files_transferred += 1;
        stats.total_size += entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.matched_data += matched_bytes;
        stats.bytes_sent += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: ndx,
            name: entry.name.clone(),
            literal_bytes,
            matched_bytes,
        });
    }

    // 4. Post-loop: write final NDX_DONE (sender.c line 462).
    let mut done_buf = Vec::new();
    crate::protocol::varint::write_ndx(
        &mut done_buf,
        crate::protocol::varint::NDX_DONE,
        &mut send_ndx_state,
        proto_ver,
    )
    .await
    .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .write_data(&done_buf)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .flush()
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    // 5. Write transfer stats (sender writes, receiver reads).
    // 5 varlong30 values: total_read, total_written, total_size,
    // flist_buildtime, flist_xfertime.
    let mut stats_buf = Vec::new();
    crate::protocol::varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    crate::protocol::varint::write_varlong30(
        &mut stats_buf,
        stats.bytes_sent as i64,
        3,
        proto_ver,
    )
    .await
    .map_err(crate::FerrosyncError::Protocol)?;
    crate::protocol::varint::write_varlong30(
        &mut stats_buf,
        stats.total_size as i64,
        3,
        proto_ver,
    )
    .await
    .map_err(crate::FerrosyncError::Protocol)?;
    if proto_ver >= 29 {
        crate::protocol::varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        crate::protocol::varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
    }
    mplex_out
        .write_data(&stats_buf)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .flush()
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    // 6. Read final NDX_DONE from generator (matches rsync's read_final_goodbye).
    if proto_ver >= 24 {
        let _ = crate::protocol::varint::read_ndx(
            &mut demux_read,
            &mut gen_ndx_state,
            proto_ver,
        )
        .await;

        // Proto >= 31: sender reads an additional NDX_DONE from the generator
        // after the goodbye exchange (rsync's read_final_goodbye extra round).
        if proto_ver >= 31 {
            let _ = crate::protocol::varint::read_ndx(
                &mut demux_read,
                &mut gen_ndx_state,
                proto_ver,
            )
            .await;
        }
    }

    let _ = demux_handle.await;

    stats.finish();
    Ok(TransferResult { stats })
}

// ---------------------------------------------------------------------------
// Pull (receiver) flow
// ---------------------------------------------------------------------------

/// Pull remote files to local (we are receiver).
async fn run_pull(
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    protocol: &NegotiatedProtocol,
    options: &TransferOptions,
    fs: &dyn FileSystem,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    // rsync 3.2+ (proto 31+) enables multiplexed I/O immediately after
    // the handshake, both for reading and writing. For protocol >= 30,
    // need_messages_from_generator is set, so rsync expects MUX-framed
    // input from us too.
    let (demux_write, mut demux_read) = tokio::io::duplex(64 * 1024);
    let demux_handle = tokio::spawn(demux_task(reader, demux_write));

    // All output to the remote must be MUX-framed.
    let mut mplex_out = MplexWriter::new(writer);

    // Filter list: for local transport with pull (sender mode on server),
    // rsync enables MUX input before reading filter list. The filter list
    // bytes get consumed as MUX DATA by the sender's MUX layer (effectively
    // as NDX_DONE markers during the phase exchange). This is how real rsync
    // behaves for local transfers.
    let filter_data = collect_filter_list(options)?;
    mplex_out.write_data(&filter_data).await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out.flush().await
        .map_err(crate::FerrosyncError::Protocol)?;

    // Receive file list from remote (through demuxed pipe).
    let received_flist = exchange::recv_file_list(&mut demux_read, protocol, options)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    let entries = received_flist.entries;
    let entry_ndx = received_flist.entry_ndx;
    stats.total_files = entries.len() as u64;

    let total_bytes: i64 = entries.iter().map(|e| e.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    tracing::debug!(count = entries.len(), "received file list");

    let dest = options
        .dest
        .clone()
        .ok_or_else(|| FsError::NotFound {
            path: PathBuf::from("<no destination>"),
        })?;

    let seed = protocol.seed;
    let checksum_type = protocol.checksum;
    let proto_ver = protocol.version;
    let mut gen_ndx_state = crate::protocol::varint::NdxState::default();
    let mut recv_ndx_state = crate::protocol::varint::NdxState::default();

    // Create directories first.
    for entry in &entries {
        if !entry.is_dir() {
            continue;
        }
        let name_str = String::from_utf8_lossy(&entry.name);
        let dest_path = sanitize_path(&dest, &name_str)?;
        if !options.dry_run {
            let mode = if options.preserve_perms {
                entry.mode & 0o7777
            } else {
                0o755
            };
            fs.mkdir(&dest_path, mode)?;
        }
        stats.directories_created += 1;
    }

    // Per-file receiver loop.
    for (idx, entry) in entries.iter().enumerate() {
        if !entry.is_file() {
            continue;
        }

        let name_str = String::from_utf8_lossy(&entry.name);
        let dest_path = sanitize_path(&dest, &name_str)?;

        progress.emit(ProgressEvent::FileStart {
            index: idx as i32,
            name: entry.name.clone(),
            size: entry.len,
        });

        // Create parent directories.
        if let Some(parent) = dest_path.parent() {
            if !fs.lexists(parent) {
                fs.mkdir(parent, 0o755)?;
            }
        }

        if options.dry_run {
            stats.files_transferred += 1;
            stats.total_size += entry.len as u64;
            progress.emit(ProgressEvent::FileComplete {
                index: idx as i32,
                name: entry.name.clone(),
                literal_bytes: entry.len as u64,
                matched_bytes: 0,
            });
            continue;
        }

        // Quick check: skip files that are already up-to-date (same size + mtime).
        // This matches rsync's generator behavior (quick_check_ok).
        // Only skip when preserve_times is set (so mtime was previously synced)
        // and not in checksum mode (which always verifies).
        // Quick check: skip files that are already up-to-date.
        // Matches rsync's cmp_time which compares seconds only.
        if options.preserve_times && !options.checksum_mode {
            if let Ok(dest_meta) = fs.lstat(&dest_path) {
                if dest_meta.len == entry.len && dest_meta.mtime == entry.mtime {
                    // Same size + same mtime (seconds) = already synced, skip.
                    // This only works because our receiver sets mtime after writing.
                    // Files that happen to have the same mtime but different content
                    // (unlikely in practice) will be caught by checksum mode.
                    continue;
                }
            }
        }

        // Read existing basis file (if any).
        let basis_data = fs.read_file(&dest_path).unwrap_or_default();

        // Send generator output to remote (through MUX framing).
        // Wire format: NDX + iflags(2) + sum_head + block sigs.
        let file_ndx = entry_ndx[idx];
        let mut sig_buf = Vec::new();
        crate::protocol::varint::write_ndx(&mut sig_buf, file_ndx, &mut gen_ndx_state, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        // iflags: ITEM_TRANSFER (1<<15) signals that this file needs data transfer.
        if proto_ver >= 29 {
            const ITEM_TRANSFER: u16 = 1 << 15;
            crate::protocol::varint::write_shortint(&mut sig_buf, ITEM_TRANSFER)
                .await
                .map_err(crate::FerrosyncError::Protocol)?;
        }
        let sigs = sum::compute_signatures(&basis_data, seed, checksum_type);
        sum::write_sums(&mut sig_buf, &sigs)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out.write_data(&sig_buf).await
            .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out.flush().await
            .map_err(crate::FerrosyncError::Protocol)?;

        // Read sender's response for this file.
        // Wire format: NDX(file_ndx) + iflags(2 bytes) + sum_head(16 bytes) + tokens + checksum

        // 1. Read file NDX from sender.
        let _file_ndx = crate::protocol::varint::read_ndx(&mut demux_read, &mut recv_ndx_state, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        // 2. Read iflags (protocol >= 29).
        if proto_ver >= 29 {
            use tokio::io::AsyncReadExt;
            let mut iflags_buf = [0u8; 2];
            demux_read.read_exact(&mut iflags_buf).await?;
            let iflags = u16::from_le_bytes(iflags_buf);

            // ITEM_BASIS_TYPE_FOLLOWS (1<<11 = 0x0800)
            if iflags & 0x0800 != 0 {
                let mut bt = [0u8; 1];
                demux_read.read_exact(&mut bt).await?;
            }
            // ITEM_XNAME_FOLLOWS (1<<12 = 0x1000)
            if iflags & 0x1000 != 0 {
                let name_len = crate::protocol::varint::read_varint(&mut demux_read)
                    .await
                    .map_err(crate::FerrosyncError::Protocol)?;
                if name_len > 0x10000 {
                    return Err(crate::FerrosyncError::Protocol(
                        crate::error::ProtocolError::WireValueOutOfRange {
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

        // 3. Read sum_head from sender (count, blength, s2length, remainder).
        let sum_head = sum::read_sum_head(&mut demux_read)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        let blength = if sum_head.blength > 0 {
            sum_head.blength as usize
        } else {
            700
        };

        // 4. Read tokens + file checksum via receiver module.
        let result_data = receiver::recv_file_delta(
            &mut demux_read,
            &basis_data,
            blength,
            seed,
            checksum_type,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

        let literal_bytes = result_data.len() as u64;

        // Write reconstructed file.
        let mode = if options.preserve_perms {
            Some(entry.mode & 0o7777)
        } else {
            None
        };
        fs.write_file(&dest_path, &result_data, mode)?;

        // Set metadata.
        if options.preserve_times {
            if let Err(e) = fs.set_mtime(&dest_path, entry.mtime, entry.mtime_nsec) {
                tracing::warn!(path = %dest_path.display(), error = %e, "failed to set mtime");
            }
        }
        if options.preserve_owner {
            if let Err(e) = fs.set_owner(&dest_path, entry.uid, entry.gid) {
                tracing::warn!(path = %dest_path.display(), error = %e, "failed to set owner");
            }
        }

        stats.files_transferred += 1;
        stats.total_size += entry.len as u64;
        stats.literal_data += literal_bytes;
        stats.bytes_received += literal_bytes;

        progress.emit(ProgressEvent::FileComplete {
            index: idx as i32,
            name: entry.name.clone(),
            literal_bytes,
            matched_bytes: 0,
        });
    }

    // Handle symlinks.
    for entry in &entries {
        if entry.is_symlink() && options.preserve_links {
            let name_str = String::from_utf8_lossy(&entry.name);
            let dest_path = sanitize_path(&dest, &name_str)?;
            if !options.dry_run && !entry.link_target.is_empty() {
                let _ = fs.create_symlink(&entry.link_target, &dest_path);
            }
            stats.symlinks += 1;
        }
    }

    // Multi-phase NDX_DONE exchange.
    // rsync's sender loop expects (max_phase + 1) NDX_DONE messages for phase
    // transitions. With inc_recurse, the sender also needs (num_flists - 1)
    // extra NDX_DONE rounds for flist cleanup (freeing each sub-flist except
    // the last, which gets freed alongside the first phase transition).
    // Total rounds = flist_cleanup + (max_phase + 1).
    // rsync's sender.c: max_phase = protocol_version >= 29 ? 2 : 1
    let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
    let flist_cleanup_rounds: u32 =
        if protocol.incremental_flist && protocol.version >= 30 {
            (received_flist.num_flists as u32).saturating_sub(1)
        } else {
            0
        };
    let total_ndx_rounds = flist_cleanup_rounds + max_phase + 1;

    for _round in 0..total_ndx_rounds {
        let mut done_buf = Vec::new();
        crate::protocol::varint::write_ndx(
            &mut done_buf,
            crate::protocol::varint::NDX_DONE,
            &mut gen_ndx_state,
            proto_ver,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out
            .write_data(&done_buf)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out
            .flush()
            .await
            .map_err(crate::FerrosyncError::Protocol)?;

        // Read sender's NDX_DONE response.
        let resp = crate::protocol::varint::read_ndx(
            &mut demux_read,
            &mut recv_ndx_state,
            proto_ver,
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
        if resp != crate::protocol::varint::NDX_DONE {
            tracing::warn!(ndx = resp, "expected NDX_DONE from sender during phase exchange");
        }
    }

    // Read transfer stats from the sender.
    // sender writes: total_read, total_written, total_size as varlong30(min_bytes=3)
    // plus flist_buildtime, flist_xfertime for proto >= 29.
    let _total_read = crate::protocol::varint::read_varlong30(&mut demux_read, 3, proto_ver)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    let _total_written = crate::protocol::varint::read_varlong30(&mut demux_read, 3, proto_ver)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    let _total_size = crate::protocol::varint::read_varlong30(&mut demux_read, 3, proto_ver)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    if proto_ver >= 29 {
        let _flist_buildtime = crate::protocol::varint::read_varlong30(&mut demux_read, 3, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        let _flist_xfertime = crate::protocol::varint::read_varlong30(&mut demux_read, 3, proto_ver)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
    }

    // Final goodbye exchange (proto >= 24).
    // Best-effort: rsync may close the connection before we finish,
    // which is fine -- the transfer already succeeded at this point.
    if proto_ver >= 24 {
        // Helper: write NDX_DONE, ignoring errors (rsync may have exited).
        async fn send_done(
            out: &mut MplexWriter<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
            st: &mut crate::protocol::varint::NdxState,
            pv: u8,
        ) {
            let mut buf = Vec::new();
            let _ = crate::protocol::varint::write_ndx(
                &mut buf, crate::protocol::varint::NDX_DONE, st, pv,
            ).await;
            let _ = out.write_data(&buf).await;
            let _ = out.flush().await;
        }

        send_done(&mut mplex_out, &mut gen_ndx_state, proto_ver).await;
        let _ = crate::protocol::varint::read_ndx(
            &mut demux_read, &mut recv_ndx_state, proto_ver,
        ).await;
        send_done(&mut mplex_out, &mut gen_ndx_state, proto_ver).await;

        if proto_ver >= 31 {
            send_done(&mut mplex_out, &mut gen_ndx_state, proto_ver).await;
        }
    }

    let _ = demux_handle.await;

    stats.finish();
    Ok(TransferResult { stats })
}

// ---------------------------------------------------------------------------
// Exclusion/filter list exchange
// ---------------------------------------------------------------------------

/// Collect the exclusion/filter list into a byte buffer.
///
/// Sanitize a wire-received filename to prevent path traversal.
///
/// Rejects absolute paths and `..` components. Returns an error if
/// the name would escape the destination directory.
fn sanitize_path(dest: &std::path::Path, name: &str) -> Result<PathBuf> {
    use std::path::Component;

    let path = std::path::Path::new(name);

    // Reject absolute paths.
    if path.is_absolute() {
        return Err(crate::FerrosyncError::Fs(FsError::PermissionDenied {
            path: path.to_path_buf(),
        }));
    }

    // Reject any ".." components.
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(crate::FerrosyncError::Fs(FsError::PermissionDenied {
                path: path.to_path_buf(),
            }));
        }
    }

    Ok(dest.join(name))
}

/// Each rule is a 4-byte LE length followed by the rule string.
/// A zero length terminates the list. The returned bytes are ready
/// to be sent as a MUX DATA frame.
fn collect_filter_list(options: &TransferOptions) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    for pattern in &options.exclude {
        let rule = format!("- {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for pattern in &options.include {
        let rule = format!("+ {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for rule in &options.filter {
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }

    // End of filter list.
    buf.extend_from_slice(&0i32.to_le_bytes());
    Ok(buf)
}


/// Read and discard the exclusion/filter list from the remote receiver.
///
// ---------------------------------------------------------------------------
// File list building helpers
// ---------------------------------------------------------------------------

/// Build FileEntry list from source paths in options.
fn build_source_entries(fs: &dyn FileSystem, options: &TransferOptions) -> Result<Vec<FileEntry>> {
    let source_paths = &options.source;
    let filters = FilterRuleList::from_options(&options.exclude, &options.include, &options.filter)?;

    let mut entries = Vec::new();

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

        if meta.mode & S_IFMT == S_IFDIR && options.recursive {
            collect_directory_entries(fs, source, &[], &mut entries, &filters)?;
        } else {
            let mut entry = meta.to_file_entry(name);
            if entry.is_symlink() {
                entry.link_target = fs.read_link(source).unwrap_or_default();
            }
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Recursively collect directory entries.
fn collect_directory_entries(
    fs: &dyn FileSystem,
    dir_path: &std::path::Path,
    prefix: &[u8],
    entries: &mut Vec<FileEntry>,
    filters: &FilterRuleList,
) -> std::result::Result<(), FsError> {
    let dir_meta = fs.lstat(dir_path)?;
    let dir_name = if prefix.is_empty() {
        b".".to_vec()
    } else {
        prefix.to_vec()
    };
    entries.push(dir_meta.to_file_entry(dir_name));

    let mut children: Vec<DirEntry> = fs.read_dir(dir_path)?;
    children.sort_by(|a, b| a.name.cmp(&b.name));

    for child in children {
        let child_name = if prefix.is_empty() {
            child.name.clone()
        } else {
            let mut n = prefix.to_vec();
            n.push(b'/');
            n.extend(&child.name);
            n
        };

        let is_dir = child.metadata.mode & S_IFMT == S_IFDIR;
        if !filters.is_included(&child_name, is_dir) {
            continue;
        }

        let child_path = dir_path.join(std::str::from_utf8(&child.name).unwrap_or("?"));

        if is_dir {
            collect_directory_entries(fs, &child_path, &child_name, entries, filters)?;
        } else {
            let mut entry = child.metadata.to_file_entry(child_name);
            if entry.is_symlink() {
                entry.link_target = fs.read_link(&child_path).unwrap_or_default();
            }
            entries.push(entry);
        }
    }

    Ok(())
}

/// Read source file data for a given file entry.
fn read_source_file(
    fs: &dyn FileSystem,
    entry: &FileEntry,
    options: &TransferOptions,
) -> Result<Vec<u8>> {
    let name_str = String::from_utf8_lossy(&entry.name);
    for source in &options.source {
        let path = if options.source.len() == 1
            && fs
                .lstat(source)
                .is_ok_and(|m| m.mode & S_IFMT == S_IFDIR)
        {
            source.join(name_str.as_ref())
        } else {
            source.clone()
        };
        if let Ok(data) = fs.read_file(&path) {
            return Ok(data);
        }
    }
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Demux background task
// ---------------------------------------------------------------------------

/// Background task that reads multiplexed frames from the wire and forwards
/// MSG_DATA payloads to a pipe. Control messages are logged/handled separately.
///
/// This allows the existing generator/sender/receiver protocol code to read
/// from the pipe as a plain `AsyncRead` stream, transparently demultiplexing.
async fn demux_task(
    reader: Box<dyn AsyncRead + Unpin + Send>,
    mut pipe: tokio::io::DuplexStream,
) {
    let mut mplex = MplexReader::new(reader);

    loop {
        match mplex.read_message().await {
            Ok(MplexMessage::Data(data)) => {
                if AsyncWriteExt::write_all(&mut pipe, &data).await.is_err() {
                    break;
                }
            }
            Ok(msg) => {
                handle_control_message(&msg);
            }
            Err(e) => {
                tracing::debug!(error = %e, "demux stream ended");
                break;
            }
        }
    }
}

/// Handle a control message from the multiplexed stream.
fn handle_control_message(msg: &MplexMessage) {
    match msg {
        MplexMessage::Info(text) => {
            tracing::info!(remote = %text.trim(), "remote info");
        }
        MplexMessage::Warning(text) => {
            tracing::warn!(remote = %text.trim(), "remote warning");
        }
        MplexMessage::Error { code, text } => {
            tracing::error!(code = ?code, remote = %text.trim(), "remote error");
        }
        MplexMessage::Log(text) => {
            tracing::debug!(remote = %text.trim(), "remote log");
        }
        MplexMessage::Noop => {}
        _ => {
            tracing::trace!(msg = ?msg, "control message");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::{DeleteMode, Verbosity};

    #[test]
    fn test_build_server_options_archive() {
        let opts = TransferOptions::builder().archive().build();
        let s = build_server_options(&opts, true);
        assert!(s.contains('l'), "missing -l (links)");
        assert!(s.contains('o'), "missing -o (owner)");
        assert!(s.contains('g'), "missing -g (group)");
        assert!(s.contains('D'), "missing -D (devices)");
        assert!(s.contains('t'), "missing -t (times)");
        assert!(s.contains('p'), "missing -p (perms)");
        assert!(s.contains('r'), "missing -r (recursive)");
        assert!(s.contains("e."), "missing capability string");
    }

    #[test]
    fn test_build_server_options_compress() {
        let opts = TransferOptions::builder().compress(true).build();
        let s = build_server_options(&opts, true);
        assert!(s.contains('z'), "missing -z (compress)");
    }

    #[test]
    fn test_build_server_options_dry_run() {
        let opts = TransferOptions::builder().dry_run(true).build();
        let s = build_server_options(&opts, true);
        assert!(s.contains('n'), "missing -n (dry-run)");
    }

    #[test]
    fn test_build_server_options_delete() {
        let opts = TransferOptions::builder()
            .delete(DeleteMode::During)
            .build();
        let s = build_server_options(&opts, true);
        assert!(s.contains("--delete-during"));
    }

    #[test]
    fn test_build_server_options_verbose() {
        let opts = TransferOptions {
            verbosity: Verbosity::VeryVerbose,
            ..Default::default()
        };
        let s = build_server_options(&opts, true);
        assert!(s.contains("vv"), "missing -vv");
    }

    #[test]
    fn test_build_server_options_minimal() {
        let opts = TransferOptions::default();
        let s = build_server_options(&opts, true);
        assert!(s.starts_with('-'));
        assert!(s.contains("e."));
    }

    #[test]
    fn test_sync_direction_eq() {
        assert_eq!(SyncDirection::Push, SyncDirection::Push);
        assert_ne!(SyncDirection::Push, SyncDirection::Pull);
    }
}
