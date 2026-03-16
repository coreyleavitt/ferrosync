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
use std::sync::Arc;

use tokio::io::AsyncRead;

use crate::engine::progress::{ProgressEvent, ProgressTracker};
use crate::engine::wire_transfer::{self, LocalFileOps, LocalFileReader};
use crate::error::FsError;
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT};
use crate::filelist::exchange;
use crate::filter::FilterRuleList;
use crate::fs::FileSystem;
use crate::options::{DeleteMode, TransferOptions};
use crate::protocol::handshake::{self, build_capability_string, NegotiatedProtocol};
use crate::protocol::multiplex::MplexWriter;
use crate::stats::TransferStats;
use crate::transport::Transport;

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
    if opts.preserve_links() {
        s.push('l');
    }
    if opts.preserve_owner() {
        s.push('o');
    }
    if opts.preserve_group() {
        s.push('g');
    }
    if opts.preserve_devices() || opts.preserve_specials() {
        s.push('D');
    }
    if opts.preserve_times() {
        s.push('t');
    }
    if opts.preserve_perms() {
        s.push('p');
    }
    if opts.recursive() {
        s.push('r');
    }
    if opts.compress() {
        s.push('z');
    }
    if opts.checksum_mode() {
        s.push('c');
    }
    if opts.update() {
        s.push('u');
    }
    if opts.dry_run() {
        s.push('n');
    }
    if opts.whole_file() {
        s.push('W');
    }
    if opts.one_file_system() {
        s.push('x');
    }
    if opts.sparse() {
        s.push('S');
    }
    match opts.verbosity() {
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
    let use_inc_recurse = opts.recursive() && !_am_sender;
    let caps = build_capability_string(use_inc_recurse, true, false);
    s.push('e');
    s.push_str(&caps);

    // Long-form options are separate arguments appended after the
    // condensed string.
    if opts.inplace() {
        s.push_str(" --inplace");
    }
    if opts.numeric_ids() {
        s.push_str(" --numeric-ids");
    }
    if opts.append() {
        s.push_str(" --append");
    }

    match opts.delete() {
        DeleteMode::Before => s.push_str(" --delete-before"),
        DeleteMode::During => s.push_str(" --delete-during"),
        DeleteMode::After => s.push_str(" --delete-after"),
        DeleteMode::Excluded => s.push_str(" --delete-excluded"),
        DeleteMode::None => {}
    }

    s
}

/// Parse the condensed option string from `rsync --server` arguments.
///
/// This is the inverse of [`build_server_options`]. The server uses it to
/// reconstruct a [`TransferOptions`] from the flags the client sent. The
/// `module_path` is used as the dest (for receive) or source (for send).
pub fn parse_server_args(
    args: &[String],
    module_path: std::path::PathBuf,
    am_sender: bool,
) -> TransferOptions {
    let mut builder = TransferOptions::builder();

    // Find the condensed option string (starts with `-`, not `--`).
    let mut condensed = "";
    let mut long_opts: Vec<&str> = Vec::new();
    for arg in args {
        if arg == "--server" || arg == "--sender" || arg == "." {
            continue;
        }
        if arg.starts_with("--") {
            long_opts.push(arg);
        } else if arg.starts_with('-') && condensed.is_empty() {
            condensed = arg;
        }
    }

    // Parse single-char flags (everything before 'e' which starts the
    // capability string).
    let flags_part = if let Some(pos) = condensed.find('e') {
        &condensed[1..pos]
    } else {
        &condensed[1..]
    };

    for ch in flags_part.chars() {
        match ch {
            'l' => {
                builder = builder.preserve_links(true);
            }
            'o' => {
                builder = builder.preserve_owner(true);
            }
            'g' => {
                builder = builder.preserve_group(true);
            }
            'D' => {
                builder = builder.preserve_devices(true).preserve_specials(true);
            }
            't' => {
                builder = builder.preserve_times(true);
            }
            'p' => {
                builder = builder.preserve_perms(true);
            }
            'r' => {
                builder = builder.recursive(true);
            }
            'z' => {
                builder = builder.compress(true);
            }
            'c' => {
                builder = builder.checksum_mode(true);
            }
            'u' => {
                builder = builder.update(true);
            }
            'n' => {
                builder = builder.dry_run(true);
            }
            'W' => {
                builder = builder.whole_file(true);
            }
            'x' => {
                builder = builder.one_file_system(true);
            }
            'S' => {
                builder = builder.sparse(true);
            }
            'v' => {
                // Verbosity is cumulative but we just set it once here.
                // Multiple v's are handled by the Verbosity enum already
                // being set.
                builder = builder.verbosity(crate::options::Verbosity::Verbose);
            }
            _ => {}
        }
    }

    // Parse long-form options.
    for opt in &long_opts {
        match *opt {
            "--inplace" => {
                builder = builder.inplace(true);
            }
            "--numeric-ids" => {
                builder = builder.numeric_ids(true);
            }
            "--append" => {
                builder = builder.append(true);
            }
            "--delete-before" => {
                builder = builder.delete(DeleteMode::Before);
            }
            "--delete-during" => {
                builder = builder.delete(DeleteMode::During);
            }
            "--delete-after" => {
                builder = builder.delete(DeleteMode::After);
            }
            "--delete-excluded" => {
                builder = builder.delete(DeleteMode::Excluded);
            }
            _ => {}
        }
    }

    // Set source/dest based on direction.
    if am_sender {
        builder = builder.source(module_path);
    } else {
        builder = builder.dest(module_path);
    }

    builder.build()
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
/// let config = DaemonTransportConfig { host: "server".into(), module: "data".into(), ..Default::default() };
/// let transport = DaemonTransport::new(config, true, &server_opts);
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
        let mut streams = Box::new(transport).connect().await?;

        let am_sender = direction == SyncDirection::Push;

        // 2. Protocol handshake (non-multiplexed phase).
        let protocol = handshake::client_handshake(
            &mut streams.reader,
            &mut streams.writer,
            am_sender,
            options.compress(),
        )
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

        tracing::info!(
            version = protocol.version,
            checksum = ?protocol.checksum,
            compress = ?protocol.compress,
            incremental = protocol.wire.supports_incremental_flist,
            seed = protocol.seed,
            "handshake complete"
        );

        // 3. Exchange file lists and transfer.
        // Take ownership of reader/writer, keeping background_task alive.
        let reader = std::mem::replace(&mut streams.reader, Box::new(tokio::io::empty()));
        let writer = std::mem::replace(&mut streams.writer, Box::new(tokio::io::sink()));
        // Keep streams alive so background_task is not aborted.
        let _streams_guard = streams;

        let fs: Arc<dyn FileSystem> = fs.into();
        if am_sender {
            run_push(reader, writer, &protocol, &options, &*fs, &mut progress).await
        } else {
            run_pull(reader, writer, &protocol, &options, fs, &mut progress).await
        }
    }
}

// ---------------------------------------------------------------------------
// Push (sender) flow
// ---------------------------------------------------------------------------

/// Push local files to remote (we are sender).
///
/// Protocol flow traced from rsync 3.1.3 C source (main.c:1146, client_run):
///
/// 1. io_start_multiplex_out (main.c:1146) -- both sides enable MUX after handshake
/// 2. io_start_multiplex_in  (main.c:1148)
/// 3. send_filter_list       (exclude.c:1377) -- CONDITIONAL, see below
/// 4. send_file_list         (flist.c)
/// 5. io_flush               (io.c)
/// 6. send_files             (sender.c) -- sender loop
/// 7. write stats            (main.c)
/// 8. goodbye exchange       (io.c)
///
/// Filter list condition (exclude.c:1377-1411):
///   For SSH push without --delete (and no --prune-empty-dirs, no inc_recurse
///   extra), neither side sends nor reads the filter list. The condition on
///   the sender side is: `delete_mode || prune_empty_dirs || inc_recurse_extra`.
///   We simplify to `delete_mode != None` since we don't support prune/inc_extra.
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

    // Both sides enable MUX after handshake (proto >= 30).
    // C ref: io_start_multiplex_out (main.c:1146)
    //
    // Uses an unbounded channel instead of a bounded duplex pipe to prevent
    // bidirectional deadlock on large transfers. See start_demux docs.
    let (mut demux_read, demux_handle) = start_demux(reader);
    let mut mplex_out = MplexWriter::new(writer);

    // Send filter list (MUX-framed) -- CONDITIONAL.
    //
    // C ref: exclude.c:1672-1697 (recv_filter_list)
    //
    // rsync's recv_filter_list reads from the wire ONLY when:
    //   !local_server && (am_sender || receiver_wants_list)
    //
    // For server receiver (our push target): am_sender=0 on the server.
    // receiver_wants_list = prune_empty_dirs || (delete_mode && ...).
    // So the server reads the filter list ONLY when delete or prune is active.
    // This is true for BOTH local_server=0 (SSH) and local_server=1 (local).
    //
    // For server sender (our pull target): am_sender=1, always reads filter list.
    // (Handled in run_pull which always sends it.)
    let send_filter_list = options.delete() != DeleteMode::None;
    tracing::debug!(send_filter_list, delete_mode = ?options.delete(), "push: filter list decision");
    if send_filter_list {
        let filter_data = collect_filter_list(options)?;
        tracing::debug!(len = filter_data.len(), "push: sending filter list");
        mplex_out
            .write_data(&filter_data)
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
        mplex_out
            .flush()
            .await
            .map_err(crate::FerrosyncError::Protocol)?;
    }

    // Build and send file list (MUX-framed).
    // C ref: send_file_list (flist.c), called from main.c:1153
    let mut entries = build_source_entries(fs, options)?;
    crate::filelist::sort::canonical_sort(&mut entries);
    stats.total_files = entries.len() as u64;
    let total_bytes: i64 = entries.iter().map(|e| e.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    let mut flist_buf = Vec::new();
    exchange::send_file_list(&mut flist_buf, &entries, protocol, options)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    tracing::debug!(
        entries = entries.len(),
        flist_bytes = flist_buf.len(),
        "push: sending file list"
    );

    mplex_out
        .write_data(&flist_buf)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .flush()
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    // Sender loop via wire_transfer.
    // C ref: send_files (sender.c), called from main.c:1157
    let ndx_map = wire_transfer::build_ndx_map(&entries, protocol, options.recursive());
    let file_reader = LocalFileReader::new(fs, options.source());

    wire_transfer::sender_loop(
        &mut demux_read,
        &mut mplex_out,
        &entries,
        &ndx_map,
        &file_reader,
        protocol,
        &mut stats,
        progress,
    )
    .await?;

    // C ref: handle_stats (main.c:325) -- client sender does NOT write stats.
    // Stats are only written by the server sender (am_server && am_sender).
    // For push (client is sender, am_server=false), handle_stats(-1) is a no-op.

    // Goodbye exchange.
    wire_transfer::sender_goodbye(&mut demux_read, &mut mplex_out, protocol).await?;

    let _ = demux_handle.await;

    stats.finish();
    Ok(TransferResult { stats })
}

// ---------------------------------------------------------------------------
// Pull (receiver) flow
// ---------------------------------------------------------------------------

/// Pull remote files to local (we are receiver).
///
/// Protocol flow traced from rsync 3.1.3 C source (main.c:985, client_run):
///
/// 1. io_start_multiplex_in  (main.c:985)  -- enable MUX for reading
/// 2. send_filter_list       (exclude.c)   -- ALWAYS sent for pull (sender reads it)
/// 3. recv_file_list         (flist.c)     -- receive file list from sender
/// 4. io_start_multiplex_out (main.c:1003) -- enable MUX for writing AFTER recv
/// 5. do_recv                (receiver.c)  -- generator + receiver loop
/// 6. phase exchange         (io.c)
/// 7. read stats             (main.c)
/// 8. goodbye exchange       (io.c)
///
/// Filter list: For pull, rsync's sender side always calls recv_filter_list()
/// (exclude.c:1377 -- the `am_sender` path reads unconditionally). We must
/// always send it.
async fn run_pull(
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    protocol: &NegotiatedProtocol,
    options: &TransferOptions,
    fs: Arc<dyn FileSystem>,
    progress: &mut ProgressTracker,
) -> Result<TransferResult> {
    let mut stats = TransferStats::new();
    stats.start();

    // Uses unbounded channel demux to prevent bidirectional deadlock.
    let (mut demux_read, demux_handle) = start_demux(reader);
    let mut mplex_out = MplexWriter::new(writer);

    // Send filter list -- always for pull.
    // C ref: exclude.c:1377 -- sender's recv_filter_list() always reads.
    let filter_data = collect_filter_list(options)?;
    tracing::debug!(len = filter_data.len(), "pull: sending filter list");
    mplex_out
        .write_data(&filter_data)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    mplex_out
        .flush()
        .await
        .map_err(crate::FerrosyncError::Protocol)?;

    // Receive file list from remote.
    // C ref: recv_file_list (flist.c), called from main.c:992
    let received_flist = exchange::recv_file_list(&mut demux_read, protocol, options)
        .await
        .map_err(crate::FerrosyncError::Protocol)?;
    let entries = received_flist.entries;
    let entry_ndx = received_flist.entry_ndx;
    stats.total_files = entries.len() as u64;

    let total_bytes: i64 = entries.iter().map(|e| e.len).sum();
    progress.set_totals(stats.total_files, total_bytes as u64);

    tracing::debug!(count = entries.len(), "received file list");

    let dest = options.dest().cloned().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no destination>"),
    })?;

    // Validate paths before passing to receiver loop.
    for entry in &entries {
        let name_str = String::from_utf8_lossy(&entry.name);
        sanitize_path(&dest, &name_str)?;
    }

    // Handle dry-run: just count files, don't do wire protocol.
    if options.dry_run() {
        for (idx, entry) in entries.iter().enumerate() {
            if entry.is_dir() {
                stats.directories_created += 1;
            } else if entry.is_file() {
                stats.files_transferred += 1;
                stats.total_size += entry.len as u64;
                progress.emit(ProgressEvent::FileComplete {
                    index: idx as i32,
                    name: crate::engine::progress::name_to_pathbuf(&entry.name),
                    literal_bytes: entry.len as u64,
                    matched_bytes: 0,
                });
            }
        }
    } else {
        // Pipelined receiver loop: generator and receiver run concurrently.
        let file_ops: Arc<dyn wire_transfer::FileOps> = Arc::new(LocalFileOps::new(
            Arc::clone(&fs),
            dest.clone(),
            options.clone(),
        ));

        let (dr, mo) = wire_transfer::receiver_loop_pipelined(
            demux_read, mplex_out, &entries, &entry_ndx, file_ops, protocol, &mut stats, progress,
        )
        .await?;
        demux_read = dr;
        mplex_out = mo;

        // Handle symlinks (after file transfers).
        for entry in &entries {
            if entry.is_symlink() && options.preserve_links() {
                let name_str = String::from_utf8_lossy(&entry.name);
                let dest_path = dest.join(name_str.as_ref());
                if !entry.link_target.is_empty() {
                    let _ = fs.create_symlink(&entry.link_target, &dest_path);
                }
                stats.symlinks += 1;
            }
        }
    }

    // Phase exchange.
    wire_transfer::receiver_phase_exchange(
        &mut demux_read,
        &mut mplex_out,
        protocol,
        received_flist.num_flists,
    )
    .await?;

    // Read transfer stats.
    wire_transfer::read_stats(&mut demux_read, protocol).await?;

    // Goodbye exchange.
    wire_transfer::receiver_goodbye(&mut demux_read, &mut mplex_out, protocol).await?;

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

    for pattern in options.exclude() {
        let rule = format!("- {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for pattern in options.include() {
        let rule = format!("+ {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for rule in options.filter() {
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }

    // End of filter list.
    buf.extend_from_slice(&0i32.to_le_bytes());
    Ok(buf)
}

// ---------------------------------------------------------------------------
// File list building helpers
// ---------------------------------------------------------------------------

/// Build FileEntry list from source paths in options.
fn build_source_entries(fs: &dyn FileSystem, options: &TransferOptions) -> Result<Vec<FileEntry>> {
    let source_paths = options.source();
    let filters =
        FilterRuleList::from_options(options.exclude(), options.include(), options.filter())?;

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

        if meta.mode & S_IFMT == S_IFDIR && options.recursive() {
            crate::filelist::walk::collect_directory_entries(
                fs,
                source,
                &[],
                &mut entries,
                &filters,
            )?;
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

// Use the unbounded-channel demux to prevent bidirectional I/O deadlock.
use crate::protocol::multiplex::start_demux;

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
        let opts = TransferOptions::builder()
            .verbosity(Verbosity::VeryVerbose)
            .build();
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
