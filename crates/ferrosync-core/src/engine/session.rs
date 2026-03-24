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

use crate::engine::delete;
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
/// Build the argument list for `rsync --server`.
///
/// Returns a vector of separate arguments: the condensed single-char flag
/// string (including the `e`-prefixed capability string) as the first
/// element, followed by any long-form options as individual elements.
/// Each element maps to one `argv` entry on the remote side.
pub fn build_server_options(opts: &TransferOptions, _am_sender: bool) -> Vec<String> {
    let mut condensed = String::from("-");

    // Single-char flags MUST come before the capability string, because
    // rsync's option parser treats `e` as consuming the rest of the arg
    // as its value.
    if opts.preserve_links() {
        condensed.push('l');
    }
    if opts.preserve_owner() {
        condensed.push('o');
    }
    if opts.preserve_group() {
        condensed.push('g');
    }
    if opts.preserve_devices() || opts.preserve_specials() {
        condensed.push('D');
    }
    if opts.preserve_times() {
        condensed.push('t');
    }
    if opts.preserve_perms() {
        condensed.push('p');
    }
    if opts.recursive() {
        condensed.push('r');
    }
    if opts.compress() {
        condensed.push('z');
    }
    if opts.checksum_mode() {
        condensed.push('c');
    }
    if opts.update() {
        condensed.push('u');
    }
    if opts.dry_run() {
        condensed.push('n');
    }
    if opts.whole_file() {
        condensed.push('W');
    }
    if opts.one_file_system() {
        condensed.push('x');
    }
    if opts.sparse() {
        condensed.push('S');
    }
    if opts.ignore_times() {
        condensed.push('I');
    }
    if opts.prune_empty_dirs() {
        condensed.push('m');
    }
    if opts.relative() {
        condensed.push('R');
    }
    if opts.copy_links() {
        condensed.push('L');
    }
    if opts.keep_dirlinks() {
        condensed.push('K');
    }
    if opts.dirs() {
        condensed.push('d');
    }
    if opts.cvs_exclude() {
        condensed.push('C');
    }
    if opts.fuzzy() {
        condensed.push('y');
    }
    if opts.preserve_hard_links() {
        condensed.push('H');
    }
    if opts.preserve_acls() {
        condensed.push('A');
    }
    if opts.preserve_xattrs() {
        condensed.push('X');
    }
    for _ in 0..opts.filter_merge_files() {
        condensed.push('F');
    }
    match opts.verbosity() {
        crate::options::Verbosity::Quiet => condensed.push('q'),
        crate::options::Verbosity::Verbose => condensed.push('v'),
        crate::options::Verbosity::VeryVerbose => {
            condensed.push('v');
            condensed.push('v');
        }
        crate::options::Verbosity::Debug => {
            condensed.push('v');
            condensed.push('v');
            condensed.push('v');
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
    condensed.push('e');
    condensed.push_str(&caps);

    let mut args = vec![condensed];

    // Long-form options: each must be its own argument so the remote
    // rsync parses them correctly (they cannot be embedded in the
    // condensed string because `e` consumes the rest of that arg).
    if opts.inplace() {
        args.push("--inplace".into());
    }
    if opts.numeric_ids() {
        args.push("--numeric-ids".into());
    }
    if opts.append() {
        args.push("--append".into());
    }
    if opts.size_only() {
        args.push("--size-only".into());
    }
    if opts.existing() {
        args.push("--existing".into());
    }
    if opts.ignore_existing() {
        args.push("--ignore-existing".into());
    }
    if let Some(n) = opts.max_delete() {
        args.push(format!("--max-delete={n}"));
    }
    if opts.safe_links() {
        args.push("--safe-links".into());
    }
    if opts.remove_source_files() {
        args.push("--remove-source-files".into());
    }
    if opts.append_verify() {
        args.push("--append-verify".into());
    }
    if opts.modify_window() > 0 {
        args.push(format!("--modify-window={}", opts.modify_window()));
    }
    if let Some(n) = opts.block_size() {
        args.push(format!("--block-size={n}"));
    }
    for spec in opts.chmod() {
        args.push(format!("--chmod={spec}"));
    }
    if opts.chown_uid().is_some() || opts.chown_gid().is_some() {
        let uid = opts.chown_uid().map_or(String::new(), |u| u.to_string());
        let gid = opts.chown_gid().map_or(String::new(), |g| g.to_string());
        args.push(format!("--chown={uid}:{gid}"));
    }
    for path in opts.exclude_from() {
        args.push(format!("--exclude-from={}", path.display()));
    }
    for path in opts.include_from() {
        args.push(format!("--include-from={}", path.display()));
    }

    if opts.partial() {
        args.push("--partial".into());
    }
    if let Some(pd) = opts.partial_dir() {
        args.push(format!("--partial-dir={}", pd.display()));
    }
    if opts.list_only() {
        args.push("--list-only".into());
    }
    if opts.fake_super() {
        args.push("--fake-super".into());
    }

    match opts.delete() {
        DeleteMode::Before => args.push("--delete-before".into()),
        DeleteMode::During => args.push("--delete-during".into()),
        DeleteMode::After => args.push("--delete-after".into()),
        DeleteMode::Excluded => args.push("--delete-excluded".into()),
        DeleteMode::None => {}
    }

    if _am_sender {
        for dir in opts.link_dest() {
            args.push(format!("--link-dest={}", dir.display()));
        }
    }

    args
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

    let mut filter_merge_count = 0u8;
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
            'I' => {
                builder = builder.ignore_times(true);
            }
            'm' => {
                builder = builder.prune_empty_dirs(true);
            }
            'L' => {
                builder = builder.copy_links(true);
            }
            'K' => {
                builder = builder.keep_dirlinks(true);
            }
            'd' => {
                builder = builder.dirs(true);
            }
            'R' => {
                builder = builder.relative(true);
            }
            'C' => {
                builder = builder.cvs_exclude(true);
            }
            'y' => {
                builder = builder.fuzzy(true);
            }
            'F' => {
                filter_merge_count = filter_merge_count.saturating_add(1);
            }
            'H' => {
                builder = builder.preserve_hard_links(true);
            }
            'A' => {
                builder = builder.preserve_acls(true);
            }
            'X' => {
                builder = builder.preserve_xattrs(true);
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

    if filter_merge_count > 0 {
        builder = builder.filter_merge_files(filter_merge_count);
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
            "--size-only" => {
                builder = builder.size_only(true);
            }
            "--existing" => {
                builder = builder.existing(true);
            }
            "--ignore-existing" => {
                builder = builder.ignore_existing(true);
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
            "--safe-links" => {
                builder = builder.safe_links(true);
            }
            "--list-only" => {
                builder = builder.list_only(true);
            }
            "--fake-super" => {
                builder = builder.fake_super(true);
            }
            "--remove-source-files" => {
                builder = builder.remove_source_files(true);
            }
            "--partial" => {
                builder = builder.partial(true);
            }
            "--append-verify" => {
                builder = builder.append_verify(true);
            }
            _ if opt.starts_with("--max-delete=") => {
                let n = &opt["--max-delete=".len()..];
                if let Ok(val) = n.parse::<u64>() {
                    builder = builder.max_delete(val);
                }
            }
            _ if opt.starts_with("--modify-window=") => {
                let n = &opt["--modify-window=".len()..];
                if let Ok(val) = n.parse::<u32>() {
                    builder = builder.modify_window(val);
                }
            }
            _ if opt.starts_with("--block-size=") => {
                let n = &opt["--block-size=".len()..];
                if let Ok(val) = n.parse::<i32>() {
                    builder = builder.block_size(val);
                }
            }
            _ if opt.starts_with("--chmod=") => {
                let spec = &opt["--chmod=".len()..];
                builder = builder.chmod(spec);
            }
            _ if opt.starts_with("--chown=") => {
                let val = &opt["--chown=".len()..];
                if let Some((uid_s, gid_s)) = val.split_once(':') {
                    if let Ok(uid) = uid_s.parse::<u32>() {
                        builder = builder.chown_uid(uid);
                    }
                    if let Ok(gid) = gid_s.parse::<u32>() {
                        builder = builder.chown_gid(gid);
                    }
                }
            }
            _ if opt.starts_with("--exclude-from=") => {
                let path = &opt["--exclude-from=".len()..];
                builder = builder.exclude_from(std::path::PathBuf::from(path));
            }
            _ if opt.starts_with("--include-from=") => {
                let path = &opt["--include-from=".len()..];
                builder = builder.include_from(std::path::PathBuf::from(path));
            }
            _ if opt.starts_with("--link-dest=") => {
                let dir = &opt["--link-dest=".len()..];
                builder = builder.link_dest(std::path::PathBuf::from(dir));
            }
            _ if opt.starts_with("--partial-dir=") => {
                let dir = &opt["--partial-dir=".len()..];
                builder = builder.partial_dir(std::path::PathBuf::from(dir));
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
    let send_filter_list = options.delete() != DeleteMode::None || options.prune_empty_dirs();
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

    // --list-only: print file list and return without transferring.
    if options.list_only() {
        for entry in &entries {
            println!("{}", entry.format_list_entry());
        }
        // Skip sender loop but complete protocol.
        wire_transfer::sender_goodbye(&mut demux_read, &mut mplex_out, protocol).await?;
        let _ = demux_handle.await;
        stats.finish();
        return Ok(TransferResult { stats });
    }

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
        options.block_size(),
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

    // --list-only: print file list and return without transferring.
    if options.list_only() {
        for entry in &entries {
            println!("{}", entry.format_list_entry());
        }
        // Skip transfer but complete protocol handshake.
        wire_transfer::receiver_phase_exchange(
            &mut demux_read,
            &mut mplex_out,
            protocol,
            received_flist.num_flists,
        )
        .await?;
        wire_transfer::read_stats(&mut demux_read, protocol).await?;
        wire_transfer::receiver_goodbye(&mut demux_read, &mut mplex_out, protocol).await?;
        let _ = demux_handle.await;
        stats.finish();
        return Ok(TransferResult { stats });
    }

    // Delete extraneous files before/during the transfer.
    let mut filters =
        FilterRuleList::from_options(options.exclude(), options.include(), options.filter())?;
    if options.cvs_exclude() {
        filters.add_cvs_excludes();
    }
    for path in options.exclude_from() {
        filters.add_excludes_from_file(path)?;
    }
    for path in options.include_from() {
        filters.add_includes_from_file(path)?;
    }
    let delete_excluded = options.delete() == DeleteMode::Excluded;
    let delete_budget = delete::DeleteBudget::new(options.max_delete());
    let deleter = delete::Deleter::new(
        &*fs,
        &filters,
        &delete_budget,
        options.dry_run(),
        delete_excluded,
    );

    if matches!(
        options.delete(),
        DeleteMode::Before | DeleteMode::During | DeleteMode::Excluded
    ) {
        let deleted = deleter.delete_extraneous(&dest, entries.iter())?;
        stats.files_deleted = deleted;
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
            demux_read,
            mplex_out,
            &entries,
            &entry_ndx,
            file_ops,
            protocol,
            &mut stats,
            progress,
            options.block_size(),
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

    // Delete extraneous files after the transfer.
    if options.delete() == DeleteMode::After {
        let deleted = deleter.delete_extraneous(&dest, entries.iter())?;
        stats.files_deleted = deleted;
    }

    // Handle --prune-empty-dirs (-m).
    if options.prune_empty_dirs() {
        let pruned = delete::prune_empty_dirs(&*fs, &dest, options.dry_run())?;
        stats.files_deleted += pruned;
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
    let mut filters =
        FilterRuleList::from_options(options.exclude(), options.include(), options.filter())?;
    if options.cvs_exclude() {
        filters.add_cvs_excludes();
    }
    for path in options.exclude_from() {
        filters.add_excludes_from_file(path)?;
    }
    for path in options.include_from() {
        filters.add_includes_from_file(path)?;
    }

    let mut entries = Vec::new();

    for source in source_paths {
        let meta = if options.copy_links() {
            match fs.stat(source) {
                Ok(m) => m,
                Err(_) => {
                    tracing::warn!(path = %source.display(), "skipping broken symlink");
                    continue;
                }
            }
        } else {
            fs.lstat(source)?
        };
        let name = crate::filelist::entry::compute_entry_name(source, options.relative());

        if !filters.is_included(&name, meta.mode & S_IFMT == S_IFDIR) {
            continue;
        }

        if meta.mode & S_IFMT == S_IFDIR && options.recursive() {
            let prefix = if options.relative() {
                name.clone()
            } else {
                Vec::new()
            };
            let walk_opts = crate::filelist::walk::WalkOptions {
                copy_links: options.copy_links(),
                one_file_system: false,
                filter_merge_files: options.filter_merge_files(),
            };
            crate::filelist::walk::collect_directory_entries(
                fs,
                source,
                &prefix,
                &mut entries,
                &mut filters,
                &walk_opts,
            )?;
        } else {
            let mut entry = meta.to_file_entry(name);
            if !options.copy_links() && entry.is_symlink() {
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

    /// The condensed flag string (first element of the args vector).
    fn condensed(args: &[String]) -> &str {
        &args[0]
    }

    /// Check if a long-form option is present in the args vector.
    fn has_long(args: &[String], opt: &str) -> bool {
        args.iter().any(|a| a == opt)
    }

    /// Check if any long-form option starts with the given prefix.
    fn has_long_prefix(args: &[String], prefix: &str) -> bool {
        args.iter().any(|a| a.starts_with(prefix))
    }

    #[test]
    fn test_build_server_options_archive() {
        let opts = TransferOptions::builder().archive().build();
        let args = build_server_options(&opts, true);
        let c = condensed(&args);
        assert!(c.contains('l'), "missing -l (links)");
        assert!(c.contains('o'), "missing -o (owner)");
        assert!(c.contains('g'), "missing -g (group)");
        assert!(c.contains('D'), "missing -D (devices)");
        assert!(c.contains('t'), "missing -t (times)");
        assert!(c.contains('p'), "missing -p (perms)");
        assert!(c.contains('r'), "missing -r (recursive)");
        assert!(c.contains("e."), "missing capability string");
    }

    #[test]
    fn test_build_server_options_compress() {
        let opts = TransferOptions::builder().compress(true).build();
        let args = build_server_options(&opts, true);
        assert!(condensed(&args).contains('z'), "missing -z (compress)");
    }

    #[test]
    fn test_build_server_options_dry_run() {
        let opts = TransferOptions::builder().dry_run(true).build();
        let args = build_server_options(&opts, true);
        assert!(condensed(&args).contains('n'), "missing -n (dry-run)");
    }

    #[test]
    fn test_build_server_options_delete() {
        let opts = TransferOptions::builder()
            .delete(DeleteMode::During)
            .build();
        let args = build_server_options(&opts, true);
        assert!(has_long(&args, "--delete-during"));
    }

    #[test]
    fn test_build_server_options_verbose() {
        let opts = TransferOptions::builder()
            .verbosity(Verbosity::VeryVerbose)
            .build();
        let args = build_server_options(&opts, true);
        assert!(condensed(&args).contains("vv"), "missing -vv");
    }

    #[test]
    fn test_build_server_options_minimal() {
        let opts = TransferOptions::default();
        let args = build_server_options(&opts, true);
        assert!(condensed(&args).starts_with('-'));
        assert!(condensed(&args).contains("e."));
    }

    #[test]
    fn test_sync_direction_eq() {
        assert_eq!(SyncDirection::Push, SyncDirection::Push);
        assert_ne!(SyncDirection::Push, SyncDirection::Pull);
    }

    #[test]
    fn test_build_server_options_ignore_times() {
        let opts = TransferOptions::builder().ignore_times(true).build();
        let args = build_server_options(&opts, true);
        assert!(condensed(&args).contains('I'), "missing -I (ignore-times)");
    }

    #[test]
    fn test_build_server_options_prune_empty_dirs() {
        let opts = TransferOptions::builder().prune_empty_dirs(true).build();
        let args = build_server_options(&opts, true);
        assert!(
            condensed(&args).contains('m'),
            "missing -m (prune-empty-dirs)"
        );
    }

    #[test]
    fn test_build_server_options_size_only() {
        let opts = TransferOptions::builder().size_only(true).build();
        let args = build_server_options(&opts, true);
        assert!(has_long(&args, "--size-only"));
    }

    #[test]
    fn test_build_server_options_existing() {
        let opts = TransferOptions::builder().existing(true).build();
        let args = build_server_options(&opts, true);
        assert!(has_long(&args, "--existing"));
    }

    #[test]
    fn test_build_server_options_ignore_existing() {
        let opts = TransferOptions::builder().ignore_existing(true).build();
        let args = build_server_options(&opts, true);
        assert!(has_long(&args, "--ignore-existing"));
    }

    #[test]
    fn test_build_server_options_max_delete() {
        let opts = TransferOptions::builder().max_delete(42).build();
        let args = build_server_options(&opts, true);
        assert!(has_long_prefix(&args, "--max-delete=42"));
    }

    #[test]
    fn test_roundtrip_new_flags() {
        let opts = TransferOptions::builder()
            .archive()
            .ignore_times(true)
            .size_only(true)
            .existing(true)
            .ignore_existing(true)
            .max_delete(99)
            .prune_empty_dirs(true)
            .build();

        let args = build_server_options(&opts, true);
        let parsed = parse_server_args(&args, "/tmp/test".into(), true);

        assert!(parsed.ignore_times());
        assert!(parsed.size_only());
        assert!(parsed.existing());
        assert!(parsed.ignore_existing());
        assert_eq!(parsed.max_delete(), Some(99));
        assert!(parsed.prune_empty_dirs());
    }

    #[test]
    fn test_roundtrip_batch2_flags() {
        let opts = TransferOptions::builder()
            .copy_links(true)
            .safe_links(true)
            .keep_dirlinks(true)
            .remove_source_files(true)
            .dirs(true)
            .cvs_exclude(true)
            .modify_window(2)
            .append_verify(true)
            .block_size(4096)
            .chmod("Du+rwx")
            .chown_uid(1000)
            .chown_gid(1000)
            .build();

        let args = build_server_options(&opts, true);
        let parsed = parse_server_args(&args, "/tmp/test".into(), true);

        assert!(parsed.copy_links());
        assert!(parsed.safe_links());
        assert!(parsed.keep_dirlinks());
        assert!(parsed.remove_source_files());
        assert!(parsed.dirs());
        assert!(parsed.cvs_exclude());
        assert_eq!(parsed.modify_window(), 2);
        assert!(parsed.append_verify());
        assert_eq!(parsed.block_size(), Some(4096));
        assert_eq!(parsed.chmod(), &["Du+rwx"]);
        assert_eq!(parsed.chown_uid(), Some(1000));
        assert_eq!(parsed.chown_gid(), Some(1000));
    }

    #[test]
    fn test_roundtrip_batch3_flags() {
        let opts = TransferOptions::builder()
            .partial(true)
            .relative(true)
            .filter_merge_files(2)
            .list_only(true)
            .fuzzy(true)
            .build();

        let args = build_server_options(&opts, true);
        let parsed = parse_server_args(&args, "/tmp/test".into(), true);

        assert!(parsed.partial());
        assert!(parsed.relative());
        assert_eq!(parsed.filter_merge_files(), 2);
        assert!(parsed.list_only());
        assert!(parsed.fuzzy());
    }

    #[test]
    fn test_roundtrip_batch4_flags() {
        let opts = TransferOptions::builder()
            .preserve_hard_links(true)
            .preserve_acls(true)
            .preserve_xattrs(true)
            .fake_super(true)
            .build();

        let args = build_server_options(&opts, true);
        let parsed = parse_server_args(&args, "/tmp/test".into(), true);

        assert!(parsed.preserve_hard_links());
        assert!(parsed.preserve_acls());
        assert!(parsed.preserve_xattrs());
        assert!(parsed.fake_super());
    }
}
