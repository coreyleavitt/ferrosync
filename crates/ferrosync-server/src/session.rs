//! Server-side rsync protocol session.
//!
//! After the daemon text-protocol handshake completes (greeting, module
//! selection, authentication), the `ServerSession` takes over the TCP
//! stream and runs the binary rsync protocol.
//!
//! The session determines whether this is a pull (client reads, server
//! sends files) or push (client writes, server receives files) based on
//! the arguments received from the client.

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::module::Module;
use ferrosync_codec::entry::FileEntry;
use ferrosync_codec::exchange;
use ferrosync_engine::progress::ProgressTracker;
use ferrosync_engine::receiver_engine::ReceiverEngine;
use ferrosync_engine::wire_transfer::{self, ModuleFileReader};
use ferrosync_filter::FilterRuleList;
use ferrosync_fs::FileSystem;
use ferrosync_protocol::handshake::{self, NegotiatedProtocol};
use ferrosync_protocol::multiplex::MuxConnection;
use ferrosync_scanner::{FileListScanner, ScanOptions};
use ferrosync_types::error::{FsError, ProtocolError};
use ferrosync_types::options::TransferConfig;
use ferrosync_types::stats::TransferStats;

/// Server-side session error type.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Fs(#[from] FsError),

    #[error("module path does not exist: {path}")]
    ModulePathNotFound { path: String },
}

impl From<ferrosync_types::FerrosyncError> for SessionError {
    fn from(e: ferrosync_types::FerrosyncError) -> Self {
        match e {
            ferrosync_types::FerrosyncError::Protocol(p) => SessionError::Protocol(p),
            ferrosync_types::FerrosyncError::Fs(f) => SessionError::Fs(f),
            ferrosync_types::FerrosyncError::Transport(t) => {
                SessionError::Protocol(ProtocolError::Handshake {
                    message: t.to_string(),
                })
            }
            ferrosync_types::FerrosyncError::Filter(f) => {
                SessionError::Protocol(ProtocolError::Handshake {
                    message: f.to_string(),
                })
            }
        }
    }
}

/// The direction of the transfer from the server's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Server sends files to the client (client is pulling/receiving).
    Send,
    /// Server receives files from the client (client is pushing/sending).
    Receive,
}

/// A server-side rsync protocol session.
///
/// Created after the daemon handshake completes. Manages the binary
/// protocol exchange for a single module access.
pub struct ServerSession {
    /// The module being served.
    module: Module,
    /// Arguments received from the client.
    args: Vec<String>,
    /// Client's network address.
    peer_addr: SocketAddr,
    /// Transfer direction (determined from args).
    direction: TransferDirection,
    /// Progress tracker for transfer events.
    progress: ProgressTracker,
}

impl ServerSession {
    /// Create a new server session.
    ///
    /// The transfer direction is determined by examining the client's
    /// arguments: if `--sender` is present, the server is receiving
    /// (the client is the sender). Otherwise, the server is sending.
    pub fn new(module: Module, args: Vec<String>, peer_addr: SocketAddr) -> Self {
        let direction = if args.iter().any(|a| a == "--sender") {
            // --sender flag tells the server to act as sender.
            TransferDirection::Send
        } else {
            // No --sender flag: server acts as receiver.
            TransferDirection::Receive
        };

        Self {
            module,
            args,
            peer_addr,
            direction,
            progress: ProgressTracker::new(),
        }
    }

    /// Set a custom progress tracker.
    pub fn with_progress(mut self, progress: ProgressTracker) -> Self {
        self.progress = progress;
        self
    }

    /// Run the server session on the given stream.
    ///
    /// This performs the binary rsync protocol exchange:
    /// 1. Protocol version handshake (via `server_handshake()`).
    /// 2. File list exchange.
    /// 3. File transfer (delta encoding).
    /// 4. Final checksum verification.
    pub async fn run<S>(self, stream: S) -> Result<(), SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        self.run_split(reader, writer).await
    }

    /// Run the server session over stdin/stdout.
    ///
    /// Used when invoked as `ferrosync --server` over SSH.
    pub async fn run_over_stdio(self) -> Result<(), SessionError> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        self.run_split(stdin, stdout).await
    }

    /// Run the server session with separate reader and writer streams.
    pub async fn run_split<R, W>(self, mut reader: R, mut writer: W) -> Result<(), SessionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        tracing::info!(
            module = %self.module.name,
            direction = ?self.direction,
            args = ?self.args,
            "starting server session"
        );

        // Parse client args into TransferConfig.
        let am_sender = self.direction == TransferDirection::Send;
        let opts = ferrosync_engine::session::parse_server_args_config(
            &self.args,
            self.module.path.clone(),
            am_sender,
        );

        // Parse client capability string from args (the `-e.xxx` part).
        let client_info = extract_client_info(&self.args);

        // Perform the binary handshake.
        let protocol = handshake::server_handshake(
            &mut reader,
            &mut writer,
            &client_info,
            am_sender,
            opts.compress(),
        )
        .await?;

        tracing::info!(
            version = protocol.version,
            checksum = ?protocol.checksum,
            compress = ?protocol.compress,
            incremental = protocol.wire().supports_incremental_flist,
            seed = protocol.seed,
            "server handshake complete"
        );

        #[cfg(unix)]
        let fs: std::sync::Arc<dyn ferrosync_fs::FileSystem> =
            std::sync::Arc::new(ferrosync_fs::unix::UnixFileSystem::new());
        #[cfg(windows)]
        let fs: std::sync::Arc<dyn ferrosync_fs::FileSystem> =
            std::sync::Arc::new(ferrosync_fs::windows::WindowsFileSystem::new());

        let mut progress = self.progress;

        match self.direction {
            TransferDirection::Send => {
                Self::handle_send_impl(
                    &self.module,
                    reader,
                    writer,
                    &protocol,
                    &*fs,
                    &opts,
                    &mut progress,
                )
                .await
            }
            TransferDirection::Receive => {
                Self::handle_receive_impl(
                    &self.module,
                    reader,
                    writer,
                    &protocol,
                    fs,
                    &opts,
                    &mut progress,
                )
                .await
            }
        }
    }

    /// Server sends files to client (client is pulling).
    ///
    /// This mirrors the client-side `run_push()` flow -- the server is
    /// the sender here, so it builds the file list, sends it, then responds
    /// to generator requests with delta data.
    async fn handle_send_impl<R, W>(
        module: &Module,
        reader: R,
        writer: W,
        protocol: &NegotiatedProtocol,
        fs: &dyn FileSystem,
        opts: &TransferConfig,
        progress: &mut ProgressTracker,
    ) -> Result<(), SessionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        // Enable multiplexing: MuxConnection drives reads and writes concurrently.
        let mut mux = MuxConnection::new(reader, writer);

        // Read and discard filter list from client.
        // C ref: recv_filter_list (exclude.c:1377) -- server receiver side.
        // For daemon protocol, always read filter list. For SSH --server,
        // the filter list is conditional on delete_mode, but our daemon
        // always sends it. This matches rsync daemon behavior.
        read_and_discard_filter_list(&mut mux).await?;

        // Build file list from module path.
        let module_path = &module.path;
        if !fs.lexists(module_path) {
            return Err(SessionError::ModulePathNotFound {
                path: module_path.display().to_string(),
            });
        }

        let mut entries = build_module_entries(fs, module, opts.recursive())?;

        // Send file list. send_file_list sorts entries in canonical order
        // internally and returns NDX assignments for build_ndx_map.
        let mut flist_buf = Vec::new();
        exchange::sort_file_list(&mut entries);
        let (ndx_assignments, pending_flists) =
            exchange::send_file_list(&mut flist_buf, &entries, protocol, opts).await?;

        mux.write_data(&flist_buf).await?;
        mux.flush().await.map_err(SessionError::Io)?;

        // Sender loop via wire_transfer.
        let ndx_map = wire_transfer::build_ndx_map(&ndx_assignments);
        let file_reader = ModuleFileReader::new(fs, module_path);
        let mut stats = TransferStats::new();
        stats.start();

        wire_transfer::sender_loop(
            &mut mux,
            &entries,
            &ndx_map,
            &file_reader,
            protocol,
            &mut stats,
            progress,
            None,
            false,
            false, // append_mode
            pending_flists,
        )
        .await?;

        // Write transfer stats and goodbye: split since these need both halves
        // via separate references.
        let (mut demux_read, mut mplex_out) = mux.into_split();
        protocol.wire().write_stats(&mut mplex_out, &stats).await?;

        // Goodbye exchange.
        protocol
            .wire()
            .server_sender_goodbye(&mut demux_read, &mut mplex_out)
            .await?;

        // Shut down the write half so the remote side sees EOF.
        let _ = mplex_out.shutdown().await;
        Ok(())
    }

    /// Server receives files from client (client is pushing).
    ///
    /// This mirrors the client-side `run_pull()` flow -- the server is
    /// the receiver here, so it receives the file list and delta data
    /// from the client sender.
    async fn handle_receive_impl<R, W>(
        module: &Module,
        reader: R,
        writer: W,
        protocol: &NegotiatedProtocol,
        fs: std::sync::Arc<dyn FileSystem>,
        opts: &TransferConfig,
        progress: &mut ProgressTracker,
    ) -> Result<(), SessionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        if module.read_only {
            return Err(SessionError::Protocol(ProtocolError::Handshake {
                message: format!(
                    "module '{}' is read-only, cannot receive files",
                    module.name
                ),
            }));
        }

        // Enable multiplexing: MuxConnection drives reads and writes concurrently.
        let mut mux = MuxConnection::new(reader, writer);

        // Read and discard the client's filter list -- CONDITIONAL.
        //
        // C ref: exclude.c:1680 -- recv_filter_list only reads when:
        //   !local_server && (am_sender || receiver_wants_list)
        // For server receiver: am_sender=0, receiver_wants_list = delete || prune.
        // Client only sends filter list when delete_mode is active (see session.rs).
        let expect_filter_list = opts.delete() != ferrosync_types::options::DeleteMode::None;
        if expect_filter_list {
            read_and_discard_filter_list(&mut mux).await?;
        }

        // Receive file list from client sender.
        let received_flist = exchange::recv_file_list(&mut mux, protocol, opts).await?;
        let entries = received_flist.entries;
        let entry_ndx = received_flist.entry_ndx;

        // Split for pipelined receiver loop: generator owns writer,
        // receiver owns reader.
        let (mut demux_read, mut mplex_out) = mux.into_split();

        // Pipelined receiver loop via wire_transfer.
        // Server receiver uses default TransferOptions -- no skip checks,
        // no link-dest, no metadata preservation.
        let engine =
            std::sync::Arc::new(ReceiverEngine::new(fs, module.path.clone(), opts.clone()));
        let mut stats = TransferStats::new();
        stats.start();

        let (dr, mo) = wire_transfer::receiver_loop_pipelined(
            demux_read, mplex_out, &entries, &entry_ndx, engine, protocol, &mut stats, progress,
            None,
        )
        .await?;
        demux_read = dr;
        mplex_out = mo;

        // Phase exchange.
        wire_transfer::server_receiver_phase_exchange(&mut demux_read, &mut mplex_out, protocol)
            .await?;

        // C ref: handle_stats (main.c:325) -- server receiver does NOT
        // read/write stats. Stats are only exchanged when the server is
        // the sender (am_server && am_sender, i.e., pull mode).

        // Goodbye exchange.
        protocol
            .wire()
            .server_receiver_goodbye(&mut mplex_out)
            .await?;

        // Shut down the write half.
        let _ = mplex_out.shutdown().await;
        Ok(())
    }

    /// Get the transfer direction for this session.
    pub fn direction(&self) -> TransferDirection {
        self.direction
    }

    /// Get the module being served.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Get the client's arguments.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Get the client's network address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Extract the remote path from the client arguments.
    ///
    /// The path is typically the last argument (after ".").
    pub fn remote_path(&self) -> &str {
        // Arguments are typically: --server [--sender] <options> . <path>
        // The path after "." is what we want.
        let mut found_dot = false;
        for arg in &self.args {
            if found_dot {
                return arg;
            }
            if arg == "." {
                found_dot = true;
            }
        }
        "."
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read and discard the client's filter list from the demuxed stream.
///
/// The filter list is a series of (len: i32, rule: bytes) pairs terminated
/// by len=0.
async fn read_and_discard_filter_list<R: AsyncRead + Unpin + Send>(
    reader: &mut R,
) -> Result<(), SessionError> {
    use tokio::io::AsyncReadExt;
    loop {
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(SessionError::Io)?;
        let rule_len = i32::from_le_bytes(len_buf);
        if rule_len == 0 {
            break;
        }
        let abs_len = rule_len.unsigned_abs() as usize;
        let mut discard = vec![0u8; abs_len];
        reader
            .read_exact(&mut discard)
            .await
            .map_err(SessionError::Io)?;
    }
    Ok(())
}

/// Extract the client capability string from the `-e.xxx` argument.
fn extract_client_info(args: &[String]) -> String {
    for arg in args {
        if arg.starts_with('-') && !arg.starts_with("--") {
            // Find 'e' in the option string; everything after it is the
            // capability string.
            if let Some(pos) = arg.find('e') {
                return arg[pos + 1..].to_string();
            }
        }
    }
    // Default capability string.
    ".LsfxCIvu".to_string()
}

/// Build file entries from a module's filesystem path.
fn build_module_entries(
    fs: &dyn FileSystem,
    module: &Module,
    recursive: bool,
) -> Result<Vec<FileEntry>, SessionError> {
    // Build filter rules from module config, matching rsync's daemon_filter_list
    // population in clientserver.c. Order: filters (highest priority), includes,
    // then excludes -- same as FilterRuleList::from_options.
    let mut filters =
        FilterRuleList::from_options(&module.exclude, &module.include, &module.filter, &[], &[])
            .map_err(|e| {
                SessionError::Protocol(ProtocolError::Handshake {
                    message: format!("invalid module filter rule: {e}"),
                })
            })?;

    let dir_mode = if recursive {
        ferrosync_types::options::DirectoryMode::Recurse
    } else {
        ferrosync_types::options::DirectoryMode::List
    };
    let scan_opts = ScanOptions {
        dir_mode,
        one_file_system: false,
        copy_links: false,
        relative: false,
        filter_merge_files: 0,
        preserve_hard_links: false,
    };
    let scanner = FileListScanner::new(fs, scan_opts);
    let entries = scanner.scan_directory(&module.path, &mut filters)?;

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::{AccessControl, ModuleAuth};
    use std::path::PathBuf;

    fn make_test_module(name: &str, read_only: bool) -> Module {
        Module {
            name: name.to_string(),
            path: PathBuf::from(format!("/srv/{name}")),
            read_only,
            list: true,
            comment: format!("{name} module"),
            auth: ModuleAuth {
                auth_users: String::new(),
                secrets_file: None,
            },
            access: AccessControl::default(),
            max_connections: 0,
            timeout: 0,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
        }
    }

    #[test]
    fn test_direction_send() {
        // --sender flag tells server to be the sender.
        let module = make_test_module("test", true);
        let args = vec![
            "--server".to_string(),
            "--sender".to_string(),
            "-logDtprze.iLsfxCIvu".to_string(),
            ".".to_string(),
            "path/".to_string(),
        ];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(session.direction(), TransferDirection::Send);
    }

    #[test]
    fn test_direction_receive() {
        // No --sender flag means server is the receiver.
        let module = make_test_module("test", false);
        let args = vec![
            "--server".to_string(),
            "-logDtprze.iLsfxCIvu".to_string(),
            ".".to_string(),
            "path/".to_string(),
        ];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(session.direction(), TransferDirection::Receive);
    }

    #[test]
    fn test_remote_path() {
        let module = make_test_module("test", true);
        let args = vec![
            "--server".to_string(),
            "-r".to_string(),
            ".".to_string(),
            "subdir/file.txt".to_string(),
        ];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(session.remote_path(), "subdir/file.txt");
    }

    #[test]
    fn test_remote_path_default() {
        let module = make_test_module("test", true);
        let args = vec!["--server".to_string(), "-r".to_string()];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(session.remote_path(), ".");
    }

    #[test]
    fn test_remote_path_dot_only() {
        let module = make_test_module("test", true);
        let args = vec!["--server".to_string(), "-r".to_string(), ".".to_string()];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        // No path after "." -> returns default.
        assert_eq!(session.remote_path(), ".");
    }

    #[test]
    fn test_session_accessors() {
        let module = make_test_module("backup", true);
        let args = vec!["--server".to_string(), ".".to_string()];
        let peer: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let session = ServerSession::new(module, args.clone(), peer);

        assert_eq!(session.module().name, "backup");
        assert_eq!(session.args(), &args);
        assert_eq!(session.peer_addr(), peer);
    }

    #[test]
    fn test_extract_client_info() {
        let args = vec![
            "--server".to_string(),
            "-logDtprze.iLsfxCIvu".to_string(),
            ".".to_string(),
        ];
        assert_eq!(extract_client_info(&args), ".iLsfxCIvu");
    }

    #[test]
    fn test_extract_client_info_no_cap() {
        let args = vec!["--server".to_string(), ".".to_string()];
        assert_eq!(extract_client_info(&args), ".LsfxCIvu");
    }

    #[test]
    fn test_read_only_module_direction() {
        // A read-only module accessed without --sender means server receives,
        // but handle_receive_impl will reject it at runtime. Verify the
        // direction is correctly parsed so `run()` dispatches properly.
        let module = make_test_module("readonly", true);
        let args = vec![
            "--server".to_string(),
            "-logDtprze.iLsfxCIvu".to_string(),
            ".".to_string(),
            "path/".to_string(),
        ];
        let session = ServerSession::new(module, args, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(session.direction(), TransferDirection::Receive);
    }
}
