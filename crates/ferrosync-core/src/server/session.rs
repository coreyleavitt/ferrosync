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

use super::module::Module;
use crate::delta::{checksum, matcher, sum, token};
use crate::engine::receiver;
use crate::error::{FsError, ProtocolError};
use crate::filelist::entry::{FileEntry, S_IFDIR, S_IFMT, S_IFREG};
use crate::filelist::exchange;
use crate::filter::FilterRuleList;
use crate::fs::FileSystem;
use crate::options::TransferOptions;
use crate::protocol::handshake::{self, NegotiatedProtocol};
use crate::protocol::multiplex::MplexWriter;
use crate::protocol::varint;

/// Server-side session error type.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {message}")]
    Protocol { message: String },

    #[error("module path does not exist: {path}")]
    ModulePathNotFound { path: String },
}

impl From<ProtocolError> for SessionError {
    fn from(e: ProtocolError) -> Self {
        SessionError::Protocol {
            message: e.to_string(),
        }
    }
}

impl From<FsError> for SessionError {
    fn from(e: FsError) -> Self {
        SessionError::Protocol {
            message: e.to_string(),
        }
    }
}

impl From<crate::FerrosyncError> for SessionError {
    fn from(e: crate::FerrosyncError) -> Self {
        SessionError::Protocol {
            message: e.to_string(),
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
#[derive(Debug)]
pub struct ServerSession {
    /// The module being served.
    module: Module,
    /// Arguments received from the client.
    args: Vec<String>,
    /// Client's network address.
    peer_addr: SocketAddr,
    /// Transfer direction (determined from args).
    direction: TransferDirection,
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
        }
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
        tracing::info!(
            peer = %self.peer_addr,
            module = %self.module.name,
            direction = ?self.direction,
            args = ?self.args,
            "starting server session"
        );

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Parse client capability string from args (the `-e.xxx` part).
        let client_info = extract_client_info(&self.args);

        // Determine if compression is requested (look for `z` in args).
        let use_compress = self
            .args
            .iter()
            .any(|a| a.contains('z') && a.starts_with('-') && !a.starts_with("--"));

        // Determine if recursive is requested.
        let is_recursive = self
            .args
            .iter()
            .any(|a| a.contains('r') && a.starts_with('-') && !a.starts_with("--"));

        // Server-side: am_sender is true when server is sending (client is pulling).
        let am_sender = self.direction == TransferDirection::Send;

        // Perform the binary handshake.
        let protocol = handshake::server_handshake(
            &mut reader,
            &mut writer,
            &client_info,
            am_sender,
            use_compress,
        )
        .await?;

        tracing::info!(
            version = protocol.version,
            checksum = ?protocol.checksum,
            compress = ?protocol.compress,
            incremental = protocol.incremental_flist,
            seed = protocol.seed,
            "server handshake complete"
        );

        #[cfg(unix)]
        let fs = crate::fs::unix::UnixFileSystem::new();
        #[cfg(windows)]
        let fs = crate::fs::windows::WindowsFileSystem::new();

        match self.direction {
            TransferDirection::Send => {
                self.handle_send_impl(reader, writer, &protocol, &fs, is_recursive)
                    .await
            }
            TransferDirection::Receive => {
                self.handle_receive_impl(reader, writer, &protocol, &fs, is_recursive)
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
        &self,
        reader: R,
        writer: W,
        protocol: &NegotiatedProtocol,
        fs: &dyn FileSystem,
        is_recursive: bool,
    ) -> Result<(), SessionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        let seed = protocol.seed;
        let checksum_type = protocol.checksum;
        let proto_ver = protocol.version;

        // Enable multiplexing: demux incoming, mux outgoing.
        let (demux_write, mut demux_read) = tokio::io::duplex(64 * 1024);
        let demux_handle = tokio::spawn(demux_task(reader, demux_write));
        let mut mplex_out = MplexWriter::new(writer);

        // Read and discard filter list from client.
        // The filter list is a series of (len: i32, rule: bytes) pairs
        // terminated by len=0.
        {
            use tokio::io::AsyncReadExt;
            loop {
                let mut len_buf = [0u8; 4];
                demux_read
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(SessionError::Io)?;
                let rule_len = i32::from_le_bytes(len_buf);
                if rule_len == 0 {
                    break;
                }
                let abs_len = rule_len.unsigned_abs() as usize;
                let mut discard = vec![0u8; abs_len];
                demux_read
                    .read_exact(&mut discard)
                    .await
                    .map_err(SessionError::Io)?;
            }
        }

        // Build file list from module path.
        let module_path = &self.module.path;
        if !fs.lexists(module_path) {
            return Err(SessionError::ModulePathNotFound {
                path: module_path.display().to_string(),
            });
        }

        let entries = build_module_entries(fs, module_path, is_recursive)?;

        // Build TransferOptions for the file list encoder.
        let opts = TransferOptions::builder()
            .recursive(is_recursive)
            .preserve_times(true)
            .source(module_path.clone())
            .build();

        // Send file list.
        let mut flist_buf = Vec::new();
        exchange::send_file_list(&mut flist_buf, &entries, protocol, &opts)
            .await
            .map_err(|e| SessionError::Protocol {
                message: e.to_string(),
            })?;

        mplex_out.write_data(&flist_buf).await?;
        mplex_out.flush().await?;

        // NDX -> entry index mapping.
        let ndx_start: i32 = if protocol.incremental_flist && proto_ver >= 30 && is_recursive {
            1
        } else {
            0
        };
        let ndx_to_entry: std::collections::HashMap<i32, usize> = entries
            .iter()
            .enumerate()
            .map(|(i, _)| (ndx_start + i as i32, i))
            .collect();

        // Sender loop: read NDX from client generator, send delta data.
        let mut gen_ndx_state = varint::NdxState::default();
        let mut send_ndx_state = varint::NdxState::default();
        let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };
        let mut phase: u32 = 0;

        loop {
            let ndx = varint::read_ndx(&mut demux_read, &mut gen_ndx_state, proto_ver).await?;

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
                    let name_len = varint::read_varint(&mut demux_read).await?;
                    let mut name_buf = vec![0u8; name_len as usize];
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

            // Only regular files have data.
            if entry.mode & S_IFMT != S_IFREG {
                continue;
            }

            // Read block signatures from generator.
            let sums = sum::read_sums(&mut demux_read).await?;

            // Read local source data.
            let source_data = read_module_file(fs, &self.module.path, entry)?;

            // Match blocks and compute delta.
            let ops = matcher::match_blocks(
                &source_data,
                &sums,
                seed,
                checksum_type,
                checksum::CHAR_OFFSET_V30,
                protocol.proper_seed_order,
            );

            // Build sender response: NDX + iflags + sum_head + tokens + checksum.
            let mut resp_buf = Vec::new();

            // NDX + iflags.
            varint::write_ndx(&mut resp_buf, ndx, &mut send_ndx_state, proto_ver).await?;
            if proto_ver >= 29 {
                varint::write_shortint(&mut resp_buf, iflags).await?;
            }

            // sum_head: echo back the generator's sum head.
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
            sum::write_sum_head(&mut resp_buf, &resp_sum_head).await?;

            // Delta tokens.
            for op in &ops {
                match op {
                    matcher::MatchOp::Data(data) => {
                        token::send_data(&mut resp_buf, data).await?;
                    }
                    matcher::MatchOp::BlockMatch(block_idx) => {
                        token::send_block_match(&mut resp_buf, *block_idx).await?;
                    }
                }
            }
            token::send_eof(&mut resp_buf).await?;

            // File-level checksum.
            let file_sum = checksum::file_checksum(&source_data, seed, checksum_type);
            resp_buf.extend_from_slice(&file_sum);

            // Send the complete response as MUX DATA.
            mplex_out.write_data(&resp_buf).await?;
            mplex_out.flush().await?;
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

        // Write transfer stats (5 varlong30 values).
        let mut stats_buf = Vec::new();
        varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
        varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
        varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
        if proto_ver >= 29 {
            varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
            varint::write_varlong30(&mut stats_buf, 0, 3, proto_ver).await?;
        }
        mplex_out.write_data(&stats_buf).await?;
        mplex_out.flush().await?;

        // Final goodbye exchange (proto >= 24).
        // Best-effort: the transfer data is already complete at this point,
        // so errors here are not fatal.
        if proto_ver >= 24 {
            // Send a goodbye NDX_DONE (the receiver expects to read one).
            let mut gb_buf = Vec::new();
            let _ = varint::write_ndx(
                &mut gb_buf,
                varint::NDX_DONE,
                &mut send_ndx_state,
                proto_ver,
            )
            .await;
            let _ = mplex_out.write_data(&gb_buf).await;
            let _ = mplex_out.flush().await;
            // Read goodbye NDX_DONEs from receiver (best-effort).
            let _ = varint::read_ndx(&mut demux_read, &mut gen_ndx_state, proto_ver).await;
            let _ = varint::read_ndx(&mut demux_read, &mut gen_ndx_state, proto_ver).await;
            if proto_ver >= 31 {
                let _ = varint::read_ndx(&mut demux_read, &mut gen_ndx_state, proto_ver).await;
            }
        }

        // Shut down the write half of the TCP stream so the remote side's
        // demux task sees EOF and exits.
        let _ = mplex_out.shutdown().await;
        drop(mplex_out);
        let _ = demux_handle.await;
        Ok(())
    }

    /// Server receives files from client (client is pushing).
    ///
    /// This mirrors the client-side `run_pull()` flow -- the server is
    /// the receiver here, so it receives the file list and delta data
    /// from the client sender.
    async fn handle_receive_impl<R, W>(
        &self,
        reader: R,
        writer: W,
        protocol: &NegotiatedProtocol,
        fs: &dyn FileSystem,
        is_recursive: bool,
    ) -> Result<(), SessionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        if self.module.read_only {
            return Err(SessionError::Protocol {
                message: format!(
                    "module '{}' is read-only, cannot receive files",
                    self.module.name
                ),
            });
        }

        let seed = protocol.seed;
        let checksum_type = protocol.checksum;
        let proto_ver = protocol.version;

        // Enable multiplexing.
        let (demux_write, mut demux_read) = tokio::io::duplex(64 * 1024);
        let demux_handle = tokio::spawn(demux_task(reader, demux_write));
        let mut mplex_out = MplexWriter::new(writer);

        // Note: filter list exchange is handled differently for daemon mode.
        // The client sender does not expect a filter list from the server
        // over daemon connections (unlike local --server mode). Omit it.

        // Build TransferOptions for the file list decoder.
        let opts = TransferOptions::builder()
            .recursive(is_recursive)
            .preserve_times(true)
            .dest(self.module.path.clone())
            .build();

        // Receive file list from client sender.
        let received_flist = exchange::recv_file_list(&mut demux_read, protocol, &opts)
            .await
            .map_err(|e| SessionError::Protocol {
                message: e.to_string(),
            })?;
        let entries = received_flist.entries;
        let entry_ndx = received_flist.entry_ndx;

        let dest = &self.module.path;

        let mut gen_ndx_state = varint::NdxState::default();
        let mut recv_ndx_state = varint::NdxState::default();

        // Create directories first.
        for entry in &entries {
            if !entry.is_dir() {
                continue;
            }
            let name_str = String::from_utf8_lossy(&entry.name);
            let dest_path = dest.join(name_str.as_ref());
            fs.mkdir(&dest_path, 0o755)?;
        }

        // Per-file receiver loop (mirrors client-side run_pull).
        for (idx, entry) in entries.iter().enumerate() {
            if !entry.is_file() {
                continue;
            }

            let name_str = String::from_utf8_lossy(&entry.name);
            let dest_path = dest.join(name_str.as_ref());

            // Create parent directories.
            if let Some(parent) = dest_path.parent() {
                if !fs.lexists(parent) {
                    fs.mkdir(parent, 0o755)?;
                }
            }

            // Read existing basis file (if any).
            let basis_data = fs.read_file(&dest_path).unwrap_or_default();

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
            // Wire format: NDX + iflags + sum_head + tokens + checksum
            let _file_ndx =
                varint::read_ndx(&mut demux_read, &mut recv_ndx_state, proto_ver).await?;
            // Read iflags (protocol >= 29).
            if proto_ver >= 29 {
                use tokio::io::AsyncReadExt;
                let mut iflags_buf = [0u8; 2];
                demux_read.read_exact(&mut iflags_buf).await?;
                let iflags = u16::from_le_bytes(iflags_buf);

                if iflags & 0x0800 != 0 {
                    let mut bt = [0u8; 1];
                    demux_read.read_exact(&mut bt).await?;
                }
                if iflags & 0x1000 != 0 {
                    let name_len = varint::read_varint(&mut demux_read).await?;
                    let mut name_buf = vec![0u8; name_len as usize];
                    demux_read.read_exact(&mut name_buf).await?;
                }
            }

            // Read sum_head from sender.
            let sum_head = sum::read_sum_head(&mut demux_read).await?;
            let blength = if sum_head.blength > 0 {
                sum_head.blength as usize
            } else {
                700
            };

            // Read tokens + file checksum.
            let result_data = receiver::recv_file_delta(
                &mut demux_read,
                &basis_data,
                blength,
                seed,
                checksum_type,
            )
            .await?;

            // Write reconstructed file.
            fs.write_file(&dest_path, &result_data, None)?;
        }

        // Phase exchange: server (generator/receiver) sends NDX_DONE for
        // each phase, the client (sender) reads them, responds with its own
        // NDX_DONE per phase, then sends a final NDX_DONE + stats after breaking.
        //
        // max_phase = 2 for proto >= 29: phases 0, 1, 2.
        // The sender loop breaks after receiving (max_phase+1) NDX_DONEs.
        // It responds with NDX_DONE for phases 0..max_phase-1 (i.e., 2 responses),
        // then writes a final NDX_DONE after breaking out.
        let max_phase: u32 = if proto_ver >= 29 { 2 } else { 1 };

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

            // The sender responds with NDX_DONE for each phase except the last
            // (it breaks out of the loop on the last one).
            if phase < max_phase {
                let resp =
                    varint::read_ndx(&mut demux_read, &mut recv_ndx_state, proto_ver).await?;
                if resp != varint::NDX_DONE {
                    tracing::warn!(ndx = resp, phase, "expected NDX_DONE from sender");
                }
            }
        }

        // Read the sender's final NDX_DONE (written after it breaks from the loop).
        let final_ndx = varint::read_ndx(&mut demux_read, &mut recv_ndx_state, proto_ver).await?;
        if final_ndx != varint::NDX_DONE {
            tracing::warn!(ndx = final_ndx, "expected final NDX_DONE from sender");
        }

        // Read transfer stats from the sender.
        let _total_read = varint::read_varlong30(&mut demux_read, 3, proto_ver).await?;
        let _total_written = varint::read_varlong30(&mut demux_read, 3, proto_ver).await?;
        let _total_size = varint::read_varlong30(&mut demux_read, 3, proto_ver).await?;
        if proto_ver >= 29 {
            let _flist_buildtime = varint::read_varlong30(&mut demux_read, 3, proto_ver).await?;
            let _flist_xfertime = varint::read_varlong30(&mut demux_read, 3, proto_ver).await?;
        }

        // Final goodbye exchange (proto >= 24).
        // The sender reads goodbye NDX_DONEs from us.
        if proto_ver >= 24 {
            async fn send_done<WW: AsyncWrite + Unpin>(
                out: &mut MplexWriter<WW>,
                st: &mut varint::NdxState,
                pv: u8,
            ) {
                let mut buf = Vec::new();
                let _ = varint::write_ndx(&mut buf, varint::NDX_DONE, st, pv).await;
                let _ = out.write_data(&buf).await;
                let _ = out.flush().await;
            }

            // Send goodbye NDX_DONEs that the sender expects to read.
            send_done(&mut mplex_out, &mut gen_ndx_state, proto_ver).await;

            if proto_ver >= 31 {
                send_done(&mut mplex_out, &mut gen_ndx_state, proto_ver).await;
            }
        }

        // Shut down the write half and abort the demux task.
        let _ = mplex_out.shutdown().await;
        drop(mplex_out);
        demux_handle.abort();
        let _ = demux_handle.await;
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
    module_path: &std::path::Path,
    recursive: bool,
) -> Result<Vec<FileEntry>, SessionError> {
    let filters = FilterRuleList::new();
    let mut entries = Vec::new();

    let meta = fs.lstat(module_path)?;
    if meta.mode & S_IFMT == S_IFDIR {
        if recursive {
            crate::filelist::walk::collect_directory_entries(
                fs,
                module_path,
                &[],
                &mut entries,
                &filters,
            )?;
        } else {
            // Non-recursive: add the directory itself and its immediate
            // non-directory children only.
            entries.push(meta.to_file_entry(b".".to_vec()));
            let mut children: Vec<crate::fs::DirEntry> = fs.read_dir(module_path)?;
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for child in children {
                let is_dir = child.metadata.mode & S_IFMT == S_IFDIR;
                if !is_dir {
                    entries.push(child.metadata.to_file_entry(child.name));
                }
            }
        }
    } else {
        let name = module_path
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
        entries.push(meta.to_file_entry(name));
    }

    Ok(entries)
}

/// Read a file from the module path given a file entry.
fn read_module_file(
    fs: &dyn FileSystem,
    module_path: &std::path::Path,
    entry: &FileEntry,
) -> Result<Vec<u8>, SessionError> {
    let name_str = String::from_utf8_lossy(&entry.name);
    let path = module_path.join(name_str.as_ref());
    Ok(fs.read_file(&path).unwrap_or_default())
}

// Use the shared demux_task from protocol::multiplex.
use crate::protocol::multiplex::demux_task;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::module::{AccessControl, ModuleAuth};
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
