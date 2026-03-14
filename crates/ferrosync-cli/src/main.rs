use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::options::{DeleteMode, TransferOptions, Verbosity};
use ferrosync_core::transport::daemon::{DaemonTransport, DaemonTransportConfig, DEFAULT_DAEMON_PORT};
use ferrosync_core::transport::local::LocalTransport;
use ferrosync_core::transport::quic::{QuicConfig, QuicTransport};
use ferrosync_core::transport::ssh::{SshTransport, SshTransportConfig};
use ferrosync_core::transport::tls::{TlsDaemonConfig, TlsDaemonTransport};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "ferrosync",
    version,
    about = "rsync-compatible file synchronization",
    long_about = "A Rust implementation of the rsync wire protocol.\n\n\
                  Usage: ferrosync [OPTIONS] SOURCE DEST\n\n\
                  Remote paths use rsync conventions:\n  \
                  user@host:path    SSH transport\n  \
                  host::module/path Daemon transport (port 873)\n  \
                  rsync://host/module/path  Daemon URL\n  \
                  /local/path       Local transport (spawns rsync --server)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Source and destination paths (last argument is the destination)
    #[arg(required = false, num_args = 0..)]
    paths: Vec<String>,

    #[command(flatten)]
    opts: TransferFlags,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// List available modules on an rsync daemon
    Ls {
        /// Daemon host (or rsync://host[:port])
        host: String,
        /// Daemon port
        #[arg(long, default_value_t = DEFAULT_DAEMON_PORT)]
        port: u16,
    },
    /// Start as an rsync-compatible daemon
    Serve {
        /// Configuration file (rsyncd.conf format)
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Port to listen on
        #[arg(long, default_value_t = 873)]
        port: u16,
    },
}

/// Transfer flags matching rsync's command-line interface.
#[derive(clap::Args, Clone, Debug)]
struct TransferFlags {
    /// Archive mode (-rlptgoD)
    #[arg(short, long)]
    archive: bool,

    /// Recurse into directories
    #[arg(short, long)]
    recursive: bool,

    /// Preserve symlinks
    #[arg(short = 'l', long)]
    links: bool,

    /// Preserve permissions
    #[arg(short = 'p', long)]
    perms: bool,

    /// Preserve modification times
    #[arg(short = 't', long)]
    times: bool,

    /// Preserve group
    #[arg(short = 'g', long)]
    group: bool,

    /// Preserve owner (requires root)
    #[arg(short = 'o', long)]
    owner: bool,

    /// Preserve device and special files
    #[arg(short = 'D', long)]
    devices: bool,

    /// Enable compression
    #[arg(short = 'z', long)]
    compress: bool,

    /// Compression level (1-9)
    #[arg(long, value_name = "LEVEL")]
    compress_level: Option<u32>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode
    #[arg(short, long)]
    quiet: bool,

    /// Show progress
    #[arg(long)]
    progress: bool,

    /// Show transfer statistics
    #[arg(long)]
    stats: bool,

    /// Dry run (show what would be transferred)
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Itemize changes
    #[arg(short = 'i', long)]
    itemize_changes: bool,

    /// Use checksums for change detection
    #[arg(short = 'c', long)]
    checksum: bool,

    /// Whole-file transfer (skip delta algorithm)
    #[arg(short = 'W', long)]
    whole_file: bool,

    /// Update only: skip files newer on receiver
    #[arg(short = 'u', long)]
    update: bool,

    /// In-place file updates
    #[arg(long)]
    inplace: bool,

    /// Delete extraneous files from destination
    #[arg(long)]
    delete: bool,

    /// Delete before transfer
    #[arg(long)]
    delete_before: bool,

    /// Delete during transfer
    #[arg(long)]
    delete_during: bool,

    /// Delete after transfer
    #[arg(long)]
    delete_after: bool,

    /// Delete excluded files too
    #[arg(long)]
    delete_excluded: bool,

    /// Exclude pattern
    #[arg(long, value_name = "PATTERN")]
    exclude: Vec<String>,

    /// Include pattern
    #[arg(long, value_name = "PATTERN")]
    include: Vec<String>,

    /// Filter rule
    #[arg(short = 'f', long, value_name = "RULE")]
    filter: Vec<String>,

    /// Bandwidth limit (bytes/sec, or use K/M/G suffix)
    #[arg(long, value_name = "RATE")]
    bwlimit: Option<String>,

    /// Maximum file size
    #[arg(long, value_name = "SIZE")]
    max_size: Option<String>,

    /// Minimum file size
    #[arg(long, value_name = "SIZE")]
    min_size: Option<String>,

    /// I/O timeout in seconds
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// Don't cross filesystem boundaries
    #[arg(short = 'x', long)]
    one_file_system: bool,

    /// Use numeric uid/gid
    #[arg(long)]
    numeric_ids: bool,

    /// Handle sparse files efficiently
    #[arg(short = 'S', long)]
    sparse: bool,

    /// Create backups of overwritten files
    #[arg(short = 'b', long)]
    backup: bool,

    /// Directory for backup files
    #[arg(long, value_name = "DIR")]
    backup_dir: Option<PathBuf>,

    /// Suffix for backup files
    #[arg(long, value_name = "SUFFIX", default_value = "~")]
    suffix: String,

    /// Hard-link to files in DIR if unchanged
    #[arg(long, value_name = "DIR")]
    link_dest: Vec<PathBuf>,

    /// Copy files from DIR if unchanged
    #[arg(long, value_name = "DIR")]
    copy_dest: Vec<PathBuf>,

    /// Skip files unchanged in DIR
    #[arg(long, value_name = "DIR")]
    compare_dest: Vec<PathBuf>,

    /// Directory for partial transfers
    #[arg(long, value_name = "DIR")]
    partial_dir: Option<PathBuf>,

    /// Append data to shorter files
    #[arg(long)]
    append: bool,

    /// Read file list from FILE
    #[arg(long, value_name = "FILE")]
    files_from: Option<PathBuf>,

    /// Path to rsync binary on remote host
    #[arg(long, value_name = "PATH")]
    rsync_path: Option<String>,

    /// SSH identity file
    #[arg(short = 'e', long, value_name = "FILE")]
    identity: Option<PathBuf>,

    /// SSH port for remote connections
    #[arg(long)]
    port: Option<u16>,

    /// Use TLS encryption for daemon connections
    #[arg(long)]
    tls: bool,

    /// Transport protocol to use for daemon connections (tcp, tls, quic)
    #[arg(long, value_name = "PROTO", default_value = "tcp")]
    transport: String,

    /// Accept invalid TLS/QUIC certificates (insecure)
    #[arg(long)]
    insecure: bool,

    /// Number of concurrent file transfers (1-64)
    #[arg(short = 'j', long, value_name = "N", default_value_t = 1)]
    concurrent: usize,
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Parsed remote path specification.
#[derive(Debug)]
enum RemotePath {
    /// Local filesystem path.
    Local(PathBuf),
    /// SSH remote: user@host:path or host:path.
    Ssh {
        user: Option<String>,
        host: String,
        path: String,
    },
    /// Rsync daemon: host::module[/path] or rsync://host[:port]/module[/path].
    Daemon {
        host: String,
        port: u16,
        module: String,
        path: String,
    },
}

/// Parse a path argument into local, SSH, or daemon form.
fn parse_path(s: &str) -> RemotePath {
    // rsync:// URL form
    if let Some(rest) = s.strip_prefix("rsync://") {
        return parse_daemon_url(rest);
    }

    // host::module/path (daemon double-colon form)
    if let Some(pos) = s.find("::") {
        let host = &s[..pos];
        let module_path = &s[pos + 2..];
        let (module, path) = match module_path.split_once('/') {
            Some((m, p)) => (m.to_string(), p.to_string()),
            None => (module_path.to_string(), String::new()),
        };
        return RemotePath::Daemon {
            host: host.to_string(),
            port: DEFAULT_DAEMON_PORT,
            module,
            path,
        };
    }

    // user@host:path or host:path (SSH form)
    // Must distinguish from Windows drive letters (C:\...) and plain paths with colons
    if let Some(colon_pos) = s.find(':') {
        let before = &s[..colon_pos];
        // Heuristic: if 'before' is a single letter, treat as Windows drive
        if before.len() == 1 && before.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            return RemotePath::Local(PathBuf::from(s));
        }
        // Must not contain path separators before the colon
        if !before.contains('/') && !before.contains('\\') {
            let after = &s[colon_pos + 1..];
            let (user, host) = match before.split_once('@') {
                Some((u, h)) => (Some(u.to_string()), h.to_string()),
                None => (None, before.to_string()),
            };
            return RemotePath::Ssh {
                user,
                host,
                path: after.to_string(),
            };
        }
    }

    RemotePath::Local(PathBuf::from(s))
}

/// Parse `host[:port]/module[/path]` from an rsync:// URL (after stripping the scheme).
fn parse_daemon_url(rest: &str) -> RemotePath {
    let (host_port, module_path) = match rest.split_once('/') {
        Some((hp, mp)) => (hp, mp),
        None => (rest, ""),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().unwrap_or(DEFAULT_DAEMON_PORT);
            (h.to_string(), port)
        }
        None => (host_port.to_string(), DEFAULT_DAEMON_PORT),
    };

    let (module, path) = match module_path.split_once('/') {
        Some((m, p)) => (m.to_string(), p.to_string()),
        None => (module_path.to_string(), String::new()),
    };

    RemotePath::Daemon {
        host,
        port,
        module,
        path,
    }
}

// ---------------------------------------------------------------------------
// Size parsing
// ---------------------------------------------------------------------------

/// Parse a size string with optional K/M/G/T suffix into bytes.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix(['K', 'k']) {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix(['M', 'm']) {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix(['G', 'g']) {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix(['T', 't']) {
        (n, 1024 * 1024 * 1024 * 1024)
    } else {
        (s, 1u64)
    };

    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid size '{s}': {e}"))?;
    Ok(n * multiplier)
}

// ---------------------------------------------------------------------------
// Flag conversion
// ---------------------------------------------------------------------------

impl TransferFlags {
    /// Convert CLI flags into `TransferOptions`.
    fn into_transfer_options(self, source: PathBuf, dest: PathBuf) -> TransferOptions {
        let mut builder = TransferOptions::builder();

        if self.archive {
            builder = builder.archive();
        }

        builder = builder
            .recursive(self.archive || self.recursive)
            .preserve_links(self.archive || self.links)
            .preserve_perms(self.archive || self.perms)
            .preserve_times(self.archive || self.times)
            .preserve_group(self.archive || self.group)
            .preserve_owner(self.archive || self.owner)
            .preserve_devices(self.archive || self.devices)
            .preserve_specials(self.archive || self.devices);

        builder = builder.compress(self.compress);
        if let Some(level) = self.compress_level {
            builder = builder.compress_level(level);
        }

        let verbosity = if self.quiet {
            Verbosity::Quiet
        } else {
            match self.verbose {
                0 => Verbosity::Normal,
                1 => Verbosity::Verbose,
                2 => Verbosity::VeryVerbose,
                _ => Verbosity::Debug,
            }
        };
        builder = builder.verbosity(verbosity);

        builder = builder
            .progress(self.progress)
            .stats(self.stats)
            .dry_run(self.dry_run)
            .itemize_changes(self.itemize_changes)
            .checksum_mode(self.checksum)
            .whole_file(self.whole_file)
            .update(self.update)
            .inplace(self.inplace);

        let delete_mode = if self.delete_before {
            DeleteMode::Before
        } else if self.delete_during || self.delete {
            DeleteMode::During
        } else if self.delete_after {
            DeleteMode::After
        } else if self.delete_excluded {
            DeleteMode::Excluded
        } else {
            DeleteMode::None
        };
        builder = builder.delete(delete_mode);

        builder = builder
            .excludes(self.exclude)
            .includes(self.include)
            .filters(self.filter);

        if let Some(ref bw) = self.bwlimit {
            if let Ok(bytes) = parse_size(bw) {
                builder = builder.bwlimit(bytes);
            }
        }
        if let Some(ref ms) = self.max_size {
            if let Ok(bytes) = parse_size(ms) {
                builder = builder.max_size(bytes);
            }
        }
        if let Some(ref ms) = self.min_size {
            if let Ok(bytes) = parse_size(ms) {
                builder = builder.min_size(bytes);
            }
        }
        if let Some(t) = self.timeout {
            builder = builder.timeout(t);
        }

        builder = builder
            .one_file_system(self.one_file_system)
            .numeric_ids(self.numeric_ids)
            .sparse(self.sparse)
            .backup(self.backup)
            .suffix(self.suffix)
            .append(self.append)
            .link_dests(self.link_dest)
            .copy_dests(self.copy_dest)
            .compare_dests(self.compare_dest)
            .sources(vec![source])
            .dest(dest);

        if let Some(bd) = self.backup_dir {
            builder = builder.backup_dir(bd);
        }
        if let Some(pd) = self.partial_dir {
            builder = builder.partial_dir(pd);
        }
        if let Some(ff) = self.files_from {
            builder = builder.files_from(ff);
        }

        builder = builder.concurrent(self.concurrent);

        builder.build()
    }
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn print_stats(stats: &ferrosync_core::stats::TransferStats) {
    eprintln!();
    eprintln!("Number of files: {}", stats.total_files);
    eprintln!(
        "Number of files transferred: {}",
        stats.files_transferred
    );
    eprintln!("Total file size: {}", format_bytes(stats.total_size));
    eprintln!(
        "Total transferred file size: {}",
        format_bytes(stats.literal_data)
    );
    eprintln!("Literal data: {}", format_bytes(stats.literal_data));
    eprintln!("Matched data: {}", format_bytes(stats.matched_data));
    eprintln!("Total bytes sent: {}", format_bytes(stats.bytes_sent));
    eprintln!(
        "Total bytes received: {}",
        format_bytes(stats.bytes_received)
    );
    let secs = stats.elapsed.as_secs_f64();
    if secs > 0.0 {
        eprintln!(
            "Transfer rate: {}/sec",
            format_bytes((stats.bytes_sent as f64 / secs) as u64)
        );
    }
    eprintln!("Speedup: {:.2}", stats.speedup());
}

// ---------------------------------------------------------------------------
// Transport dispatch
// ---------------------------------------------------------------------------

/// Run a sync session, dispatching to the correct transport based on the
/// parsed remote path.
async fn run_sync(
    direction: SyncDirection,
    local_path: PathBuf,
    remote: RemotePath,
    flags: TransferFlags,
) -> Result<(), ferrosync_core::FerrosyncError> {
    let rsync_path = flags.rsync_path.clone();
    let identity = flags.identity.clone();
    let ssh_port = flags.port;
    let show_stats = flags.stats;
    let use_tls = flags.tls || flags.transport == "tls";
    let use_quic = flags.transport == "quic";
    let insecure = flags.insecure;

    let fs = create_filesystem();

    match remote {
        RemotePath::Local(remote_path) => {
            let (source, dest) = match direction {
                SyncDirection::Push => (local_path, remote_path),
                SyncDirection::Pull => (remote_path, local_path),
            };
            let opts = flags.into_transfer_options(source, dest.clone());
            let server_opts = build_server_options(&opts, direction == SyncDirection::Push);
            let am_sender = direction == SyncDirection::Push;

            let path = if am_sender {
                dest
            } else {
                opts.source()[0].clone()
            };

            let transport = LocalTransport::new(
                rsync_path.as_deref(),
                am_sender,
                &server_opts,
                &path,
            );
            let session = SyncSession::new(transport, opts, fs, direction);
            let result = session.run().await?;
            if show_stats {
                print_stats(&result.stats);
            }
        }
        RemotePath::Ssh {
            user,
            host,
            path: remote_path,
        } => {
            let (source, dest) = match direction {
                SyncDirection::Push => (local_path, PathBuf::from(&remote_path)),
                SyncDirection::Pull => (PathBuf::from(&remote_path), local_path),
            };
            let opts = flags.into_transfer_options(source, dest);
            let server_opts = build_server_options(&opts, direction == SyncDirection::Push);
            let am_sender = direction == SyncDirection::Push;

            let mut ssh_config = SshTransportConfig::from_host(&host);
            if let Some(u) = user {
                ssh_config.user = u;
            }
            if let Some(port) = ssh_port {
                ssh_config.port = port;
            }
            if let Some(id) = identity {
                ssh_config.identity_files = vec![id];
            }
            if let Some(ref rp) = rsync_path {
                ssh_config.rsync_path = rp.clone();
            }

            let remote_p = std::path::Path::new(&remote_path);
            let transport = SshTransport::new(ssh_config, am_sender, &server_opts, remote_p);
            let session = SyncSession::new(transport, opts, fs, direction);
            let result = session.run().await?;
            if show_stats {
                print_stats(&result.stats);
            }
        }
        RemotePath::Daemon {
            host,
            port,
            module,
            path: remote_path,
        } => {
            let (source, dest) = match direction {
                SyncDirection::Push => (local_path, PathBuf::from(&remote_path)),
                SyncDirection::Pull => (PathBuf::from(&remote_path), local_path),
            };
            let opts = flags.into_transfer_options(source, dest);
            let server_opts = build_server_options(&opts, direction == SyncDirection::Push);
            let am_sender = direction == SyncDirection::Push;

            if use_quic {
                let config = QuicConfig {
                    host,
                    port,
                    server_name: None,
                    danger_accept_invalid_certs: insecure,
                    ..Default::default()
                };
                let transport = QuicTransport::new(config);
                let session = SyncSession::new(transport, opts, fs, direction);
                let result = session.run().await?;
                if show_stats {
                    print_stats(&result.stats);
                }
            } else if use_tls {
                let config = TlsDaemonConfig {
                    host,
                    port,
                    module,
                    path: remote_path,
                    danger_accept_invalid_certs: insecure,
                    ..Default::default()
                };
                let transport = TlsDaemonTransport::new(config, am_sender, &server_opts);
                let session = SyncSession::new(transport, opts, fs, direction);
                let result = session.run().await?;
                if show_stats {
                    print_stats(&result.stats);
                }
            } else {
                let config = DaemonTransportConfig {
                    host,
                    port,
                    module,
                    path: remote_path,
                    ..Default::default()
                };
                let transport = DaemonTransport::new(config, am_sender, &server_opts);
                let session = SyncSession::new(transport, opts, fs, direction);
                let result = session.run().await?;
                if show_stats {
                    print_stats(&result.stats);
                }
            }
        }
    }

    Ok(())
}

/// Create the platform-appropriate filesystem implementation.
fn create_filesystem() -> Box<dyn ferrosync_core::fs::FileSystem> {
    #[cfg(unix)]
    {
        Box::new(ferrosync_core::fs::unix::UnixFileSystem::new())
    }
    #[cfg(windows)]
    {
        Box::new(ferrosync_core::fs::windows::WindowsFileSystem::new())
    }
    #[cfg(not(any(unix, windows)))]
    {
        compile_error!("unsupported platform: only Unix and Windows are supported")
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Ls { host, port }) => run_ls(&host, port).await,
        Some(Commands::Serve { config: _, port: _ }) => {
            eprintln!("ferrosync: serve command not yet fully implemented");
            return ExitCode::from(1);
        }
        None => {
            if cli.paths.len() < 2 {
                eprintln!("ferrosync: need at least a source and destination path");
                eprintln!("Usage: ferrosync [OPTIONS] SOURCE DEST");
                eprintln!("       ferrosync ls HOST");
                eprintln!("Try 'ferrosync --help' for more information.");
                return ExitCode::from(1);
            }
            run_transfer(cli.paths, cli.opts).await
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ferrosync: {e}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

/// List modules on an rsync daemon.
async fn run_ls(host: &str, port: u16) -> Result<(), ferrosync_core::FerrosyncError> {
    let (host, port) = if let Some(rest) = host.strip_prefix("rsync://") {
        let (h, p) = match rest.trim_end_matches('/').rsplit_once(':') {
            Some((h, port_str)) => {
                let p = port_str.parse::<u16>().unwrap_or(port);
                (h.to_string(), p)
            }
            None => (rest.trim_end_matches('/').to_string(), port),
        };
        (h, p)
    } else {
        // Strip trailing ::
        let h = host.trim_end_matches(':');
        (h.to_string(), port)
    };

    let modules = DaemonTransport::list_modules(&host, port, Duration::from_secs(10))
        .await
        .map_err(ferrosync_core::FerrosyncError::Transport)?;

    for m in &modules {
        if m.comment.is_empty() {
            println!("{}", m.name);
        } else {
            println!("{:<20} {}", m.name, m.comment);
        }
    }
    Ok(())
}

/// Run a transfer: infer direction from paths (rsync convention).
///
/// If the source is remote, we're pulling. If the destination is remote,
/// we're pushing. Both local = local transfer via rsync subprocess.
async fn run_transfer(
    paths: Vec<String>,
    opts: TransferFlags,
) -> Result<(), ferrosync_core::FerrosyncError> {
    let dest_str = paths.last().unwrap();
    let source_str = &paths[0]; // TODO: support multiple sources

    let source = parse_path(source_str);
    let dest = parse_path(dest_str);

    match (&source, &dest) {
        (RemotePath::Local(src), _) => {
            // Source is local -> pushing to dest
            run_sync(SyncDirection::Push, src.clone(), dest, opts).await
        }
        (_, RemotePath::Local(dst)) => {
            // Dest is local -> pulling from source
            run_sync(SyncDirection::Pull, dst.clone(), source, opts).await
        }
        _ => {
            eprintln!("ferrosync: remote-to-remote transfers are not supported");
            Err(ferrosync_core::FerrosyncError::Transport(
                ferrosync_core::error::TransportError::ConnectionFailed {
                    message: "remote-to-remote transfers are not supported".to_string(),
                },
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_path() {
        match parse_path("/tmp/data") {
            RemotePath::Local(p) => assert_eq!(p, PathBuf::from("/tmp/data")),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_relative_path() {
        match parse_path("./src/lib.rs") {
            RemotePath::Local(p) => assert_eq!(p, PathBuf::from("./src/lib.rs")),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_ssh_host_path() {
        match parse_path("server:/data/backup") {
            RemotePath::Ssh { user, host, path } => {
                assert_eq!(user, None);
                assert_eq!(host, "server");
                assert_eq!(path, "/data/backup");
            }
            other => panic!("expected Ssh, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_ssh_user_host_path() {
        match parse_path("deploy@prod.example.com:/var/www") {
            RemotePath::Ssh { user, host, path } => {
                assert_eq!(user, Some("deploy".to_string()));
                assert_eq!(host, "prod.example.com");
                assert_eq!(path, "/var/www");
            }
            other => panic!("expected Ssh, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_daemon_double_colon() {
        match parse_path("backup-server::data/subdir") {
            RemotePath::Daemon {
                host,
                port,
                module,
                path,
            } => {
                assert_eq!(host, "backup-server");
                assert_eq!(port, DEFAULT_DAEMON_PORT);
                assert_eq!(module, "data");
                assert_eq!(path, "subdir");
            }
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_daemon_double_colon_no_path() {
        match parse_path("host::module") {
            RemotePath::Daemon {
                host,
                module,
                path,
                ..
            } => {
                assert_eq!(host, "host");
                assert_eq!(module, "module");
                assert_eq!(path, "");
            }
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_daemon_url() {
        match parse_path("rsync://mirror.example.com/packages/latest") {
            RemotePath::Daemon {
                host,
                port,
                module,
                path,
            } => {
                assert_eq!(host, "mirror.example.com");
                assert_eq!(port, DEFAULT_DAEMON_PORT);
                assert_eq!(module, "packages");
                assert_eq!(path, "latest");
            }
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_daemon_url_with_port() {
        match parse_path("rsync://host:8873/mod") {
            RemotePath::Daemon {
                host,
                port,
                module,
                ..
            } => {
                assert_eq!(host, "host");
                assert_eq!(port, 8873);
                assert_eq!(module, "mod");
            }
            other => panic!("expected Daemon, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_windows_drive_letter() {
        match parse_path("C:\\Users\\data") {
            RemotePath::Local(p) => assert_eq!(p, PathBuf::from("C:\\Users\\data")),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_size_kilobytes() {
        assert_eq!(parse_size("10K").unwrap(), 10 * 1024);
        assert_eq!(parse_size("10k").unwrap(), 10 * 1024);
    }

    #[test]
    fn test_parse_size_megabytes() {
        assert_eq!(parse_size("5M").unwrap(), 5 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_gigabytes() {
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 bytes");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }
}
