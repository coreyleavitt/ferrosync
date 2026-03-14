//! TCP listener for the rsync daemon.
//!
//! Accepts incoming TCP connections on the configured port (default 873),
//! performs the daemon text-protocol handshake (greeting, module selection,
//! optional authentication), then hands off to a `ServerSession` for the
//! binary rsync protocol exchange.
//!
//! Modeled after rsync's `socket.c` `start_accept_loop()` and
//! `clientserver.c` `start_daemon()`.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use super::auth;
use super::module::ModuleRegistry;
use super::session::ServerSession;

// TODO: wire up after Phase 0b -- use crate::error types
/// Listener-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("failed to bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("accept error: {0}")]
    Accept(std::io::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Protocol version we advertise to clients.
const DAEMON_PROTOCOL_VERSION: u8 = 31;
/// Sub-protocol version.
const DAEMON_SUB_PROTOCOL_VERSION: u8 = 0;
/// Maximum line length from clients (8 KiB).
const MAX_LINE_LENGTH: usize = 8192;

/// Configuration for the daemon listener.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Optional MOTD text sent to clients after the greeting.
    pub motd: Option<String>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 873)),
            motd: None,
        }
    }
}

/// TCP listener for the rsync daemon.
///
/// Accepts connections and spawns a per-connection task that performs
/// the daemon protocol handshake, then delegates to `ServerSession`.
pub struct DaemonListener {
    config: ListenerConfig,
    registry: Arc<ModuleRegistry>,
    /// Sender half of the shutdown signal.
    shutdown_tx: watch::Sender<bool>,
    /// Receiver half (cloned for each connection task).
    shutdown_rx: watch::Receiver<bool>,
}

impl DaemonListener {
    /// Create a new daemon listener.
    pub fn new(config: ListenerConfig, registry: Arc<ModuleRegistry>) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            registry,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Get a handle to trigger graceful shutdown.
    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Bind the TCP listener and return the bound address.
    ///
    /// This is useful for tests that need to know the OS-assigned port
    /// when binding to port 0.
    pub async fn bind(&self) -> Result<(TcpListener, SocketAddr), ListenerError> {
        let listener =
            TcpListener::bind(self.config.bind_addr)
                .await
                .map_err(|e| ListenerError::Bind {
                    addr: self.config.bind_addr,
                    source: e,
                })?;
        let local_addr = listener.local_addr().map_err(ListenerError::Io)?;
        Ok((listener, local_addr))
    }

    /// Run the accept loop on a pre-bound listener until shutdown.
    ///
    /// Each accepted connection is spawned as an independent tokio task.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), ListenerError> {
        tracing::info!(addr = %listener.local_addr().unwrap_or(self.config.bind_addr), "daemon listening");
        self.accept_loop_inner(listener).await
    }

    /// Run the accept loop until a shutdown signal is received.
    ///
    /// Each accepted connection is spawned as an independent tokio task.
    pub async fn accept_loop(&self) -> Result<(), ListenerError> {
        let listener =
            TcpListener::bind(self.config.bind_addr)
                .await
                .map_err(|e| ListenerError::Bind {
                    addr: self.config.bind_addr,
                    source: e,
                })?;

        tracing::info!(addr = %self.config.bind_addr, "daemon listening");
        self.accept_loop_inner(listener).await
    }

    async fn accept_loop_inner(&self, listener: TcpListener) -> Result<(), ListenerError> {
        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = result.map_err(ListenerError::Accept)?;
                    tracing::debug!(peer = %peer_addr, "accepted connection");

                    let registry = Arc::clone(&self.registry);
                    let motd = self.config.motd.clone();
                    let conn_shutdown_rx = self.shutdown_rx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            peer_addr,
                            registry,
                            motd,
                            conn_shutdown_rx,
                        ).await {
                            tracing::warn!(
                                peer = %peer_addr,
                                error = %e,
                                "connection handler error"
                            );
                        }
                    });
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("shutdown signal received, stopping accept loop");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single client connection.
///
/// This implements the server side of the daemon text protocol:
/// 1. Send greeting.
/// 2. Read client greeting.
/// 3. Send MOTD (if configured).
/// 4. Read module name (or `#list`).
/// 5. Authenticate (if required).
/// 6. Send `@RSYNCD: OK`.
/// 7. Read rsync arguments.
/// 8. Hand off to `ServerSession`.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    registry: Arc<ModuleRegistry>,
    motd: Option<String>,
    _shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Step 1: Send our greeting.
    let greeting = format!(
        "@RSYNCD: {DAEMON_PROTOCOL_VERSION}.{DAEMON_SUB_PROTOCOL_VERSION}\n"
    );
    writer.write_all(greeting.as_bytes()).await?;
    writer.flush().await?;

    // Step 2: Read client greeting.
    let client_greeting = read_line(&mut reader).await?;
    if !client_greeting.starts_with("@RSYNCD: ") {
        writer
            .write_all(b"@ERROR: protocol startup error\n")
            .await?;
        return Err(format!("invalid client greeting: {client_greeting}").into());
    }

    let _client_version = parse_version(&client_greeting)?;
    tracing::debug!(
        peer = %peer_addr,
        greeting = %client_greeting,
        "client greeting received"
    );

    // Step 3: Send MOTD (if any).
    if let Some(ref motd_text) = motd {
        for line in motd_text.lines() {
            writer
                .write_all(format!("{line}\n").as_bytes())
                .await?;
        }
    }

    // Step 4: Read module name.
    let module_name = read_line(&mut reader).await?;
    tracing::debug!(peer = %peer_addr, module = %module_name, "module requested");

    // Handle module listing.
    if module_name.is_empty() || module_name == "#list" {
        tracing::info!(peer = %peer_addr, "module list requested");
        for module in registry.list_visible() {
            let line = format!("{}\t{}\n", module.name, module.comment);
            writer.write_all(line.as_bytes()).await?;
        }
        writer.write_all(b"@RSYNCD: EXIT\n").await?;
        writer.flush().await?;
        return Ok(());
    }

    // Handle unknown commands.
    if module_name.starts_with('#') {
        writer
            .write_all(format!("@ERROR: Unknown command '{}'\n", module_name).as_bytes())
            .await?;
        return Ok(());
    }

    // Look up the module.
    let module = match registry.resolve_module(&module_name) {
        Some(m) => m,
        None => {
            tracing::warn!(peer = %peer_addr, module = %module_name, "unknown module");
            writer
                .write_all(
                    format!("@ERROR: Unknown module '{}'\n", module_name).as_bytes(),
                )
                .await?;
            return Ok(());
        }
    };

    // Step 5: Check host-based access control.
    if !module.access.check_host(&peer_addr.ip()) {
        tracing::warn!(
            peer = %peer_addr,
            module = %module_name,
            "access denied by host rules"
        );
        writer
            .write_all(
                format!(
                    "@ERROR: access denied to {} from {} ({})\n",
                    module_name,
                    peer_addr.ip(),
                    peer_addr.ip()
                )
                .as_bytes(),
            )
            .await?;
        return Ok(());
    }

    // Step 6: Authenticate (if required).
    if module.auth.requires_auth() {
        let challenge = auth::generate_challenge();
        writer
            .write_all(format!("@RSYNCD: AUTHREQD {challenge}\n").as_bytes())
            .await?;
        writer.flush().await?;

        let auth_line = read_line(&mut reader).await?;
        let (user, client_hash) = match auth::parse_auth_response(&auth_line) {
            Ok(parsed) => parsed,
            Err(_) => {
                writer
                    .write_all(
                        format!("@ERROR: auth failed on module {}\n", module_name)
                            .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
        };

        // Check if user is authorized for this module.
        let authorized_users = module.auth.user_list();
        if !authorized_users.is_empty()
            && !authorized_users.iter().any(|u| *u == user)
        {
            tracing::warn!(
                peer = %peer_addr,
                module = %module_name,
                user,
                "user not authorized"
            );
            writer
                .write_all(
                    format!("@ERROR: auth failed on module {}\n", module_name)
                        .as_bytes(),
                )
                .await?;
            return Ok(());
        }

        // Verify credentials against secrets file.
        if let Some(ref secrets_path) = module.auth.secrets_file {
            if let Err(e) =
                auth::verify_response(user, client_hash, &challenge, secrets_path)
            {
                tracing::warn!(
                    peer = %peer_addr,
                    module = %module_name,
                    user,
                    error = %e,
                    "auth verification failed"
                );
                writer
                    .write_all(
                        format!("@ERROR: auth failed on module {}\n", module_name)
                            .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
        }

        tracing::info!(
            peer = %peer_addr,
            module = %module_name,
            user,
            "authentication successful"
        );
    }

    // Step 7: Send OK.
    writer.write_all(b"@RSYNCD: OK\n").await?;
    writer.flush().await?;

    // Step 8: Read rsync arguments.
    let mut args = Vec::new();
    loop {
        let line = read_line(&mut reader).await?;
        if line.is_empty() {
            break;
        }
        args.push(line);
    }

    tracing::debug!(
        peer = %peer_addr,
        module = %module_name,
        args = ?args,
        "rsync arguments received"
    );

    // Step 9: Hand off to server session for binary protocol.
    // The BufReader may have buffered data from the text handshake
    // that belongs to the binary protocol, so we chain it back.
    let buffered = reader.buffer().to_vec();
    let inner_reader = reader.into_inner();
    let stream = inner_reader.unsplit(writer);

    let session = ServerSession::new(module.clone(), args, peer_addr);
    if buffered.is_empty() {
        session.run(stream).await?;
    } else {
        // Chain the buffered bytes with the rest of the stream.
        let (read_half, write_half) = tokio::io::split(stream);
        use tokio::io::AsyncReadExt as _;
        let chained_read = std::io::Cursor::new(buffered).chain(read_half);
        let rejoined = tokio::io::join(chained_read, write_half);
        session.run(rejoined).await?;
    }

    Ok(())
}

/// Read a single line from the client (up to newline, strips trailing CR/LF).
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err("client closed connection".into());
    }
    if line.len() > MAX_LINE_LENGTH {
        return Err(format!(
            "line exceeds maximum length ({} > {MAX_LINE_LENGTH})",
            line.len()
        )
        .into());
    }
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Parse the major protocol version from a greeting line.
fn parse_version(
    greeting: &str,
) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    let version_str = greeting
        .trim_start_matches("@RSYNCD: ")
        .trim();
    let major_str = version_str.split('.').next().unwrap_or(version_str);
    // Strip any trailing auth digest list (space-separated).
    let major_str = major_str.split_whitespace().next().unwrap_or(major_str);
    let major: u8 = major_str
        .parse()
        .map_err(|_| format!("invalid version: {version_str}"))?;
    Ok(major)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::module::Module;
    use std::path::PathBuf;

    fn make_test_registry() -> Arc<ModuleRegistry> {
        let mut registry = ModuleRegistry::new();
        registry.register(Module {
            name: "backup".to_string(),
            path: PathBuf::from("/data/backup"),
            read_only: true,
            list: true,
            comment: "Daily backups".to_string(),
            auth: super::super::module::ModuleAuth {
                auth_users: String::new(),
                secrets_file: None,
            },
            access: super::super::module::AccessControl::default(),
            max_connections: 0,
            timeout: 0,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
        });
        registry.register(Module {
            name: "hidden".to_string(),
            path: PathBuf::from("/data/hidden"),
            read_only: true,
            list: false,
            comment: "Hidden module".to_string(),
            auth: super::super::module::ModuleAuth {
                auth_users: String::new(),
                secrets_file: None,
            },
            access: super::super::module::AccessControl::default(),
            max_connections: 0,
            timeout: 0,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
        });
        Arc::new(registry)
    }

    #[test]
    fn test_parse_version_simple() {
        let v = parse_version("@RSYNCD: 31.0").unwrap();
        assert_eq!(v, 31);
    }

    #[test]
    fn test_parse_version_no_sub() {
        let v = parse_version("@RSYNCD: 30").unwrap();
        assert_eq!(v, 30);
    }

    #[test]
    fn test_parse_version_with_auth_choices() {
        let v = parse_version("@RSYNCD: 31.0 md5 sha256").unwrap();
        assert_eq!(v, 31);
    }

    #[test]
    fn test_parse_version_invalid() {
        let result = parse_version("@RSYNCD: abc");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_line_basic() {
        let data = b"hello world\n";
        let mut reader = BufReader::new(&data[..]);
        let line = read_line(&mut reader).await.unwrap();
        assert_eq!(line, "hello world");
    }

    #[tokio::test]
    async fn test_read_line_crlf() {
        let data = b"test\r\n";
        let mut reader = BufReader::new(&data[..]);
        let line = read_line(&mut reader).await.unwrap();
        assert_eq!(line, "test");
    }

    #[tokio::test]
    async fn test_read_line_eof() {
        let data = b"";
        let mut reader = BufReader::new(&data[..]);
        let result = read_line(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_listener_config_default() {
        let config = ListenerConfig::default();
        assert_eq!(config.bind_addr.port(), 873);
        assert!(config.motd.is_none());
    }

    /// Test the module registry provides correct listing data.
    /// (handle_connection requires TcpStream, so we test the registry directly.)
    #[test]
    fn test_module_listing_via_registry() {
        let registry = make_test_registry();
        let visible = registry.list_visible();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "backup");
        assert_eq!(visible[0].comment, "Daily backups");
        // Hidden module should not appear.
        assert!(visible.iter().all(|m| m.name != "hidden"));
    }

    /// Test server greeting and module list via raw I/O simulation.
    #[tokio::test]
    async fn test_server_greeting_format() {
        let mut buf = Vec::new();
        let greeting = format!(
            "@RSYNCD: {DAEMON_PROTOCOL_VERSION}.{DAEMON_SUB_PROTOCOL_VERSION}\n"
        );
        buf.extend_from_slice(greeting.as_bytes());

        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("@RSYNCD: "));
        assert!(s.contains("31.0"));
        assert!(s.ends_with('\n'));
    }

    /// Verify the DaemonListener can be constructed and its shutdown handle works.
    #[tokio::test]
    async fn test_shutdown_handle() {
        let config = ListenerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            motd: None,
        };
        let registry = make_test_registry();
        let listener = DaemonListener::new(config, registry);

        let shutdown = listener.shutdown_handle();
        // Signal shutdown.
        shutdown.send(true).unwrap();
        assert!(*listener.shutdown_rx.borrow());
    }

    /// Simulate the handshake at the I/O level using duplex streams.
    #[tokio::test]
    async fn test_handshake_protocol_simulation() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);

        // Server side.
        let server_handle = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_stream);
            let mut reader = BufReader::new(reader);

            // Send greeting.
            let greeting = format!(
                "@RSYNCD: {DAEMON_PROTOCOL_VERSION}.{DAEMON_SUB_PROTOCOL_VERSION}\n"
            );
            writer.write_all(greeting.as_bytes()).await.unwrap();
            writer.flush().await.unwrap();

            // Read client greeting.
            let line = read_line(&mut reader).await.unwrap();
            assert!(line.starts_with("@RSYNCD: "));

            // Read module name.
            let module = read_line(&mut reader).await.unwrap();
            assert_eq!(module, "testmod");

            // Send OK.
            writer.write_all(b"@RSYNCD: OK\n").await.unwrap();
            writer.flush().await.unwrap();

            // Read args until empty line.
            loop {
                let line = read_line(&mut reader).await.unwrap();
                if line.is_empty() {
                    break;
                }
            }
        });

        // Client side.
        let (reader, mut writer) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(reader);

        // Read server greeting.
        let greeting = read_line(&mut reader).await.unwrap();
        assert!(greeting.starts_with("@RSYNCD: 31"));

        // Send client greeting.
        writer
            .write_all(b"@RSYNCD: 31.0\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();

        // Send module name.
        writer.write_all(b"testmod\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read OK.
        let ok = read_line(&mut reader).await.unwrap();
        assert_eq!(ok, "@RSYNCD: OK");

        // Send args.
        writer.write_all(b"--server\n--sender\n.\n\n").await.unwrap();
        writer.flush().await.unwrap();

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }
}
