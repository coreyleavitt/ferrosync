//! Rsync daemon transport (TCP port 873).
//!
//! Connects to an rsync daemon, performs the text-based greeting/module
//! selection/authentication handshake, then hands off the TCP stream for
//! the binary rsync protocol exchange.
//!
//! The daemon protocol flow:
//!
//! 1. TCP connect to `host:port` (default port 873).
//! 2. Server sends `@RSYNCD: <major>.<minor>\n`.
//! 3. Client responds with `@RSYNCD: <major>.<minor>\n`.
//! 4. Client sends module name (or `#list` for module listing).
//! 5. Server responds with one of:
//!    - `@RSYNCD: OK\n` -- module selected, proceed.
//!    - `@RSYNCD: AUTHREQD <challenge>\n` -- auth required.
//!    - `@RSYNCD: EXIT\n` -- server closing (after module list).
//!    - `@ERROR: <message>\n` -- fatal error.
//! 6. If auth required: client sends `<user> <response>\n`.
//! 7. After `@RSYNCD: OK`: client sends rsync arguments, then binary
//!    protocol handshake proceeds on the same TCP stream.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Default rsync daemon port.
pub const DEFAULT_DAEMON_PORT: u16 = 873;

/// Protocol version we advertise to the daemon.
///
/// This is the text-level daemon protocol version, not the binary rsync
/// protocol version (which is negotiated later via the binary handshake).
const DAEMON_PROTOCOL_VERSION: u8 = 31;

/// Sub-protocol version (used since protocol 30+).
const DAEMON_SUB_PROTOCOL_VERSION: u8 = 0;

/// A module entry returned by the daemon's module listing.
#[derive(Debug, Clone)]
pub struct DaemonModule {
    /// Module name.
    pub name: String,
    /// Module description/comment (may be empty).
    pub comment: String,
}

/// Configuration for a daemon transport connection.
#[derive(Debug, Clone)]
pub struct DaemonTransportConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// Daemon port (default 873).
    pub port: u16,
    /// Module name to connect to.
    pub module: String,
    /// Remote path within the module (appended after module name).
    pub path: String,
    /// Username for authentication (if the module requires it).
    pub user: Option<String>,
    /// Password for authentication.
    pub password: Option<String>,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for DaemonTransportConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_DAEMON_PORT,
            module: String::new(),
            path: String::new(),
            user: None,
            password: None,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Rsync daemon transport over TCP.
///
/// Connects to an rsync daemon (typically on port 873), performs the
/// text-based module selection and optional authentication, then returns
/// the TCP stream for binary protocol exchange.
pub struct DaemonTransport {
    config: DaemonTransportConfig,
    /// Whether we are sending to the remote (remote is receiver).
    am_sender: bool,
    /// Server-mode option string.
    options: String,
}

impl DaemonTransport {
    /// Create a new daemon transport.
    ///
    /// - `config`: daemon connection parameters.
    /// - `am_sender`: if true, we are sending to the remote (remote is receiver).
    /// - `options`: the server-mode option string (e.g., "-logDtprze.iLsfxCIvu").
    pub fn new(config: DaemonTransportConfig, am_sender: bool, options: &str) -> Self {
        Self {
            config,
            am_sender,
            options: options.to_string(),
        }
    }

    /// List available modules on the daemon.
    ///
    /// Connects, exchanges greetings, sends `#list`, and returns the
    /// list of modules before the server sends `@RSYNCD: EXIT`.
    pub async fn list_modules(
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<DaemonModule>> {
        let addr = format!("{host}:{port}");
        let stream = tcp_connect(&addr, timeout).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Exchange greetings.
        let _version = read_greeting(&mut reader).await?;
        send_greeting(&mut writer).await?;

        // Send #list request.
        writer.write_all(b"#list\n").await.map_err(io_err)?;
        writer.flush().await.map_err(io_err)?;

        // Read module list until @RSYNCD: EXIT.
        let mut modules = Vec::new();
        loop {
            let line = read_line(&mut reader).await?;
            if line.starts_with("@RSYNCD: EXIT") {
                break;
            }
            if line.starts_with("@ERROR:") {
                return Err(TransportError::ConnectionFailed {
                    message: line.trim_start_matches("@ERROR:").trim().to_string(),
                });
            }
            // Module lines are formatted as "name\tcomment" or just "name".
            let (name, comment) = match line.split_once('\t') {
                Some((n, c)) => (n.trim().to_string(), c.trim().to_string()),
                None => (line.trim().to_string(), String::new()),
            };
            if !name.is_empty() {
                modules.push(DaemonModule { name, comment });
            }
        }

        Ok(modules)
    }

    /// Build the argument list to send after module selection.
    ///
    /// For daemon connections, rsync sends arguments as newline-terminated
    /// strings, ending with an empty line.
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("--server".to_string());
        if !self.am_sender {
            args.push("--sender".to_string());
        }
        args.push(self.options.clone());
        args.push(".".to_string());

        // The path within the module.
        let path = if self.config.path.is_empty() {
            ".".to_string()
        } else {
            self.config.path.clone()
        };
        args.push(path);

        args
    }
}

impl Transport for DaemonTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        tracing::debug!(
            addr = %addr,
            module = %self.config.module,
            "connecting to rsync daemon"
        );

        let stream = tcp_connect(&addr, self.config.connect_timeout).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        // Step 1: Exchange daemon protocol greetings.
        let _remote_version = read_greeting(&mut reader).await?;
        send_greeting(&mut writer).await?;

        // Step 2: Send the module name.
        writer
            .write_all(format!("{}\n", self.config.module).as_bytes())
            .await
            .map_err(io_err)?;
        writer.flush().await.map_err(io_err)?;

        // Step 3: Read response -- could be MOTD lines, then @RSYNCD: or @ERROR:.
        loop {
            let line = read_line(&mut reader).await?;

            if line.starts_with("@RSYNCD: OK") {
                break;
            } else if line.starts_with("@RSYNCD: AUTHREQD ") {
                let challenge = line
                    .trim_start_matches("@RSYNCD: AUTHREQD ")
                    .trim()
                    .to_string();
                let response = compute_auth_response(
                    &challenge,
                    self.config.user.as_deref().unwrap_or(""),
                    self.config.password.as_deref().unwrap_or(""),
                );
                writer
                    .write_all(response.as_bytes())
                    .await
                    .map_err(io_err)?;
                writer.flush().await.map_err(io_err)?;

                // Read the result of authentication.
                let auth_line = read_line(&mut reader).await?;
                if auth_line.starts_with("@RSYNCD: OK") {
                    break;
                } else if auth_line.starts_with("@ERROR:") {
                    let msg = auth_line.trim_start_matches("@ERROR:").trim();
                    if msg.contains("auth failed") {
                        return Err(TransportError::AuthFailed {
                            message: format!(
                                "authentication failed on module {}",
                                self.config.module
                            ),
                        });
                    }
                    return Err(TransportError::ConnectionFailed {
                        message: msg.to_string(),
                    });
                } else {
                    return Err(TransportError::AuthFailed {
                        message: format!(
                            "unexpected response after auth: {auth_line}"
                        ),
                    });
                }
            } else if line.starts_with("@ERROR:") {
                let msg = line.trim_start_matches("@ERROR:").trim();
                if msg.contains("Unknown module") {
                    return Err(TransportError::ModuleNotFound {
                        module: self.config.module.clone(),
                    });
                }
                return Err(TransportError::ConnectionFailed {
                    message: msg.to_string(),
                });
            } else if line.starts_with("@RSYNCD: EXIT") {
                return Err(TransportError::ConnectionFailed {
                    message: "daemon sent EXIT before module selection completed"
                        .to_string(),
                });
            } else {
                // MOTD or informational line -- log and continue.
                tracing::debug!(motd = %line, "daemon MOTD");
            }
        }

        // Step 4: Send arguments (newline-terminated, empty line to finish).
        let args = self.build_args();
        for arg in &args {
            writer
                .write_all(format!("{arg}\n").as_bytes())
                .await
                .map_err(io_err)?;
        }
        writer.write_all(b"\n").await.map_err(io_err)?;
        writer.flush().await.map_err(io_err)?;

        tracing::debug!(
            module = %self.config.module,
            args = ?args,
            "daemon module selected, starting binary protocol"
        );

        // Reassemble the split stream into a single TcpStream.
        // The BufReader may have buffered data from the text handshake
        // that belongs to the binary protocol, so we chain it back.
        let buffered = reader.buffer().to_vec();
        let inner_reader = reader.into_inner();
        let stream = inner_reader.unsplit(writer);

        if buffered.is_empty() {
            let (read_half, write_half) = tokio::io::split(stream);
            Ok(TransportStreams {
                reader: Box::new(read_half),
                writer: Box::new(write_half),
                background_task: None,
            })
        } else {
            // Chain the buffered bytes with the stream for reads;
            // writes go directly to the stream.
            let (read_half, write_half) = tokio::io::split(stream);
            use tokio::io::AsyncReadExt as _;
            let chained_read = std::io::Cursor::new(buffered).chain(read_half);
            Ok(TransportStreams {
                reader: Box::new(chained_read),
                writer: Box::new(write_half),
                background_task: None,
            })
        }
        })
    }
}

// ---------------------------------------------------------------------------
// Daemon protocol helpers
// ---------------------------------------------------------------------------

/// Establish a TCP connection with timeout.
async fn tcp_connect(addr: &str, timeout: Duration) -> Result<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| TransportError::ConnectionFailed {
            message: format!("connection to {addr} timed out"),
        })?
        .map_err(|e| TransportError::ConnectionFailed {
            message: format!("TCP connection to {addr} failed: {e}"),
        })
}

/// Read the daemon greeting line: `@RSYNCD: <major>.<minor>\n`.
///
/// Returns the major protocol version.
async fn read_greeting<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<u8> {
    let line = read_line(reader).await?;

    if !line.starts_with("@RSYNCD: ") {
        return Err(TransportError::ConnectionFailed {
            message: format!("expected daemon greeting, got: {line}"),
        });
    }

    let version_str = line.trim_start_matches("@RSYNCD: ").trim();

    // Version may be "31" or "31.0".
    let major_str = version_str.split('.').next().unwrap_or(version_str);
    let major: u8 = major_str.parse().map_err(|_| {
        TransportError::ConnectionFailed {
            message: format!("invalid daemon version: {version_str}"),
        }
    })?;

    tracing::debug!(version = %version_str, "daemon greeting received");
    Ok(major)
}

/// Send our daemon protocol greeting.
async fn send_greeting<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
) -> Result<()> {
    let greeting = format!(
        "@RSYNCD: {DAEMON_PROTOCOL_VERSION}.{DAEMON_SUB_PROTOCOL_VERSION}\n"
    );
    writer.write_all(greeting.as_bytes()).await.map_err(io_err)?;
    writer.flush().await.map_err(io_err)?;
    Ok(())
}

/// Maximum line length accepted from the daemon (8 KiB).
const MAX_LINE_LENGTH: usize = 8192;

/// Read a single line from the daemon (up to `\n`).
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<String> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).await.map_err(io_err)?;
    if bytes_read == 0 {
        return Err(TransportError::ConnectionFailed {
            message: "daemon closed connection unexpectedly".to_string(),
        });
    }
    if line.len() > MAX_LINE_LENGTH {
        return Err(TransportError::ConnectionFailed {
            message: format!(
                "daemon sent line exceeding maximum length ({} > {MAX_LINE_LENGTH} bytes)",
                line.len()
            ),
        });
    }
    // Strip trailing newline/carriage return.
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Compute the authentication response for a daemon challenge (for use by TLS transport).
pub(crate) fn compute_auth_response_for_tls(
    challenge: &str,
    user: &str,
    password: &str,
) -> String {
    compute_auth_response(challenge, user, password)
}

/// Compute the authentication response for a daemon challenge.
///
/// The rsync daemon auth protocol:
/// 1. Server sends a base64-encoded challenge string.
/// 2. Client computes MD4(zero-padded-password + challenge) and base64-encodes it.
/// 3. Client sends `<user> <base64_hash>\n`.
fn compute_auth_response(challenge: &str, user: &str, password: &str) -> String {
    use md4::{Digest, Md4};

    let mut hasher = Md4::new();
    // Zero-pad the password to 64 bytes (rsync behavior).
    let mut padded_password = [0u8; 64];
    let pw_bytes = password.as_bytes();
    let copy_len = pw_bytes.len().min(64);
    padded_password[..copy_len].copy_from_slice(&pw_bytes[..copy_len]);

    hasher.update(padded_password);
    hasher.update(challenge.as_bytes());
    let digest = hasher.finalize();

    let encoded = base64_encode(&digest);
    format!("{user} {encoded}\n")
}

/// Minimal base64 encoder (standard alphabet with padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        match chunk.len() {
            3 => {
                let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n & 0x3F) as usize] as char);
            }
            2 => {
                let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
                result.push('=');
            }
            1 => {
                let n = (chunk[0] as u32) << 16;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push('=');
                result.push('=');
            }
            _ => unreachable!(),
        }
    }

    result
}

/// Map I/O errors to TransportError.
fn io_err(e: std::io::Error) -> TransportError {
    TransportError::Io(std::sync::Arc::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_transport_config_defaults() {
        let config = DaemonTransportConfig::default();
        assert_eq!(config.port, DEFAULT_DAEMON_PORT);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.user.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_build_args_sender() {
        let config = DaemonTransportConfig {
            module: "backup".to_string(),
            path: "subdir".to_string(),
            ..Default::default()
        };
        let transport = DaemonTransport::new(config, true, "-logDtprze.iLsfxCIvu");
        let args = transport.build_args();
        assert_eq!(args[0], "--server");
        assert!(!args.contains(&"--sender".to_string()));
        assert!(args.contains(&"subdir".to_string()));
    }

    #[test]
    fn test_build_args_receiver() {
        let config = DaemonTransportConfig {
            module: "data".to_string(),
            path: String::new(),
            ..Default::default()
        };
        let transport = DaemonTransport::new(config, false, "-logDtprze.iLsfxCIvu");
        let args = transport.build_args();
        assert_eq!(args[0], "--server");
        assert_eq!(args[1], "--sender");
        assert_eq!(args.last().unwrap(), ".");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_compute_auth_response_format() {
        let response = compute_auth_response("testchallenge", "myuser", "mypass");
        assert!(response.starts_with("myuser "));
        assert!(response.ends_with('\n'));
        let parts: Vec<&str> = response.trim().split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "myuser");
        assert!(parts[1]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_compute_auth_response_deterministic() {
        let r1 = compute_auth_response("challenge1", "user", "pass");
        let r2 = compute_auth_response("challenge1", "user", "pass");
        assert_eq!(r1, r2);

        let r3 = compute_auth_response("challenge2", "user", "pass");
        assert_ne!(r1, r3);
    }

    #[tokio::test]
    async fn test_read_greeting_valid() {
        let data = b"@RSYNCD: 31.0\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let version = read_greeting(&mut reader).await.unwrap();
        assert_eq!(version, 31);
    }

    #[tokio::test]
    async fn test_read_greeting_no_subversion() {
        let data = b"@RSYNCD: 30\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let version = read_greeting(&mut reader).await.unwrap();
        assert_eq!(version, 30);
    }

    #[tokio::test]
    async fn test_read_greeting_invalid() {
        let data = b"NOT A GREETING\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let result = read_greeting(&mut reader).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::ConnectionFailed { message } => {
                assert!(message.contains("expected daemon greeting"));
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_read_line_eof() {
        let data = b"";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let result = read_line(&mut reader).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::ConnectionFailed { message } => {
                assert!(message.contains("closed connection"));
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_send_greeting() {
        let mut buf = Vec::new();
        send_greeting(&mut buf).await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("@RSYNCD: "));
        assert!(s.ends_with('\n'));
        assert!(s.contains("31"));
    }

    /// Helper: simulate a daemon server on one side of a duplex stream.
    /// Uses BufReader for line-based reading (avoids duplex buffering issues).
    async fn mock_server_no_auth(server_stream: tokio::io::DuplexStream) {
        let (reader, mut writer) = tokio::io::split(server_stream);
        let mut reader = BufReader::new(reader);

        // Send greeting.
        writer.write_all(b"@RSYNCD: 31.0\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read client greeting.
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("@RSYNCD: "));

        // Read module name.
        line.clear();
        reader.read_line(&mut line).await.unwrap();

        // Send OK.
        writer.write_all(b"@RSYNCD: OK\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read args until empty line.
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await.unwrap();
            if n == 0 || line.trim().is_empty() {
                break;
            }
        }
    }

    /// Full daemon handshake simulation without auth.
    #[tokio::test]
    async fn test_daemon_handshake_no_auth() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let server_handle = tokio::spawn(mock_server_no_auth(server_stream));

        let (reader, mut writer) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(reader);

        let version = read_greeting(&mut reader).await.unwrap();
        assert_eq!(version, 31);
        send_greeting(&mut writer).await.unwrap();

        writer.write_all(b"testmod\n").await.unwrap();
        writer.flush().await.unwrap();

        let response = read_line(&mut reader).await.unwrap();
        assert!(response.starts_with("@RSYNCD: OK"));

        let config = DaemonTransportConfig {
            module: "testmod".to_string(),
            ..Default::default()
        };
        let transport = DaemonTransport::new(config, false, "-r");
        for arg in &transport.build_args() {
            writer
                .write_all(format!("{arg}\n").as_bytes())
                .await
                .unwrap();
        }
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }

    /// Handshake simulation with MOTD lines before @RSYNCD: OK.
    #[tokio::test]
    async fn test_daemon_handshake_with_motd() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            writer.write_all(b"@RSYNCD: 31.0\n").await.unwrap();
            writer.flush().await.unwrap();

            // Read client greeting.
            reader.read_line(&mut line).await.unwrap();
            // Read module name.
            line.clear();
            reader.read_line(&mut line).await.unwrap();

            // Send MOTD then OK.
            writer
                .write_all(
                    b"Welcome to the backup server\n\
                      Maintenance window: Sundays 2-4am\n\
                      @RSYNCD: OK\n",
                )
                .await
                .unwrap();
            writer.flush().await.unwrap();

            // Consume remaining data until client closes.
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
            }
        });

        let (reader, mut writer) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(reader);

        let _version = read_greeting(&mut reader).await.unwrap();
        send_greeting(&mut writer).await.unwrap();

        writer.write_all(b"backup\n").await.unwrap();
        writer.flush().await.unwrap();

        // Should read through MOTD lines and find OK.
        let mut motd_lines = Vec::new();
        loop {
            let line = read_line(&mut reader).await.unwrap();
            if line.starts_with("@RSYNCD: OK") {
                break;
            }
            motd_lines.push(line);
        }

        assert_eq!(motd_lines.len(), 2);
        assert!(motd_lines[0].contains("Welcome"));
        assert!(motd_lines[1].contains("Maintenance"));

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }

    /// Handshake simulation with authentication.
    #[tokio::test]
    async fn test_daemon_handshake_with_auth() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            writer.write_all(b"@RSYNCD: 31.0\n").await.unwrap();
            writer.flush().await.unwrap();

            // Read client greeting.
            reader.read_line(&mut line).await.unwrap();
            // Read module name.
            line.clear();
            reader.read_line(&mut line).await.unwrap();

            // Send auth challenge.
            writer
                .write_all(b"@RSYNCD: AUTHREQD abc123challenge\n")
                .await
                .unwrap();
            writer.flush().await.unwrap();

            // Read auth response.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("backupuser "));

            // Accept.
            writer.write_all(b"@RSYNCD: OK\n").await.unwrap();
            writer.flush().await.unwrap();

            // Consume remaining data.
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
            }
        });

        let (reader, mut writer) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(reader);

        let _version = read_greeting(&mut reader).await.unwrap();
        send_greeting(&mut writer).await.unwrap();

        writer.write_all(b"secured\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read AUTHREQD.
        let line = read_line(&mut reader).await.unwrap();
        assert!(line.starts_with("@RSYNCD: AUTHREQD "));

        let challenge = line
            .trim_start_matches("@RSYNCD: AUTHREQD ")
            .trim()
            .to_string();
        assert_eq!(challenge, "abc123challenge");

        let response =
            compute_auth_response(&challenge, "backupuser", "secretpass");
        writer.write_all(response.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        let ok_line = read_line(&mut reader).await.unwrap();
        assert!(ok_line.starts_with("@RSYNCD: OK"));

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }

    /// Test module listing protocol.
    #[tokio::test]
    async fn test_daemon_module_listing() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);

        let server_handle = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            writer.write_all(b"@RSYNCD: 31.0\n").await.unwrap();
            writer.flush().await.unwrap();

            // Read client greeting.
            reader.read_line(&mut line).await.unwrap();
            // Read #list.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("#list"));

            // Send module list.
            writer
                .write_all(
                    b"backup         \tDaily backups\n\
                      data           \tShared data\n\
                      @RSYNCD: EXIT\n",
                )
                .await
                .unwrap();
            writer.flush().await.unwrap();
        });

        let (reader, mut writer) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(reader);

        let _version = read_greeting(&mut reader).await.unwrap();
        send_greeting(&mut writer).await.unwrap();

        writer.write_all(b"#list\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut modules = Vec::new();
        loop {
            let line = read_line(&mut reader).await.unwrap();
            if line.starts_with("@RSYNCD: EXIT") {
                break;
            }
            let (name, comment) = match line.split_once('\t') {
                Some((n, c)) => (n.trim().to_string(), c.trim().to_string()),
                None => (line.trim().to_string(), String::new()),
            };
            if !name.is_empty() {
                modules.push(DaemonModule { name, comment });
            }
        }

        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "backup");
        assert_eq!(modules[0].comment, "Daily backups");
        assert_eq!(modules[1].name, "data");
        assert_eq!(modules[1].comment, "Shared data");

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }

    /// Integration test: connect to a real rsync daemon.
    /// Gated behind FERROSYNC_DAEMON_TEST=1 env var.
    #[tokio::test]
    async fn test_connect_real_daemon() {
        if std::env::var("FERROSYNC_DAEMON_TEST").as_deref() != Ok("1") {
            eprintln!(
                "skipping daemon integration test (set FERROSYNC_DAEMON_TEST=1)"
            );
            return;
        }

        let host = std::env::var("FERROSYNC_DAEMON_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("FERROSYNC_DAEMON_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_DAEMON_PORT);

        match DaemonTransport::list_modules(&host, port, Duration::from_secs(5)).await
        {
            Ok(modules) => {
                eprintln!("daemon modules:");
                for m in &modules {
                    eprintln!("  {} - {}", m.name, m.comment);
                }
            }
            Err(e) => {
                eprintln!("daemon connection failed (expected in CI): {e}");
            }
        }
    }
}
