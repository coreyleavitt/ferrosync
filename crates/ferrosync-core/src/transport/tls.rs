//! TLS-encrypted daemon transport.
//!
//! Wraps the standard rsync daemon protocol (greeting, module selection,
//! authentication) in a TLS layer using `rustls` + `tokio-rustls`. This
//! provides encryption and optional mutual authentication on top of the
//! existing daemon transport flow.
//!
//! TLS is opt-in: the plain `DaemonTransport` continues to work unmodified.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Default rsync-over-TLS port (stunnel convention).
pub const DEFAULT_TLS_DAEMON_PORT: u16 = 874;

/// Configuration for a TLS daemon transport connection.
#[derive(Debug, Clone)]
pub struct TlsDaemonConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// TLS daemon port (default 874).
    pub port: u16,
    /// Module name to connect to.
    pub module: String,
    /// Remote path within the module.
    pub path: String,
    /// Username for authentication (if the module requires it).
    pub user: Option<String>,
    /// Password for authentication.
    pub password: Option<String>,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// PEM-encoded CA certificate bytes for custom CA verification.
    /// If `None`, the default webpki root store is used.
    pub ca_cert: Option<Vec<u8>>,
    /// PEM-encoded client certificate bytes for mutual TLS.
    pub client_cert: Option<Vec<u8>>,
    /// PEM-encoded client private key bytes for mutual TLS.
    pub client_key: Option<Vec<u8>>,
    /// Accept invalid server certificates (insecure, for testing only).
    pub danger_accept_invalid_certs: bool,
}

impl Default for TlsDaemonConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_TLS_DAEMON_PORT,
            module: String::new(),
            path: String::new(),
            user: None,
            password: None,
            connect_timeout: Duration::from_secs(30),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            danger_accept_invalid_certs: false,
        }
    }
}

/// Build a `rustls::ClientConfig` from the TLS daemon config.
fn build_tls_config(config: &TlsDaemonConfig) -> Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ref ca_pem) = config.ca_cert {
        let certs = rustls_pemfile::certs(&mut &ca_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to parse CA certificate: {e}"),
            })?;
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("failed to add CA certificate: {e}"),
                })?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::ConnectionFailed {
            message: format!("failed to configure TLS protocol versions: {e}"),
        })?
        .with_root_certificates(root_store);

    let tls_config = if let (Some(ref cert_pem), Some(ref key_pem)) =
        (&config.client_cert, &config.client_key)
    {
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to parse client certificate: {e}"),
            })?;

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to parse client key: {e}"),
            })?
            .ok_or_else(|| TransportError::ConnectionFailed {
                message: "no private key found in client key PEM".to_string(),
            })?;

        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to configure client auth: {e}"),
            })?
    } else {
        builder.with_no_client_auth()
    };

    Ok(tls_config)
}

/// A dangerous verifier that accepts all server certificates without
/// verification. Only for testing.
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Rsync daemon transport over TLS-encrypted TCP.
///
/// Connects to an rsync daemon over TLS, then performs the standard
/// daemon text protocol (greeting, module selection, optional auth)
/// over the encrypted channel. After handshake, returns the TLS stream
/// for binary protocol exchange.
pub struct TlsDaemonTransport {
    config: TlsDaemonConfig,
    /// Whether we are sending to the remote (remote is receiver).
    am_sender: bool,
    /// Server-mode option string.
    options: String,
}

impl TlsDaemonTransport {
    /// Create a new TLS daemon transport.
    pub fn new(config: TlsDaemonConfig, am_sender: bool, options: &str) -> Self {
        Self {
            config,
            am_sender,
            options: options.to_string(),
        }
    }

    /// Build the argument list to send after module selection.
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("--server".to_string());
        if !self.am_sender {
            args.push("--sender".to_string());
        }
        args.push(self.options.clone());
        args.push(".".to_string());

        let path = if self.config.path.is_empty() {
            ".".to_string()
        } else {
            self.config.path.clone()
        };
        args.push(path);

        args
    }
}

impl Transport for TlsDaemonTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let addr = format!("{}:{}", self.config.host, self.config.port);
            tracing::debug!(
                addr = %addr,
                module = %self.config.module,
                "connecting to rsync daemon over TLS"
            );

            // Build TLS config.
            let mut tls_config = build_tls_config(&self.config)?;
            if self.config.danger_accept_invalid_certs {
                tls_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DangerousVerifier));
            }

            // TCP connect with timeout.
            let tcp_stream =
                tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| TransportError::ConnectionFailed {
                        message: format!("connection to {addr} timed out"),
                    })?
                    .map_err(|e| TransportError::ConnectionFailed {
                        message: format!("TCP connection to {addr} failed: {e}"),
                    })?;

            // TLS handshake.
            let server_name = ServerName::try_from(self.config.host.clone()).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("invalid server name '{}': {e}", self.config.host),
                }
            })?;

            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("TLS handshake with {addr} failed: {e}"),
                })?;

            tracing::debug!(addr = %addr, "TLS handshake completed");

            // Now run the daemon text protocol over the TLS stream.
            let (reader, mut writer) = tokio::io::split(tls_stream);
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

            // Step 3: Read response.
            loop {
                let line = read_line(&mut reader).await?;

                if line.starts_with("@RSYNCD: OK") {
                    break;
                } else if line.starts_with("@RSYNCD: AUTHREQD ") {
                    let challenge = line
                        .trim_start_matches("@RSYNCD: AUTHREQD ")
                        .trim()
                        .to_string();
                    let response = super::daemon::compute_auth_response_for_tls(
                        &challenge,
                        self.config.user.as_deref().unwrap_or(""),
                        self.config.password.as_deref().unwrap_or(""),
                    );
                    writer
                        .write_all(response.as_bytes())
                        .await
                        .map_err(io_err)?;
                    writer.flush().await.map_err(io_err)?;

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
                            message: format!("unexpected response after auth: {auth_line}"),
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
                        message: "daemon sent EXIT before module selection completed".to_string(),
                    });
                } else {
                    tracing::debug!(motd = %line, "daemon MOTD (TLS)");
                }
            }

            // Step 4: Send arguments.
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
                "TLS daemon module selected, starting binary protocol"
            );

            // Reassemble the stream, handling buffered data.
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
                let cursor = std::io::Cursor::new(buffered);
                let chained = tokio::io::join(cursor, stream);
                let (read_half, write_half) = tokio::io::split(chained);
                Ok(TransportStreams {
                    reader: Box::new(read_half),
                    writer: Box::new(write_half),
                    background_task: None,
                })
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Daemon protocol helpers (reused from daemon.rs but over TLS streams)
// ---------------------------------------------------------------------------

const DAEMON_PROTOCOL_VERSION: u8 = 31;
const DAEMON_SUB_PROTOCOL_VERSION: u8 = 0;
const MAX_LINE_LENGTH: usize = 8192;

async fn read_greeting<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<u8> {
    let line = read_line(reader).await?;

    if !line.starts_with("@RSYNCD: ") {
        return Err(TransportError::ConnectionFailed {
            message: format!("expected daemon greeting, got: {line}"),
        });
    }

    let version_str = line.trim_start_matches("@RSYNCD: ").trim();
    let major_str = version_str.split('.').next().unwrap_or(version_str);
    let major: u8 = major_str
        .parse()
        .map_err(|_| TransportError::ConnectionFailed {
            message: format!("invalid daemon version: {version_str}"),
        })?;

    tracing::debug!(version = %version_str, "daemon greeting received (TLS)");
    Ok(major)
}

async fn send_greeting<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    let greeting = format!("@RSYNCD: {DAEMON_PROTOCOL_VERSION}.{DAEMON_SUB_PROTOCOL_VERSION}\n");
    writer
        .write_all(greeting.as_bytes())
        .await
        .map_err(io_err)?;
    writer.flush().await.map_err(io_err)?;
    Ok(())
}

/// Read a single line from the daemon (up to `\n`), enforcing
/// `MAX_LINE_LENGTH` *during* the read to prevent unbounded allocation
/// from a malicious or malfunctioning peer.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(io_err)?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(TransportError::ConnectionFailed {
                    message: "daemon closed connection unexpectedly".to_string(),
                });
            }
            break;
        }
        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&available[..=newline_pos]);
            let consumed = newline_pos + 1;
            reader.consume(consumed);
            break;
        }
        let len = available.len();
        line.extend_from_slice(available);
        reader.consume(len);
        if line.len() > MAX_LINE_LENGTH {
            return Err(TransportError::ConnectionFailed {
                message: format!(
                    "daemon sent line exceeding maximum length ({MAX_LINE_LENGTH} bytes)"
                ),
            });
        }
    }
    if line.len() > MAX_LINE_LENGTH {
        return Err(TransportError::ConnectionFailed {
            message: format!(
                "daemon sent line exceeding maximum length ({} > {MAX_LINE_LENGTH} bytes)",
                line.len()
            ),
        });
    }
    let mut s = String::from_utf8_lossy(&line).into_owned();
    if s.ends_with('\n') {
        s.pop();
    }
    if s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}

fn io_err(e: std::io::Error) -> TransportError {
    TransportError::Io(std::sync::Arc::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_daemon_config_defaults() {
        let config = TlsDaemonConfig::default();
        assert_eq!(config.port, DEFAULT_TLS_DAEMON_PORT);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.user.is_none());
        assert!(config.password.is_none());
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_tls_transport_build_args_sender() {
        let config = TlsDaemonConfig {
            module: "backup".to_string(),
            path: "subdir".to_string(),
            ..Default::default()
        };
        let transport = TlsDaemonTransport::new(config, true, "-logDtprze.iLsfxCIvu");
        let args = transport.build_args();
        assert_eq!(args[0], "--server");
        assert!(!args.contains(&"--sender".to_string()));
        assert!(args.contains(&"subdir".to_string()));
    }

    #[test]
    fn test_tls_transport_build_args_receiver() {
        let config = TlsDaemonConfig {
            module: "data".to_string(),
            path: String::new(),
            ..Default::default()
        };
        let transport = TlsDaemonTransport::new(config, false, "-logDtprze.iLsfxCIvu");
        let args = transport.build_args();
        assert_eq!(args[0], "--server");
        assert_eq!(args[1], "--sender");
        assert_eq!(args.last().unwrap(), ".");
    }

    #[test]
    fn test_build_tls_config_default_roots() {
        let config = TlsDaemonConfig::default();
        let result = build_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_tls_config_custom_ca() {
        // Generate a self-signed CA certificate for testing.
        let ca = rcgen::generate_simple_self_signed(Vec::<String>::new()).expect("gen");
        let ca_pem = ca.cert.pem().into_bytes();

        let config = TlsDaemonConfig {
            ca_cert: Some(ca_pem),
            ..Default::default()
        };
        let result = build_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_tls_config_invalid_ca() {
        let config = TlsDaemonConfig {
            ca_cert: Some(b"not valid pem".to_vec()),
            ..Default::default()
        };
        // With no valid certs parsed, the root store will be empty but config
        // creation should still succeed (it just won't verify anything).
        // Actually, rustls_pemfile::certs returns an empty vec for invalid PEM.
        let result = build_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dangerous_verifier() {
        let config = TlsDaemonConfig {
            danger_accept_invalid_certs: true,
            ..Default::default()
        };
        let mut tls_config = build_tls_config(&config).unwrap();
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(DangerousVerifier));
        // Should compile and not panic.
    }

    #[tokio::test]
    async fn test_tls_greeting_exchange() {
        // Test the protocol helpers work over plain streams (same logic as TLS).
        let data = b"@RSYNCD: 31.0\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let version = read_greeting(&mut reader).await.unwrap();
        assert_eq!(version, 31);

        let mut buf = Vec::new();
        send_greeting(&mut buf).await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("@RSYNCD: "));
        assert!(s.contains("31"));
    }

    #[test]
    fn test_build_tls_config_with_client_cert() {
        // Generate a self-signed cert/key pair for mutual TLS testing.
        let key_pair =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen");

        let cert_pem = key_pair.cert.pem().into_bytes();
        let key_pem = key_pair.key_pair.serialize_pem().into_bytes();

        let config = TlsDaemonConfig {
            client_cert: Some(cert_pem),
            client_key: Some(key_pem),
            ..Default::default()
        };
        let result = build_tls_config(&config);
        assert!(result.is_ok());
    }
}
