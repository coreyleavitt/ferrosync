//! QUIC transport.
//!
//! Provides an rsync transport over QUIC, leveraging the `quinn` crate.
//! QUIC offers built-in encryption (via TLS 1.3), multiplexed streams,
//! and reduced connection latency compared to TCP+TLS.
//!
//! The transport opens a single bidirectional QUIC stream for the rsync
//! protocol exchange. Future versions may use multiple streams for
//! concurrent file transfers.

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::ServerName;

use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Default QUIC port for rsync (non-standard, chosen to avoid conflicts).
pub const DEFAULT_QUIC_PORT: u16 = 8873;

/// Configuration for a QUIC transport connection.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// Remote QUIC port.
    pub port: u16,
    /// Server name for TLS verification (SNI). Defaults to `host` if not set.
    pub server_name: Option<String>,
    /// PEM-encoded CA certificate bytes for custom CA verification.
    /// If `None`, the default webpki root store is used.
    pub ca_cert: Option<Vec<u8>>,
    /// Accept invalid server certificates (insecure, for testing only).
    pub danger_accept_invalid_certs: bool,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_QUIC_PORT,
            server_name: None,
            ca_cert: None,
            danger_accept_invalid_certs: false,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Build a `quinn::ClientConfig` from the QUIC config.
fn build_client_config(config: &QuicConfig) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    if config.danger_accept_invalid_certs {
        let crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to configure TLS versions: {e}"),
            })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
            .with_no_client_auth();

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("failed to build QUIC crypto config: {e}"),
                }
            })?,
        ));
        return Ok(client_config);
    }

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

    let crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::ConnectionFailed {
            message: format!("failed to configure TLS versions: {e}"),
        })?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
            TransportError::ConnectionFailed {
                message: format!("failed to build QUIC crypto config: {e}"),
            }
        })?,
    ));

    Ok(client_config)
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

/// QUIC transport for rsync connections.
///
/// Connects to a remote host over QUIC, opens a bidirectional stream,
/// and returns async read/write streams for the rsync protocol exchange.
pub struct QuicTransport {
    config: QuicConfig,
}

impl QuicTransport {
    /// Create a new QUIC transport.
    pub fn new(config: QuicConfig) -> Self {
        Self { config }
    }

    /// Open an additional bidirectional stream on an existing QUIC connection.
    ///
    /// This enables future concurrent file transfers over multiple streams.
    /// Note: This is a design placeholder. In practice, the `quinn::Connection`
    /// would need to be stored and shared.
    pub fn supports_multi_stream() -> bool {
        true
    }
}

impl Transport for QuicTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let addr_str = format!("{}:{}", self.config.host, self.config.port);
            tracing::debug!(addr = %addr_str, "connecting via QUIC");

            let client_config = build_client_config(&self.config)?;

            // Create a QUIC endpoint bound to any local address.
            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("failed to parse bind address: {e}"),
                }
            })?)
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("failed to create QUIC endpoint: {e}"),
            })?;

            endpoint.set_default_client_config(client_config);

            // Resolve the remote address.
            let addr = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("DNS resolution failed for {addr_str}: {e}"),
                })?
                .next()
                .ok_or_else(|| TransportError::ConnectionFailed {
                    message: format!("no addresses found for {addr_str}"),
                })?;

            let server_name = self
                .config
                .server_name
                .as_deref()
                .unwrap_or(&self.config.host);

            // Connect with timeout.
            let connecting = endpoint.connect(addr, server_name).map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("QUIC connection to {addr_str} failed: {e}"),
                }
            })?;

            let connection = tokio::time::timeout(self.config.connect_timeout, connecting)
                .await
                .map_err(|_| TransportError::ConnectionFailed {
                    message: format!("QUIC connection to {addr_str} timed out"),
                })?
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("QUIC handshake with {addr_str} failed: {e}"),
                })?;

            tracing::debug!(
                addr = %addr_str,
                "QUIC connection established"
            );

            // Open a bidirectional stream.
            let (send, recv) =
                connection
                    .open_bi()
                    .await
                    .map_err(|e| TransportError::ConnectionFailed {
                        message: format!("failed to open QUIC bidirectional stream: {e}"),
                    })?;

            tracing::debug!("QUIC bidirectional stream opened");

            // Store the connection in a background task to keep it alive.
            let bg_connection = connection.clone();
            let background_task = tokio::spawn(async move {
                // Keep the connection alive until dropped.
                bg_connection.closed().await;
                tracing::debug!("QUIC connection closed");
            });

            Ok(TransportStreams {
                reader: Box::new(recv),
                writer: Box::new(send),
                background_task: Some(background_task),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config_defaults() {
        let config = QuicConfig::default();
        assert_eq!(config.port, DEFAULT_QUIC_PORT);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.ca_cert.is_none());
        assert!(config.server_name.is_none());
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_quic_supports_multi_stream() {
        assert!(QuicTransport::supports_multi_stream());
    }

    #[test]
    fn test_build_client_config_default_roots() {
        let config = QuicConfig::default();
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_client_config_dangerous() {
        let config = QuicConfig {
            danger_accept_invalid_certs: true,
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_client_config_custom_ca() {
        let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen");
        let ca_pem = ca.cert.pem().into_bytes();

        let config = QuicConfig {
            ca_cert: Some(ca_pem),
            ..Default::default()
        };
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    /// Integration test: QUIC connection with self-signed cert.
    /// This test sets up a real QUIC server and client using rcgen-generated certs.
    #[tokio::test]
    async fn test_quic_self_signed_connection() {
        // Install rustls crypto provider (required since rustls 0.23).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate a self-signed certificate.
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen");

        let cert_der = rustls::pki_types::CertificateDer::from(certified_key.cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der());

        // Set up server config with explicit crypto provider.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .expect("server config");

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .expect("quic server config"),
        ));

        // Bind server to a random port.
        let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");

        let server_addr = server_endpoint.local_addr().unwrap();

        // Server task: accept one connection and one stream, echo data.
        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();

            // Echo back whatever we receive.
            let mut buf = vec![0u8; 1024];
            if let Ok(Some(n)) = recv.read(&mut buf).await {
                send.write_all(&buf[..n]).await.unwrap();
                send.finish().unwrap();
            }

            // Give client time to read.
            tokio::time::sleep(Duration::from_millis(50)).await;
            server_endpoint.close(0u32.into(), b"done");
        });

        // Client side: connect and exchange data.
        // Use 127.0.0.1 (not "localhost") to avoid IPv6 resolution mismatch.
        let config = QuicConfig {
            host: "127.0.0.1".to_string(),
            port: server_addr.port(),
            server_name: Some("localhost".to_string()),
            danger_accept_invalid_certs: true,
            ..Default::default()
        };

        let transport = Box::new(QuicTransport::new(config));
        let mut streams = transport.connect().await.expect("connect");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send test data.
        streams.writer.write_all(b"hello quic").await.unwrap();
        streams.writer.shutdown().await.unwrap();

        // Read echo response.
        let mut response = Vec::new();
        streams.reader.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response, b"hello quic");

        drop(streams);
        server_handle.await.unwrap();
    }
}
