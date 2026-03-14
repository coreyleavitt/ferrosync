//! Noise protocol transport.
//!
//! Provides encrypted transport using the Noise protocol framework (via the
//! `snow` crate). This is useful when you want strong, simple encryption
//! without the complexity of X.509/PKI that TLS requires.
//!
//! Supports both Noise_XX (mutual authentication with key exchange) and
//! Noise_IK (initiator knows responder's static key) handshake patterns.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Maximum Noise message size (65535 bytes per spec).
const MAX_NOISE_MSG_LEN: usize = 65535;

/// Noise protocol pattern to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePattern {
    /// Noise_XX: mutual authentication. Both sides exchange static keys
    /// during the handshake. No prior key knowledge required.
    XX,
    /// Noise_IK: initiator knows responder's static key. Provides one
    /// round-trip handshake with forward secrecy.
    IK,
}

impl NoisePattern {
    /// Return the Noise protocol name string.
    fn protocol_name(self) -> &'static str {
        match self {
            NoisePattern::XX => "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            NoisePattern::IK => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        }
    }
}

/// Configuration for a Noise protocol transport connection.
#[derive(Debug, Clone)]
pub struct NoiseConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// Local static private key (32 bytes for Curve25519).
    pub local_private_key: Vec<u8>,
    /// Remote static public key (32 bytes). Required for IK pattern,
    /// optional for XX (will be learned during handshake).
    pub remote_public_key: Option<Vec<u8>>,
    /// Pre-shared key for PSK-based patterns (optional).
    pub psk: Option<Vec<u8>>,
    /// Noise handshake pattern.
    pub pattern: NoisePattern,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            local_private_key: Vec::new(),
            remote_public_key: None,
            psk: None,
            pattern: NoisePattern::XX,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Async adapter wrapping a Noise `TransportState` over a TCP stream.
///
/// Implements framed reads/writes using length-prefixed Noise messages:
/// each message is preceded by a 2-byte big-endian length prefix.
struct NoiseStream {
    /// The underlying TCP stream.
    tcp: TcpStream,
    /// Noise transport state (after handshake completion).
    noise: Arc<Mutex<TransportState>>,
    /// Decrypted read buffer.
    read_buf: Vec<u8>,
    /// Current read position in `read_buf`.
    read_pos: usize,
}

impl NoiseStream {
    /// Create a new `NoiseStream` from a completed handshake.
    fn new(tcp: TcpStream, noise: TransportState) -> Self {
        Self {
            tcp,
            noise: Arc::new(Mutex::new(noise)),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Split into read and write halves.
    fn split(self) -> (NoiseReader, NoiseWriter) {
        let (tcp_reader, tcp_writer) = tokio::io::split(self.tcp);
        (
            NoiseReader {
                tcp_reader,
                noise: Arc::clone(&self.noise),
                read_buf: self.read_buf,
                read_pos: self.read_pos,
            },
            NoiseWriter {
                tcp_writer,
                noise: self.noise,
            },
        )
    }
}

/// Read half of a `NoiseStream`.
pub struct NoiseReader {
    tcp_reader: tokio::io::ReadHalf<TcpStream>,
    noise: Arc<Mutex<TransportState>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

/// Write half of a `NoiseStream`.
pub struct NoiseWriter {
    tcp_writer: tokio::io::WriteHalf<TcpStream>,
    noise: Arc<Mutex<TransportState>>,
}

impl AsyncRead for NoiseReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // If we have buffered decrypted data, return it.
        if me.read_pos < me.read_buf.len() {
            let remaining = &me.read_buf[me.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            me.read_pos += to_copy;
            if me.read_pos >= me.read_buf.len() {
                me.read_buf.clear();
                me.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read the 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        let mut len_read_buf = ReadBuf::new(&mut len_buf);
        match Pin::new(&mut me.tcp_reader).poll_read(cx, &mut len_read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = len_read_buf.filled().len();
                if filled == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                if filled < 2 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            return Poll::Ready(Ok(()));
        }

        // Read the encrypted message body.
        let mut encrypted = vec![0u8; msg_len];
        let mut body_buf = ReadBuf::new(&mut encrypted);
        match Pin::new(&mut me.tcp_reader).poll_read(cx, &mut body_buf) {
            Poll::Ready(Ok(())) => {
                let filled = body_buf.filled().len();
                if filled < msg_len {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Decrypt the message.
        let mut plaintext = vec![0u8; msg_len];
        match me.noise.try_lock() {
            Ok(mut transport) => {
                match transport.read_message(&encrypted, &mut plaintext) {
                    Ok(len) => {
                        plaintext.truncate(len);
                        let to_copy = len.min(buf.remaining());
                        buf.put_slice(&plaintext[..to_copy]);
                        if to_copy < len {
                            me.read_buf = plaintext;
                            me.read_pos = to_copy;
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Noise decrypt error: {e}"),
                    ))),
                }
            }
            Err(_) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for NoiseWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // Encrypt the data. Leave room for the poly1305 MAC tag (16 bytes).
        let chunk_size = buf.len().min(MAX_NOISE_MSG_LEN - 16);
        let chunk = &buf[..chunk_size];
        let mut encrypted = vec![0u8; chunk_size + 16];

        let enc_len = match me.noise.try_lock() {
            Ok(mut transport) => match transport.write_message(chunk, &mut encrypted) {
                Ok(len) => {
                    encrypted.truncate(len);
                    len
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Noise encrypt error: {e}"),
                    )));
                }
            },
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Write length prefix + encrypted data as a single frame.
        let len_bytes = (enc_len as u16).to_be_bytes();
        let mut frame = Vec::with_capacity(2 + enc_len);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&encrypted);

        match Pin::new(&mut me.tcp_writer).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n >= 2 + enc_len {
                    Poll::Ready(Ok(chunk_size))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp_writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp_writer).poll_shutdown(cx)
    }
}

/// Noise protocol transport for rsync connections.
///
/// Connects to a remote host over TCP, performs a Noise protocol handshake,
/// then returns encrypted async streams for the rsync protocol exchange.
pub struct NoiseDaemonTransport {
    config: NoiseConfig,
}

impl NoiseDaemonTransport {
    /// Create a new Noise transport.
    pub fn new(config: NoiseConfig) -> Self {
        Self { config }
    }

    /// Perform the Noise handshake as the initiator.
    async fn handshake(
        config: &NoiseConfig,
        tcp: &mut TcpStream,
    ) -> Result<TransportState> {
        let mut builder = Builder::new(config.pattern.protocol_name().parse().map_err(|e| {
            TransportError::ConnectionFailed {
                message: format!("invalid Noise protocol name: {e}"),
            }
        })?)
        .local_private_key(&config.local_private_key);

        if let Some(ref remote_pk) = config.remote_public_key {
            builder = builder.remote_public_key(remote_pk);
        }

        if let Some(ref psk) = config.psk {
            builder = builder.psk(0, psk);
        }

        let mut handshake = builder.build_initiator().map_err(|e| {
            TransportError::ConnectionFailed {
                message: format!("Noise handshake init failed: {e}"),
            }
        })?;

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];

        loop {
            if handshake.is_handshake_finished() {
                break;
            }

            if handshake.is_my_turn() {
                let len = handshake.write_message(&[], &mut buf).map_err(|e| {
                    TransportError::ConnectionFailed {
                        message: format!("Noise handshake write failed: {e}"),
                    }
                })?;
                tcp.write_all(&(len as u16).to_be_bytes())
                    .await
                    .map_err(io_err)?;
                tcp.write_all(&buf[..len]).await.map_err(io_err)?;
                tcp.flush().await.map_err(io_err)?;
            } else {
                let mut len_buf = [0u8; 2];
                tcp.read_exact(&mut len_buf).await.map_err(io_err)?;
                let msg_len = u16::from_be_bytes(len_buf) as usize;

                let mut msg = vec![0u8; msg_len];
                tcp.read_exact(&mut msg).await.map_err(io_err)?;

                handshake.read_message(&msg, &mut buf).map_err(|e| {
                    TransportError::ConnectionFailed {
                        message: format!("Noise handshake read failed: {e}"),
                    }
                })?;
            }
        }

        let transport = handshake.into_transport_mode().map_err(|e| {
            TransportError::ConnectionFailed {
                message: format!("Noise transport mode transition failed: {e}"),
            }
        })?;

        Ok(transport)
    }
}

impl Transport for NoiseDaemonTransport {
    fn connect(
        self: Box<Self>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let addr = format!("{}:{}", self.config.host, self.config.port);
            tracing::debug!(
                addr = %addr,
                pattern = ?self.config.pattern,
                "connecting via Noise protocol"
            );

            let mut tcp = tokio::time::timeout(
                self.config.connect_timeout,
                TcpStream::connect(&addr),
            )
            .await
            .map_err(|_| TransportError::ConnectionFailed {
                message: format!("connection to {addr} timed out"),
            })?
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("TCP connection to {addr} failed: {e}"),
            })?;

            let transport_state =
                Self::handshake(&self.config, &mut tcp).await?;

            tracing::debug!(addr = %addr, "Noise handshake completed");

            let stream = NoiseStream::new(tcp, transport_state);
            let (reader, writer) = stream.split();

            Ok(TransportStreams {
                reader: Box::new(reader),
                writer: Box::new(writer),
                background_task: None,
            })
        })
    }
}

fn io_err(e: std::io::Error) -> TransportError {
    TransportError::Io(std::sync::Arc::new(e))
}

/// Generate a random Curve25519 keypair for Noise protocol.
///
/// Returns `(private_key, public_key)` as 32-byte vectors.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let builder = Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("valid protocol name"),
    );
    let keypair = builder.generate_keypair().expect("keypair generation");
    (keypair.private, keypair.public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_config_defaults() {
        let config = NoiseConfig::default();
        assert_eq!(config.pattern, NoisePattern::XX);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.remote_public_key.is_none());
        assert!(config.psk.is_none());
    }

    #[test]
    fn test_noise_pattern_names() {
        assert_eq!(
            NoisePattern::XX.protocol_name(),
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(
            NoisePattern::IK.protocol_name(),
            "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        );
    }

    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = generate_keypair();
        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 32);

        let (private_key2, public_key2) = generate_keypair();
        assert_ne!(private_key, private_key2);
        assert_ne!(public_key, public_key2);
    }

    #[test]
    fn test_noise_builder_xx() {
        let (private_key, _public_key) = generate_keypair();
        let result = Builder::new(
            NoisePattern::XX
                .protocol_name()
                .parse()
                .unwrap(),
        )
        .local_private_key(&private_key)
        .build_initiator();
        assert!(result.is_ok());
    }

    #[test]
    fn test_noise_builder_ik_requires_remote_key() {
        let (init_priv, _) = generate_keypair();
        let (_, remote_pub) = generate_keypair();

        let result = Builder::new(
            NoisePattern::IK
                .protocol_name()
                .parse()
                .unwrap(),
        )
        .local_private_key(&init_priv)
        .remote_public_key(&remote_pub)
        .build_initiator();
        assert!(result.is_ok());
    }

    /// Simulate a full Noise_XX handshake between initiator and responder
    /// using in-memory buffers (no TCP).
    #[test]
    fn test_noise_xx_handshake_simulation() {
        let (init_priv, _init_pub) = generate_keypair();
        let (resp_priv, _resp_pub) = generate_keypair();

        let mut initiator = Builder::new(
            NoisePattern::XX.protocol_name().parse().unwrap(),
        )
        .local_private_key(&init_priv)
        .build_initiator()
        .unwrap();

        let mut responder = Builder::new(
            NoisePattern::XX.protocol_name().parse().unwrap(),
        )
        .local_private_key(&resp_priv)
        .build_responder()
        .unwrap();

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];
        let mut msg = vec![0u8; MAX_NOISE_MSG_LEN];

        // -> e
        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut msg).unwrap();

        // <- e, ee, s, es
        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..len], &mut msg).unwrap();

        // -> s, se
        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut msg).unwrap();

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        let mut init_transport = initiator.into_transport_mode().unwrap();
        let mut resp_transport = responder.into_transport_mode().unwrap();

        // Test data exchange.
        let plaintext = b"hello from initiator";
        let len = init_transport
            .write_message(plaintext, &mut buf)
            .unwrap();
        let len = resp_transport
            .read_message(&buf[..len], &mut msg)
            .unwrap();
        assert_eq!(&msg[..len], plaintext);

        let reply = b"hello from responder";
        let len = resp_transport
            .write_message(reply, &mut buf)
            .unwrap();
        let len = init_transport
            .read_message(&buf[..len], &mut msg)
            .unwrap();
        assert_eq!(&msg[..len], reply);
    }

    /// Test Noise_IK handshake simulation.
    #[test]
    fn test_noise_ik_handshake_simulation() {
        let (init_priv, _init_pub) = generate_keypair();
        let (resp_priv, resp_pub) = generate_keypair();

        let mut initiator = Builder::new(
            NoisePattern::IK.protocol_name().parse().unwrap(),
        )
        .local_private_key(&init_priv)
        .remote_public_key(&resp_pub)
        .build_initiator()
        .unwrap();

        let mut responder = Builder::new(
            NoisePattern::IK.protocol_name().parse().unwrap(),
        )
        .local_private_key(&resp_priv)
        .build_responder()
        .unwrap();

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];
        let mut msg = vec![0u8; MAX_NOISE_MSG_LEN];

        // -> e, es, s, ss
        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut msg).unwrap();

        // <- e, ee, se
        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..len], &mut msg).unwrap();

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        let mut init_transport = initiator.into_transport_mode().unwrap();
        let mut resp_transport = responder.into_transport_mode().unwrap();

        let data = b"test data over IK pattern";
        let len = init_transport.write_message(data, &mut buf).unwrap();
        let len = resp_transport.read_message(&buf[..len], &mut msg).unwrap();
        assert_eq!(&msg[..len], data);
    }

    #[tokio::test]
    async fn test_noise_full_duplex_handshake() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let (init_priv, _init_pub) = generate_keypair();
        let (resp_priv, _resp_pub) = generate_keypair();

        let server_handle = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server_stream);

            let mut responder = Builder::new(
                NoisePattern::XX.protocol_name().parse().unwrap(),
            )
            .local_private_key(&resp_priv)
            .build_responder()
            .unwrap();

            let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];

            while !responder.is_handshake_finished() {
                if !responder.is_my_turn() {
                    let mut len_buf = [0u8; 2];
                    reader.read_exact(&mut len_buf).await.unwrap();
                    let msg_len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg = vec![0u8; msg_len];
                    reader.read_exact(&mut msg).await.unwrap();
                    responder.read_message(&msg, &mut buf).unwrap();
                }

                if !responder.is_handshake_finished() && responder.is_my_turn() {
                    let len = responder.write_message(&[], &mut buf).unwrap();
                    writer
                        .write_all(&(len as u16).to_be_bytes())
                        .await
                        .unwrap();
                    writer.write_all(&buf[..len]).await.unwrap();
                    writer.flush().await.unwrap();
                }
            }

            assert!(responder.is_handshake_finished());
        });

        let (mut reader, mut writer) = tokio::io::split(client_stream);

        let mut initiator = Builder::new(
            NoisePattern::XX.protocol_name().parse().unwrap(),
        )
        .local_private_key(&init_priv)
        .build_initiator()
        .unwrap();

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];

        while !initiator.is_handshake_finished() {
            if initiator.is_my_turn() {
                let len = initiator.write_message(&[], &mut buf).unwrap();
                writer
                    .write_all(&(len as u16).to_be_bytes())
                    .await
                    .unwrap();
                writer.write_all(&buf[..len]).await.unwrap();
                writer.flush().await.unwrap();
            }

            if !initiator.is_handshake_finished() && !initiator.is_my_turn() {
                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await.unwrap();
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                reader.read_exact(&mut msg).await.unwrap();
                initiator.read_message(&msg, &mut buf).unwrap();
            }
        }

        assert!(initiator.is_handshake_finished());

        drop(writer);
        drop(reader);
        server_handle.await.unwrap();
    }
}
