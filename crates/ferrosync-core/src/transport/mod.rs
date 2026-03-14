//! Transport layer for rsync connections.
//!
//! The [`Transport`] trait abstracts how we connect to a remote rsync process.
//! Implementations handle:
//!
//! - **Local:** Spawn `rsync --server` as a child process, pipe via stdin/stdout.
//! - **SSH:** Spawn `ssh <host> rsync --server ...` (Phase 6).
//! - **Daemon:** TCP connection to port 873 (Phase 6).

pub mod daemon;
pub mod local;
pub mod noise;
pub mod quic;
pub mod ssh;
pub mod ssh_config;
pub mod tls;

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// A pair of async read/write streams connected to a remote rsync process.
pub struct TransportStreams {
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    /// Background task handle (e.g., child process monitor). Aborted on drop.
    pub(crate) background_task: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for TransportStreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportStreams").finish_non_exhaustive()
    }
}

impl Drop for TransportStreams {
    fn drop(&mut self) {
        if let Some(handle) = self.background_task.take() {
            handle.abort();
        }
    }
}

/// Trait for establishing a connection to an rsync process.
///
/// Implementations spawn or connect to a remote rsync, returning async streams
/// for the protocol exchange. The transport is consumed on connect -- each
/// `Transport` instance represents a single connection attempt.
///
/// Object-safe: returns `Pin<Box<dyn Future>>` so the trait can be used as
/// `dyn Transport`. Designed to support server-mode in v2: the same trait can
/// accept incoming connections by implementing `connect()` on a listener wrapper.
pub trait Transport: Send {
    /// Establish the connection and return read/write streams.
    fn connect(self: Box<Self>) -> Pin<Box<dyn Future<Output = Result<TransportStreams>> + Send>>;
}
