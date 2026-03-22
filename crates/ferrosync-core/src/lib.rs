//! # ferrosync-core
//!
//! A Rust implementation of the rsync wire protocol (protocol versions 27-31).
//!
//! This crate provides the building blocks for rsync-compatible file
//! synchronization: protocol handshake, file list exchange, rolling-checksum
//! delta transfer, and multiplexed I/O framing.
//!
//! ## Quick start
//!
//! ```ignore
//! use ferrosync_core::prelude::*;
//! use ferrosync_core::transport::daemon::{DaemonTransport, DaemonTransportConfig};
//! use ferrosync_core::engine::session::build_server_options;
//!
//! let options = TransferOptions::builder()
//!     .recursive(true)
//!     .preserve_times(true)
//!     .source("/src".into())
//!     .dest("/dst".into())
//!     .build();
//!
//! let config = DaemonTransportConfig {
//!     host: "server".into(),
//!     module: "data".into(),
//!     ..Default::default()
//! };
//! let server_opts = build_server_options(&options, true);
//! let transport = DaemonTransport::new(config, true, &server_opts);
//! let session = SyncSession::new(transport, options, fs, SyncDirection::Push);
//! let result = session.run().await?;
//! ```

pub mod chmod;
pub mod delta;
pub mod engine;
pub mod error;
pub mod filelist;
pub mod filter;
pub mod fs;
pub mod options;
pub mod protocol;
pub mod server;
pub mod stats;
pub mod transport;

pub use error::FerrosyncError;
pub type Result<T> = std::result::Result<T, FerrosyncError>;

/// Convenience re-exports for common usage.
pub mod prelude {
    pub use crate::engine::session::{SyncDirection, SyncSession};
    pub use crate::error::FerrosyncError;
    pub use crate::fs::FileSystem;
    pub use crate::options::TransferOptions;
    pub use crate::transport::{Transport, TransportStreams};
}
