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

pub use ferrosync_codec::acl;
pub use ferrosync_codec::chmod;
pub use ferrosync_delta as delta;
pub use ferrosync_engine as engine;
pub mod filelist;
pub use ferrosync_filter as filter;
pub use ferrosync_fs as fs;
pub use ferrosync_protocol as protocol;
pub mod server;
pub use ferrosync_codec::xattr;
pub use ferrosync_transport as transport;

// Re-export from ferrosync-types for backward compatibility.
// All existing `use crate::{error,options,stats,types}::*` imports
// continue to resolve through these module-level re-exports.
pub use ferrosync_types::error;
pub use ferrosync_types::options;
pub use ferrosync_types::stats;
pub use ferrosync_types::types;

pub use ferrosync_types::FerrosyncError;
pub type Result<T> = std::result::Result<T, FerrosyncError>;

/// Convenience re-exports for common usage.
pub mod prelude {
    pub use crate::engine::session::{SyncDirection, SyncSession};
    pub use crate::error::FerrosyncError;
    pub use crate::fs::FileSystem;
    pub use crate::options::{TransferConfig, TransferOptions};
    pub use crate::transport::{Transport, TransportStreams};
}
