//! Rsync daemon server implementation.
//!
//! This crate provides the server-side components for running an rsync daemon
//! that accepts connections on TCP port 873 (by default), serves configured
//! modules, and performs the rsync protocol exchange.
//!
//! # Architecture
//!
//! The daemon server consists of:
//!
//! - [`config`]: Parser for `rsyncd.conf` configuration files.
//! - [`module`]: Module registry managing named filesystem exports.
//! - [`auth`]: MD5-based challenge-response authentication.
//! - [`listener`]: TCP listener that accepts and dispatches connections.
//! - [`session`]: Server-side rsync protocol session handler.
//!
//! # Protocol Flow (server perspective)
//!
//! 1. Accept TCP connection from client.
//! 2. Send greeting: `@RSYNCD: <major>.<minor>\n`.
//! 3. Read client greeting: `@RSYNCD: <major>.<minor>\n`.
//! 4. Read module name (or `#list` for module listing).
//! 5. If module requires auth: send `@RSYNCD: AUTHREQD <challenge>\n`,
//!    read `<user> <response>\n`, verify credentials.
//! 6. Send `@RSYNCD: OK\n`.
//! 7. Read rsync arguments from client (newline-terminated, empty line ends).
//! 8. Begin binary rsync protocol exchange.

pub mod auth;
pub mod config;
pub mod listener;
pub mod module;
pub mod session;
