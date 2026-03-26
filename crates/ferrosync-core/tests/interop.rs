//! Interop tests: end-to-end transfers against real rsync.
//!
//! Verifies that ferrosync produces correct results when transferring
//! files to/from a real rsync binary over SSH.
//!
//! Requires Docker:
//! ```sh
//! docker compose -f docker-compose.test.yml run ferrosync-dev \
//!     cargo test -p ferrosync-core --test interop
//! ```
//!
//! Gated behind `FERROSYNC_SSH_TEST=1` env var.
#![cfg(unix)]
#![allow(unused_imports)]

#[macro_use]
mod common;

mod interop {
    pub mod auth;
    pub mod push;
    pub mod pull;
    pub mod reverse;
    pub mod native;
    pub mod scenarios;
}
