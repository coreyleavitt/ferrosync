//! Centralized protocol constants.
//!
//! All wire-format sizing constants live here so that every module
//! references a single source of truth. The canonical definitions now
//! live in `ferrosync-types`; this module re-exports them for
//! backward compatibility.

pub use ferrosync_types::constants::*;
