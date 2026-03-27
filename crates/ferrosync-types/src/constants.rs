//! Centralized protocol constants.
//!
//! All wire-format sizing constants live here so that every module
//! references a single source of truth.

/// Typical data chunk size for multiplexed I/O and literal token
/// payloads (matches rsync's IO_BUFFER_SIZE, 32 KiB).
pub const DATA_CHUNK_SIZE: usize = 32 * 1024;

/// Write buffer size for the multiplexer.
///
/// Two `DATA_CHUNK_SIZE` frames fit comfortably, allowing multiple
/// messages to coalesce before flushing.
pub const MPLEX_BUF_SIZE: usize = DATA_CHUNK_SIZE * 2;

/// Maximum size for a single wire allocation (256 MiB).
///
/// Prevents OOM from malicious or corrupted wire values.
pub const MAX_WIRE_ALLOC: usize = 256 * 1024 * 1024;

/// Minimum block length used by block-size computation.
pub const MIN_BLOCK_LEN: i32 = 700;

/// Maximum block length (128 KiB) used by block-size computation.
pub const MAX_BLOCK_LEN: i32 = 1 << 17;

/// Base tag value for multiplexed message framing.
pub const MPLEX_BASE: u8 = 7;
