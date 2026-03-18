//! Delta transfer: block checksums, matching, and wire-format tokens.
//!
//! This module implements rsync's delta transfer algorithm:
//!
//! 1. **Signatures** (`sum`): The receiver computes rolling + strong checksums
//!    for each block of the basis file and sends them to the sender.
//! 2. **Matching** (`matcher`): The sender scans the source file with a rolling
//!    checksum, looking up matches in the signature hash table.
//! 3. **Tokens** (`token`): Match/literal operations are encoded as wire-format
//!    tokens and sent to the receiver.
//! 4. **Checksums** (`checksum`): MD4 (proto < 30) or MD5 (proto >= 30) for
//!    block-level and file-level verification.

pub mod checksum;
pub mod chunker;
pub mod matcher;
pub mod sum;
pub mod token;

use crate::protocol::handshake::{ChecksumType, NegotiatedProtocol};
use crate::protocol::wire_format::IntCodec;

/// Protocol parameters needed for delta computation.
///
/// Encapsulates checksum algorithm, seed, and version-dependent behavior
/// so callers don't need to thread individual protocol fields.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolContext {
    pub seed: i32,
    pub checksum_type: ChecksumType,
    pub char_offset: u32,
    pub proper_seed_order: bool,
}

impl ProtocolContext {
    /// Create from a negotiated protocol (post-handshake).
    pub fn from_protocol(proto: &NegotiatedProtocol) -> Self {
        let char_offset = if proto.wire.int_codec == IntCodec::Compact {
            checksum::CHAR_OFFSET_V30
        } else {
            checksum::CHAR_OFFSET_OLD
        };
        Self {
            seed: proto.seed,
            checksum_type: proto.checksum,
            char_offset,
            proper_seed_order: proto.proper_seed_order,
        }
    }

    /// Convenience for tests using protocol >= 30 defaults.
    #[cfg(test)]
    pub fn test_default(seed: i32, checksum_type: ChecksumType) -> Self {
        Self {
            seed,
            checksum_type,
            char_offset: checksum::CHAR_OFFSET_V30,
            proper_seed_order: true,
        }
    }
}
