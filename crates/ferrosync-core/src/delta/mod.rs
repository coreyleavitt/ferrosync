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
pub mod matcher;
pub mod sum;
pub mod token;
