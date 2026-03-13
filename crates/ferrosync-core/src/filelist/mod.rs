//! File list encoding, decoding, and sorting for the rsync wire protocol.
//!
//! This module implements Phase 2 of the ferrosync roadmap:
//! - `entry` -- `FileEntry` struct with file metadata
//! - `xmit` -- XMIT flag constants
//! - `codec` -- Delta-encoded file entry encoder/decoder
//! - `sort` -- Canonical sort order matching rsync's `f_name_cmp`
//! - `incremental` -- Incremental file list exchange (protocol >= 30)

pub mod codec;
pub mod entry;
pub mod incremental;
pub mod sort;
pub mod xmit;
