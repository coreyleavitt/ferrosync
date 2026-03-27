//! rsync file list codec: entry encoding, ACL/xattr wire format, file list exchange.
//!
//! This crate provides the wire-level encoding and decoding for rsync file lists,
//! including delta-encoded file entries, ACL/xattr wire format, sort ordering,
//! incremental file list exchange, and chmod spec parsing.

pub mod acl;
pub mod chmod;
pub mod codec;
pub mod entry;
pub mod exchange;
pub mod iconv;
pub mod incremental;
pub mod sort;
pub mod xattr;
pub mod xmit;
