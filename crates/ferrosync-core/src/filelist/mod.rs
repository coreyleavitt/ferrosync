//! File list encoding, decoding, scanning, and sorting for the rsync wire protocol.
//!
//! This module re-exports from `ferrosync-codec` and `ferrosync-scanner`
//! for backward compatibility.

pub use ferrosync_codec::codec;
pub use ferrosync_codec::entry;
pub use ferrosync_codec::exchange;
pub use ferrosync_codec::iconv;
pub use ferrosync_codec::incremental;
pub use ferrosync_codec::sort;
pub use ferrosync_codec::xmit;

pub use ferrosync_scanner as scanner;
pub use ferrosync_scanner::walk;
