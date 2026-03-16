//! Version-dependent wire format decisions, resolved once at handshake time.
//!
//! All encoding, field-presence, and behavioral differences between protocol
//! versions 27-31 are captured here. Codec and transfer code matches on
//! `WireFormat` fields -- raw version numbers never escape the handshake.

use super::handshake::compat_flags;

/// Integer encoding strategy on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntCodec {
    /// Proto < 30: 4-byte LE, sentinel longint, fixed NDX.
    Fixed,
    /// Proto >= 30: varint, varlong, delta-encoded NDX.
    Compact,
}

/// XMIT flag encoding in file list entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagsCodec {
    /// Proto < 28: single byte.
    Byte,
    /// Proto 28-29: byte + optional extended byte.
    ByteExtended,
    /// Proto >= 30 with CF_VARINT_FLIST_FLAGS.
    Varint,
}

/// Device number encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCodec {
    /// Proto < 28: single integer.
    SingleInt,
    /// Proto >= 28: separate major/minor (varint_minor when proto >= 30).
    MajorMinor { varint_minor: bool },
}

/// All version-dependent wire format decisions, resolved at handshake time.
///
/// Constructed once from `(version, compat_flags)` at the end of the
/// handshake. Adding a new protocol version means updating `WireFormat::new`;
/// the compiler enforces exhaustive matching on any new enum variants.
#[derive(Debug, Clone)]
pub struct WireFormat {
    // -- Encoding --
    /// Integer/varint encoding strategy.
    pub int_codec: IntCodec,
    /// XMIT flag encoding in file list entries.
    pub flags_codec: FlagsCodec,
    /// Device number encoding.
    pub device_codec: DeviceCodec,

    // -- Field presence --
    /// Proto >= 30: uid/gid carry inline username/group strings.
    pub has_inline_names: bool,
    /// Proto >= 31: mtime_nsec field present in file entries.
    pub has_nanoseconds: bool,
    /// Proto < 31: special files carry rdev.
    pub special_rdev: bool,

    // -- Behavior --
    /// Number of transfer phases: 1 (< 29) or 2 (>= 29).
    pub phase_count: u8,
    /// Proto >= 29: iflags sent alongside NDX in sender/receiver loops.
    pub has_iflags: bool,
    /// Proto >= 31: extra NDX_DONE goodbye exchange.
    pub has_error_exit_sync: bool,
    /// Proto >= 30 + CF_INC_RECURSE: incremental recursive file list.
    pub supports_incremental_flist: bool,
    /// Proto < 30: io_error sent after end-of-list marker.
    pub trailing_io_error: bool,

    // -- Diagnostics only --
    /// Kept for handshake logging and error messages. Not for branching.
    pub(crate) negotiated_version: u8,
}

impl WireFormat {
    /// Resolve all wire format decisions from the negotiated version and
    /// compatibility flags. This is the **only** place that knows about
    /// raw protocol version numbers.
    pub fn new(version: u8, compat_flags: u32) -> Self {
        let varint_flist = compat_flags & compat_flags::VARINT_FLIST_FLAGS != 0;

        Self {
            int_codec: if version >= 30 {
                IntCodec::Compact
            } else {
                IntCodec::Fixed
            },
            flags_codec: if varint_flist {
                FlagsCodec::Varint
            } else if version >= 28 {
                FlagsCodec::ByteExtended
            } else {
                FlagsCodec::Byte
            },
            device_codec: if version < 28 {
                DeviceCodec::SingleInt
            } else {
                DeviceCodec::MajorMinor {
                    varint_minor: version >= 30,
                }
            },
            has_inline_names: version >= 30,
            has_nanoseconds: version >= 31,
            special_rdev: version < 31,
            phase_count: if version >= 29 { 2 } else { 1 },
            has_iflags: version >= 29,
            has_error_exit_sync: version >= 31,
            supports_incremental_flist: version >= 30
                && (compat_flags & compat_flags::INC_RECURSE != 0),
            trailing_io_error: version < 30,
            negotiated_version: version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto27_all_fixed() {
        let wf = WireFormat::new(27, 0);
        assert_eq!(wf.int_codec, IntCodec::Fixed);
        assert_eq!(wf.flags_codec, FlagsCodec::Byte);
        assert_eq!(wf.device_codec, DeviceCodec::SingleInt);
        assert!(!wf.has_inline_names);
        assert!(!wf.has_nanoseconds);
        assert!(wf.special_rdev);
        assert_eq!(wf.phase_count, 1);
        assert!(!wf.has_iflags);
        assert!(!wf.has_error_exit_sync);
        assert!(!wf.supports_incremental_flist);
        assert!(wf.trailing_io_error);
    }

    #[test]
    fn proto28_extended_flags_and_major_minor() {
        let wf = WireFormat::new(28, 0);
        assert_eq!(wf.int_codec, IntCodec::Fixed);
        assert_eq!(wf.flags_codec, FlagsCodec::ByteExtended);
        assert_eq!(
            wf.device_codec,
            DeviceCodec::MajorMinor {
                varint_minor: false
            }
        );
        assert_eq!(wf.phase_count, 1);
        assert!(!wf.has_iflags);
    }

    #[test]
    fn proto29_iflags_and_two_phases() {
        let wf = WireFormat::new(29, 0);
        assert_eq!(wf.phase_count, 2);
        assert!(wf.has_iflags);
        assert!(!wf.has_error_exit_sync);
    }

    #[test]
    fn proto30_compact_with_varint_flist() {
        let flags = compat_flags::VARINT_FLIST_FLAGS | compat_flags::INC_RECURSE;
        let wf = WireFormat::new(30, flags);
        assert_eq!(wf.int_codec, IntCodec::Compact);
        assert_eq!(wf.flags_codec, FlagsCodec::Varint);
        assert_eq!(
            wf.device_codec,
            DeviceCodec::MajorMinor { varint_minor: true }
        );
        assert!(wf.has_inline_names);
        assert!(!wf.has_nanoseconds);
        assert!(wf.special_rdev);
        assert!(wf.supports_incremental_flist);
        assert!(!wf.trailing_io_error);
    }

    #[test]
    fn proto30_without_inc_recurse() {
        let flags = compat_flags::VARINT_FLIST_FLAGS;
        let wf = WireFormat::new(30, flags);
        assert!(!wf.supports_incremental_flist);
    }

    #[test]
    fn proto31_nanoseconds_and_goodbye() {
        let flags = compat_flags::VARINT_FLIST_FLAGS | compat_flags::INC_RECURSE;
        let wf = WireFormat::new(31, flags);
        assert!(wf.has_nanoseconds);
        assert!(!wf.special_rdev);
        assert!(wf.has_error_exit_sync);
        assert_eq!(wf.phase_count, 2);
    }
}
