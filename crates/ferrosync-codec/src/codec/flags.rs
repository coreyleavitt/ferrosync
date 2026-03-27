//! XMIT flag type and flag-level encode/decode.
//!
//! `XmitFlags` is a newtype over `u32` providing named accessors for each
//! flag bit and type-safe flag manipulation. Flag encoding/decoding and
//! `compute_xmit_flags` (a pure function extracting flag computation from
//! the encoder) live here.

use tokio::io::{AsyncRead, AsyncWrite};

use ferrosync_protocol::varint::{self, read_byte, read_varint, write_byte, write_varint};
use ferrosync_protocol::wire_format::FlagsCodec;
use ferrosync_types::error::ProtocolError;

use super::options::FileListOptions;
use super::state::DeltaState;
use super::HardLinkAction;
use crate::entry::{FileEntry, S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT, S_IFSOCK};
use crate::xmit::*;
use ferrosync_protocol::wire_format::DeviceCodec;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// XmitFlags newtype
// ---------------------------------------------------------------------------

/// Type-safe wrapper around the raw XMIT flag word.
///
/// Provides named accessors for each flag bit, preventing accidental
/// confusion with other `u32` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XmitFlags(u32);

impl XmitFlags {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    // --- Flag accessors ---

    pub const fn top_dir(self) -> bool {
        self.0 & XMIT_TOP_DIR != 0
    }

    pub const fn same_mode(self) -> bool {
        self.0 & XMIT_SAME_MODE != 0
    }

    pub const fn same_rdev_pre28(self) -> bool {
        self.0 & XMIT_SAME_RDEV_PRE28 != 0
    }

    pub const fn extended_flags(self) -> bool {
        self.0 & XMIT_EXTENDED_FLAGS != 0
    }

    pub const fn same_uid(self) -> bool {
        self.0 & XMIT_SAME_UID != 0
    }

    pub const fn same_gid(self) -> bool {
        self.0 & XMIT_SAME_GID != 0
    }

    pub const fn same_name(self) -> bool {
        self.0 & XMIT_SAME_NAME != 0
    }

    pub const fn long_name(self) -> bool {
        self.0 & XMIT_LONG_NAME != 0
    }

    pub const fn same_time(self) -> bool {
        self.0 & XMIT_SAME_TIME != 0
    }

    pub const fn same_rdev_major(self) -> bool {
        self.0 & XMIT_SAME_RDEV_MAJOR != 0
    }

    pub const fn hlinked(self) -> bool {
        self.0 & XMIT_HLINKED != 0
    }

    pub const fn hlink_first(self) -> bool {
        self.0 & XMIT_HLINK_FIRST != 0
    }

    pub const fn user_name_follows(self) -> bool {
        self.0 & XMIT_USER_NAME_FOLLOWS != 0
    }

    pub const fn group_name_follows(self) -> bool {
        self.0 & XMIT_GROUP_NAME_FOLLOWS != 0
    }

    pub const fn mod_nsec(self) -> bool {
        self.0 & XMIT_MOD_NSEC != 0
    }
}

impl std::ops::BitOr for XmitFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for XmitFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for XmitFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Flag constants as XmitFlags values
// ---------------------------------------------------------------------------

impl XmitFlags {
    pub const TOP_DIR: Self = Self(XMIT_TOP_DIR);
    pub const SAME_MODE: Self = Self(XMIT_SAME_MODE);
    pub const SAME_RDEV_PRE28: Self = Self(XMIT_SAME_RDEV_PRE28);
    pub const EXTENDED_FLAGS: Self = Self(XMIT_EXTENDED_FLAGS);
    pub const SAME_UID: Self = Self(XMIT_SAME_UID);
    pub const SAME_GID: Self = Self(XMIT_SAME_GID);
    pub const SAME_NAME: Self = Self(XMIT_SAME_NAME);
    pub const LONG_NAME: Self = Self(XMIT_LONG_NAME);
    pub const SAME_TIME: Self = Self(XMIT_SAME_TIME);
    pub const SAME_RDEV_MAJOR: Self = Self(XMIT_SAME_RDEV_MAJOR);
    pub const HLINKED: Self = Self(XMIT_HLINKED);
    pub const HLINK_FIRST: Self = Self(XMIT_HLINK_FIRST);
    pub const USER_NAME_FOLLOWS: Self = Self(XMIT_USER_NAME_FOLLOWS);
    pub const GROUP_NAME_FOLLOWS: Self = Self(XMIT_GROUP_NAME_FOLLOWS);
    pub const MOD_NSEC: Self = Self(XMIT_MOD_NSEC);
}

// ---------------------------------------------------------------------------
// compute_xmit_flags -- pure function
// ---------------------------------------------------------------------------

/// Compute the XMIT flags for a file entry by comparing it against the
/// previous delta state.
///
/// This is a pure function with no I/O, making flag computation independently
/// testable and separating it from the encoding logic.
pub fn compute_xmit_flags(
    entry: &FileEntry,
    wire_name: &[u8],
    state: &DeltaState,
    opts: &FileListOptions,
    hlink_action: &HardLinkAction,
) -> XmitFlags {
    // Preserve TOP_DIR if the entry has it set.
    let mut flags = XmitFlags::from_raw(entry.flags) & XmitFlags::TOP_DIR;

    // Hard-link flags.
    match hlink_action {
        HardLinkAction::FirstOccurrence => {
            flags |= XmitFlags::HLINKED | XmitFlags::HLINK_FIRST;
        }
        HardLinkAction::DuplicateOf(_) => {
            flags |= XmitFlags::HLINKED;
        }
        HardLinkAction::NotHardLinked => {}
    }

    // Filename prefix compression.
    let common_prefix = common_prefix_len(&state.prev_name, wire_name);
    if common_prefix > 0 {
        flags |= XmitFlags::SAME_NAME;
    }
    let suffix_len = wire_name.len() - common_prefix;
    if suffix_len > 255 {
        flags |= XmitFlags::LONG_NAME;
    }

    // Delta-encoded fields.
    //
    // C ref: flist.c send_file_entry -- rsync gates each SAME_* flag on
    // `*lastname`, which is false for the first entry (static buffer is
    // zero-initialized). This prevents compressing against the default
    // initial state, ensuring the first entry always sends all fields.
    // We mirror this with `has_prev`.
    let has_prev = !state.prev_name.is_empty();

    if entry.mtime.secs() == state.prev_mtime && has_prev {
        flags |= XmitFlags::SAME_TIME;
    }
    if entry.mode == state.prev_mode && has_prev {
        flags |= XmitFlags::SAME_MODE;
    }
    // C ref: flist.c -- rsync's condition is:
    //   if (!preserve_uid || (uid == prev_uid && *lastname))
    //       xflags |= XMIT_SAME_UID;
    // When preservation is disabled, SAME_UID is always set (field never sent).
    // When enabled, only set if uid matches AND there was a previous entry.
    if !opts.preserve_uid || (entry.uid == state.prev_uid && has_prev) {
        flags |= XmitFlags::SAME_UID;
    }
    if !opts.preserve_gid || (entry.gid == state.prev_gid && has_prev) {
        flags |= XmitFlags::SAME_GID;
    }

    // Device flags.
    if should_send_rdev(entry.mode, opts) {
        match opts.wire.device_codec {
            DeviceCodec::MajorMinor { .. } => {
                if entry.rdev_major() == state.prev_rdev_major {
                    flags |= XmitFlags::SAME_RDEV_MAJOR;
                }
            }
            DeviceCodec::SingleInt => {
                if entry.rdev == state.prev_rdev {
                    flags |= XmitFlags::SAME_RDEV_PRE28;
                }
            }
        }
    }

    // Mtime nanoseconds.
    if opts.wire.has_nanoseconds && entry.mtime_nsec != 0 {
        flags |= XmitFlags::MOD_NSEC;
    }

    // Username/group name follows.
    if opts.preserve_uid
        && !flags.same_uid()
        && opts.wire.has_inline_names
        && !entry.user_name.is_empty()
        && entry.user_name != state.prev_user_name
    {
        flags |= XmitFlags::USER_NAME_FOLLOWS;
    }
    if opts.preserve_gid
        && !flags.same_gid()
        && opts.wire.has_inline_names
        && !entry.group_name.is_empty()
        && entry.group_name != state.prev_group_name
    {
        flags |= XmitFlags::GROUP_NAME_FOLLOWS;
    }

    flags
}

// ---------------------------------------------------------------------------
// Flag encoding/decoding
// ---------------------------------------------------------------------------

/// Result of decoding XMIT flags -- either flags for an entry, or end-of-list.
pub enum DecodedFlags {
    /// Entry flags decoded successfully.
    Entry(XmitFlags),
    /// End-of-list marker encountered.
    EndOfList { io_error: i32 },
}

/// Decode XMIT flags from the wire.
///
/// Returns `DecodedFlags::Entry(flags)` for a normal entry, or
/// `DecodedFlags::EndOfList` when the end-of-list marker is encountered.
pub async fn decode_xmit_flags<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
) -> Result<DecodedFlags> {
    match opts.wire.flags_codec {
        FlagsCodec::Varint => {
            let f = read_varint(r).await?;
            if f == 0 {
                let io_error = read_varint(r).await? as i32;
                return Ok(DecodedFlags::EndOfList { io_error });
            }
            Ok(DecodedFlags::Entry(XmitFlags::from_raw(f)))
        }
        FlagsCodec::ByteExtended => {
            let first_byte = read_byte(r).await?;
            if first_byte == 0 {
                return Ok(DecodedFlags::EndOfList { io_error: 0 });
            }
            let mut f = first_byte as u32;
            if (f & XMIT_EXTENDED_FLAGS) != 0 {
                let second_byte = read_byte(r).await?;
                f |= (second_byte as u32) << 8;
                if f == (XMIT_EXTENDED_FLAGS | XMIT_IO_ERROR_ENDLIST) {
                    let io_error = read_varint(r).await? as i32;
                    return Ok(DecodedFlags::EndOfList { io_error });
                }
            }
            Ok(DecodedFlags::Entry(XmitFlags::from_raw(f)))
        }
        FlagsCodec::Byte => {
            let first_byte = read_byte(r).await?;
            if first_byte == 0 {
                return Ok(DecodedFlags::EndOfList { io_error: 0 });
            }
            Ok(DecodedFlags::Entry(XmitFlags::from_raw(first_byte as u32)))
        }
    }
}

/// Encode XMIT flags to the wire.
pub async fn encode_xmit_flags<W: AsyncWrite + Unpin>(
    w: &mut W,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    let raw = flags.raw();
    match opts.wire.flags_codec {
        FlagsCodec::Varint => {
            // Varint mode: if flags would be 0, send XMIT_EXTENDED_FLAGS instead.
            let wire_flags = if raw == 0 { XMIT_EXTENDED_FLAGS } else { raw };
            write_varint(w, wire_flags).await?;
        }
        FlagsCodec::ByteExtended => {
            if (raw & 0xFF00) != 0 || raw == 0 {
                let wire_flags = raw | XMIT_EXTENDED_FLAGS;
                varint::write_shortint(w, wire_flags as u16).await?;
            } else {
                write_byte(w, raw as u8).await?;
            }
        }
        FlagsCodec::Byte => {
            let mut low = (raw & 0xFF) as u8;
            if low == 0 {
                low = XMIT_TOP_DIR as u8;
            }
            write_byte(w, low).await?;
        }
    }
    Ok(())
}

/// Write the end-of-file-list marker.
pub async fn encode_end_of_flist<W: AsyncWrite + Unpin>(
    w: &mut W,
    io_error: i32,
    opts: &FileListOptions,
) -> Result<()> {
    match opts.wire.flags_codec {
        FlagsCodec::Varint => {
            write_varint(w, 0).await?;
            write_varint(w, io_error as u32).await?;
        }
        FlagsCodec::ByteExtended if io_error != 0 => {
            varint::write_shortint(w, (XMIT_EXTENDED_FLAGS | XMIT_IO_ERROR_ENDLIST) as u16).await?;
            write_varint(w, io_error as u32).await?;
        }
        _ => {
            write_byte(w, 0).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine if rdev should be sent for this file mode.
pub(crate) fn should_send_rdev(mode: u32, opts: &FileListOptions) -> bool {
    let ft = mode & S_IFMT;
    let is_device = ft == S_IFBLK || ft == S_IFCHR;
    let is_special = ft == S_IFIFO || ft == S_IFSOCK;

    if opts.preserve_devices && is_device {
        return true;
    }
    if opts.preserve_specials && is_special && opts.wire.special_rdev {
        return true;
    }
    false
}

/// Compute the length of the common prefix between two byte slices.
pub(crate) fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    // Cap at 255 since the prefix length is sent as a single byte.
    let max = a.len().min(b.len()).min(255);
    a.iter()
        .zip(b.iter())
        .take(max)
        .take_while(|(x, y)| x == y)
        .count()
}
