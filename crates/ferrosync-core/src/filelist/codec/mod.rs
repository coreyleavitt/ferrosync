//! XMIT-flag codec for rsync file list entries.
//!
//! The rsync file list wire format uses delta encoding: each entry's fields
//! are compared against the previous entry, and XMIT flags indicate which
//! fields have changed. This module provides `encode_entry` and
//! `decode_entry` that maintain the necessary delta state.
//!
//! # Architecture
//!
//! The codec is split into focused modules:
//!
//! - **`flags`** -- `XmitFlags` newtype, `compute_xmit_flags`, flag encode/decode
//! - **`fields`** -- per-field encode/decode functions (filename, mtime, uid, etc.)
//! - **`hlink`** -- hard-link encoder/decoder state and field functions
//! - **`options`** -- `FileListOptions` bridging handshake to codec
//! - **`state`** -- `DeltaState` for delta encoding
//! - **`diagnostic`** -- `DecodedField` diagnostic decoder for conformance testing
//!
//! The `encode_entry` and `decode_entry` orchestrators call the same field
//! functions in the same order, making field-ordering mismatches impossible
//! by construction.
//!
//! Supports protocol versions 27-31.

pub mod diagnostic;
pub mod fields;
pub mod flags;
pub mod hlink;
pub mod options;
pub mod state;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Public API re-exports
// ---------------------------------------------------------------------------

pub use flags::{
    compute_xmit_flags, decode_xmit_flags, encode_end_of_flist, encode_xmit_flags, DecodedFlags,
    XmitFlags,
};
pub use hlink::{
    HardLinkAction, HardLinkDecoder, HardLinkEncoder, HardLinkInfo, HlinkEncodeResult,
};
pub use options::FileListOptions;
pub use state::DeltaState;

// Backward-compatible aliases for callers that use the old names.
pub use self::decode_entry as recv_file_entry;
pub use self::encode_end_of_flist as write_end_of_flist;
pub use self::encode_entry as send_file_entry;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProtocolError;

use super::entry::FileEntry;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result of reading a file list entry -- either an entry or end-of-list.
#[derive(Debug)]
pub enum ReadEntryResult {
    /// A file entry was read.
    Entry(Box<FileEntry>),
    /// End of file list, with optional I/O error code.
    EndOfList { io_error: i32 },
}

// ---------------------------------------------------------------------------
// Encoder orchestrator
// ---------------------------------------------------------------------------

/// Encode a file entry to the wire format.
///
/// The encoder orchestrator calls per-field functions in the canonical order.
/// Flag computation is separated into `compute_xmit_flags` (a pure function),
/// and each field encode function is independently testable.
#[allow(clippy::too_many_arguments)]
pub async fn encode_entry<W: AsyncWrite + Unpin>(
    w: &mut W,
    entry: &FileEntry,
    state: &mut DeltaState,
    opts: &FileListOptions,
    hlink_encoder: &mut HardLinkEncoder,
    hlink_info: Option<&HardLinkInfo>,
    entry_index: i32,
    iconv: Option<&crate::filelist::iconv::FilenameConverter>,
) -> Result<()> {
    // --- Filename encoding conversion (--iconv) ---
    let wire_name = if let Some(conv) = iconv {
        conv.to_wire(&entry.name)
    } else {
        entry.name.clone()
    };

    // --- Hard-link action ---
    let hlink_action = hlink::resolve_hlink_action(opts, hlink_info, hlink_encoder, entry_index);

    // --- Compute XMIT flags (pure function) ---
    let flags = compute_xmit_flags(entry, &wire_name, state, opts, &hlink_action);

    // --- Write XMIT flags ---
    encode_xmit_flags(w, flags, opts).await?;

    // --- Filename ---
    fields::encode_filename(w, &wire_name, state, flags, opts).await?;

    // --- Hard-link back-reference ---
    match hlink::encode_hlink(w, &hlink_action).await? {
        HlinkEncodeResult::Abbreviated => {
            // Duplicate entry: remaining fields were skipped.
            state::update_delta_state(state, entry);
            state.prev_name = wire_name;
            return Ok(());
        }
        HlinkEncodeResult::Continue => {}
    }

    // --- File length ---
    fields::encode_file_length(w, entry.len, opts).await?;

    // --- Modification time ---
    fields::encode_mtime(w, entry.mtime, flags, opts).await?;

    // --- Mtime nanoseconds ---
    fields::encode_mtime_nsec(w, entry.mtime_nsec, flags, opts).await?;

    // --- File mode ---
    fields::encode_mode(w, entry.mode, flags).await?;

    // --- UID ---
    fields::encode_uid(w, entry.uid, &entry.user_name, flags, opts).await?;

    // --- GID ---
    fields::encode_gid(w, entry.gid, &entry.group_name, flags, opts).await?;

    // --- Device numbers ---
    fields::encode_rdev(
        w,
        entry.mode,
        entry.rdev,
        entry.rdev_major(),
        entry.rdev_minor(),
        flags,
        opts,
    )
    .await?;

    // --- Symlink target ---
    fields::encode_symlink(w, entry.mode, &entry.link_target, opts).await?;

    // --- File checksum ---
    fields::encode_checksum(w, entry.mode, &entry.checksum, opts).await?;

    // --- Update delta state ---
    state::update_delta_state(state, entry);
    state.prev_name = wire_name;

    Ok(())
}

// ---------------------------------------------------------------------------
// Decoder orchestrator
// ---------------------------------------------------------------------------

/// Decode a single file entry from the wire.
///
/// Returns `ReadEntryResult::Entry` with the decoded entry, or
/// `ReadEntryResult::EndOfList` when the end-of-list marker is encountered.
///
/// The decoder orchestrator calls per-field functions in the same order as
/// the encoder, ensuring symmetric encode/decode.
pub async fn decode_entry<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &mut DeltaState,
    opts: &FileListOptions,
    hlink_decoder: &mut HardLinkDecoder,
    prev_entries: &[FileEntry],
    iconv: Option<&crate::filelist::iconv::FilenameConverter>,
) -> Result<ReadEntryResult> {
    // --- Read XMIT flags ---
    let flags = match decode_xmit_flags(r, opts).await? {
        DecodedFlags::Entry(f) => f,
        DecodedFlags::EndOfList { io_error } => {
            return Ok(ReadEntryResult::EndOfList { io_error });
        }
    };

    // --- Filename ---
    let name = fields::decode_filename(r, state, flags, opts, iconv).await?;

    // --- Hard-link back-reference ---
    match hlink::decode_hlink(
        r,
        flags,
        opts,
        hlink_decoder,
        prev_entries,
        name.clone(),
        state,
    )
    .await?
    {
        hlink::HlinkDecodeResult::Abbreviated(entry) => {
            return Ok(ReadEntryResult::Entry(entry));
        }
        hlink::HlinkDecodeResult::Continue => {}
    }

    // --- File length ---
    let len = fields::decode_file_length(r, opts).await?;

    // --- Modification time ---
    let mtime = fields::decode_mtime(r, state, flags, opts).await?;

    // --- Mtime nanoseconds ---
    let mtime_nsec = fields::decode_mtime_nsec(r, flags, opts).await?;

    // --- File mode ---
    let mode = fields::decode_mode(r, state, flags).await?;

    // --- UID ---
    let (uid, user_name) = fields::decode_uid(r, state, flags, opts).await?;

    // --- GID ---
    let (gid, group_name) = fields::decode_gid(r, state, flags, opts).await?;

    // --- Device numbers ---
    let rdev = fields::decode_rdev(r, mode, state, flags, opts).await?;

    // --- Symlink target ---
    let link_target = fields::decode_symlink(r, mode, opts).await?;

    // --- File checksum ---
    let checksum = fields::decode_checksum(r, mode, opts).await?;

    let entry = FileEntry {
        name,
        len,
        mtime,
        mtime_nsec,
        mode,
        uid,
        gid,
        rdev,
        link_target,
        checksum,
        flags: flags.raw(),
        user_name,
        group_name,
        hlink_source: None,
        hard_link_info: None,
    };

    // --- Update delta state ---
    state::update_delta_state(state, &entry);

    Ok(ReadEntryResult::Entry(Box::new(entry)))
}
