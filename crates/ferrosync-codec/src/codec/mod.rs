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
pub mod visitor;

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

use ferrosync_types::error::ProtocolError;

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
/// Uses the `FieldVisitor` pattern: field order is defined once in
/// `traverse_fields`, and the `Encoder` visitor writes each field to
/// the wire. Adding a new field requires implementing `visit_X` on the
/// visitor trait -- the compiler forces all three visitors (Encoder,
/// Decoder, DiagnosticDecoder) to implement it.
///
/// ## Adding a new field
///
/// 1. Add `encode_X` / `decode_X` to `fields.rs`
/// 2. Add field to `visitor::FieldValues`
/// 3. Add `async fn visit_X(...)` to `visitor::FieldVisitor`
/// 4. Implement `visit_X` in Encoder, Decoder, and DiagnosticDecoder
/// 5. Add `visitor.visit_X(ctx).await?;` in `visitor::traverse_fields`
/// 6. Update `compute_xmit_flags()` in `flags.rs` if delta-encoded
/// 7. Update `DeltaState` and `update_delta_state()` in `state.rs`
#[allow(clippy::too_many_arguments)]
pub async fn encode_entry<W: AsyncWrite + Unpin>(
    w: &mut W,
    entry: &FileEntry,
    state: &mut DeltaState,
    opts: &FileListOptions,
    hlink_encoder: &mut HardLinkEncoder,
    hlink_info: Option<&HardLinkInfo>,
    entry_index: i32,
    iconv: Option<&crate::iconv::FilenameConverter>,
    acl_encoder: &mut crate::acl::AclEncoder,
    xattr_encoder: &mut crate::xattr::XattrEncoder,
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
    let xmit_flags = compute_xmit_flags(entry, &wire_name, state, opts, &hlink_action);

    // --- Write XMIT flags ---
    encode_xmit_flags(w, xmit_flags, opts).await?;

    // --- Filename ---
    fields::encode_filename(w, &wire_name, state, xmit_flags, opts).await?;

    // --- Hard-link back-reference ---
    match hlink::encode_hlink(w, &hlink_action).await? {
        HlinkEncodeResult::Abbreviated => {
            state::update_delta_state(state, entry);
            state.prev_name = wire_name;
            return Ok(());
        }
        HlinkEncodeResult::Continue => {}
    }

    // --- Metadata fields via visitor traversal ---
    let mut values = visitor::FieldValues::from_entry(entry, wire_name);
    {
        let mut ctx = visitor::FieldContext {
            flags: xmit_flags,
            state,
            opts,
            values: &mut values,
        };
        let mut enc = visitor::Encoder {
            writer: w,
            acl_encoder,
            xattr_encoder,
        };
        visitor::traverse_fields(&mut enc, &mut ctx).await?;
    }

    // --- Update delta state (after ctx is dropped) ---
    values.update_state(state);

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
/// Uses the `FieldVisitor` pattern: `traverse_fields` defines the field
/// order once, and the `Decoder` visitor reads each field from the wire.
#[allow(clippy::too_many_arguments)]
pub async fn decode_entry<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &mut DeltaState,
    opts: &FileListOptions,
    hlink_decoder: &mut HardLinkDecoder,
    prev_entries: &[FileEntry],
    iconv: Option<&crate::iconv::FilenameConverter>,
    acl_decoder: &mut crate::acl::AclDecoder,
    xattr_decoder: &mut crate::xattr::XattrDecoder,
) -> Result<ReadEntryResult> {
    // --- Read XMIT flags ---
    let xmit_flags = match decode_xmit_flags(r, opts).await? {
        DecodedFlags::Entry(f) => f,
        DecodedFlags::EndOfList { io_error } => {
            return Ok(ReadEntryResult::EndOfList { io_error });
        }
    };

    // --- Filename ---
    let name = fields::decode_filename(r, state, xmit_flags, opts, iconv).await?;

    // --- Hard-link back-reference ---
    match hlink::decode_hlink(
        r,
        xmit_flags,
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

    // --- Metadata fields via visitor traversal ---
    let mut values = visitor::FieldValues {
        name,
        ..Default::default()
    };
    {
        let mut ctx = visitor::FieldContext {
            flags: xmit_flags,
            state,
            opts,
            values: &mut values,
        };
        let mut dec = visitor::Decoder {
            reader: r,
            acl_decoder,
            xattr_decoder,
        };
        visitor::traverse_fields(&mut dec, &mut ctx).await?;
    }

    let entry = values.into_entry(xmit_flags);

    // --- Update delta state (after ctx is dropped) ---
    state::update_delta_state(state, &entry);

    Ok(ReadEntryResult::Entry(Box::new(entry)))
}
