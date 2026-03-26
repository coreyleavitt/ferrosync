//! Hard-link encoding and decoding.
//!
//! Tracks (dev, ino) pairs on the encoder side to detect duplicate inodes,
//! and maps flist indices on the decoder side to resolve back-references.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProtocolError;
use crate::protocol::varint::{read_varint, write_varint};

use super::flags::XmitFlags;
use super::options::FileListOptions;
use super::state::DeltaState;
use crate::filelist::entry::FileEntry;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Hard-link identity from the source filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardLinkInfo {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
}

/// What to do with a file during hard-link encoding.
#[derive(Debug)]
pub enum HardLinkAction {
    /// File is not a hard-link candidate (nlink <= 1).
    NotHardLinked,
    /// First occurrence of this dev+ino pair in the flist.
    FirstOccurrence,
    /// Duplicate of an earlier entry at the given flist index.
    DuplicateOf(i32),
}

// ---------------------------------------------------------------------------
// Encoder state
// ---------------------------------------------------------------------------

/// Encoder-side state for hard-link deduplication.
///
/// Tracks which (dev, ino) pairs have been seen and their flist indices.
#[derive(Debug, Default)]
pub struct HardLinkEncoder {
    seen: HashMap<(u64, u64), i32>,
}

impl HardLinkEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this file is a hard-link duplicate.
    pub fn check(&mut self, info: &HardLinkInfo, index: i32) -> HardLinkAction {
        if info.nlink <= 1 {
            return HardLinkAction::NotHardLinked;
        }
        let key = (info.dev, info.ino);
        if let Some(&first_index) = self.seen.get(&key) {
            HardLinkAction::DuplicateOf(first_index)
        } else {
            self.seen.insert(key, index);
            HardLinkAction::FirstOccurrence
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder state
// ---------------------------------------------------------------------------

/// Decoder-side state for hard-link resolution.
///
/// Maps flist indices of duplicate entries to their first occurrence.
#[derive(Debug, Default)]
pub struct HardLinkDecoder {
    /// entry_index -> first_occurrence_index
    groups: HashMap<i32, i32>,
}

impl HardLinkDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a duplicate hard-link entry.
    pub fn record_duplicate(&mut self, entry_index: i32, first_index: i32) {
        self.groups.insert(entry_index, first_index);
    }

    /// Get the first occurrence index for a duplicate entry.
    pub fn first_index(&self, entry_index: i32) -> Option<i32> {
        self.groups.get(&entry_index).copied()
    }

    /// Iterate over all (duplicate_index, first_index) pairs.
    pub fn duplicates(&self) -> impl Iterator<Item = (i32, i32)> + '_ {
        self.groups.iter().map(|(&dup, &first)| (dup, first))
    }
}

// ---------------------------------------------------------------------------
// Resolve hard-link action from options + info
// ---------------------------------------------------------------------------

/// Determine the hard-link action for an entry.
pub fn resolve_hlink_action(
    opts: &FileListOptions,
    hlink_info: Option<&HardLinkInfo>,
    hlink_encoder: &mut HardLinkEncoder,
    entry_index: i32,
) -> HardLinkAction {
    if opts.preserve_hard_links {
        if let Some(info) = hlink_info {
            return hlink_encoder.check(info, entry_index);
        }
    }
    HardLinkAction::NotHardLinked
}

// ---------------------------------------------------------------------------
// Encode hard-link back-reference
// ---------------------------------------------------------------------------

/// Result of encoding a hard-link field.
#[derive(Debug)]
pub enum HlinkEncodeResult {
    /// Not a duplicate -- continue encoding remaining fields.
    Continue,
    /// Duplicate entry was fully written -- caller should return early.
    Abbreviated,
}

/// Encode the hard-link back-reference field.
///
/// C ref: flist.c send_file_entry
///
/// For `DuplicateOf`: writes the first-occurrence's flist index as a
/// varint and returns `Abbreviated` -- the caller should update delta
/// state and return (remaining metadata fields are not sent).
///
/// For `FirstOccurrence`: no bytes written. The XMIT_HLINK_FIRST flag
/// alone signals the first occurrence; rsync does NOT write a varint.
///
/// For `NotHardLinked`: no bytes written.
pub async fn encode_hlink<W: AsyncWrite + Unpin>(
    w: &mut W,
    hlink_action: &HardLinkAction,
) -> Result<HlinkEncodeResult> {
    match hlink_action {
        HardLinkAction::DuplicateOf(first_ndx) => {
            write_varint(w, *first_ndx as u32).await?;
            Ok(HlinkEncodeResult::Abbreviated)
        }
        HardLinkAction::FirstOccurrence => {
            // No varint written -- the XMIT_HLINK_FIRST flag is sufficient.
            Ok(HlinkEncodeResult::Continue)
        }
        HardLinkAction::NotHardLinked => Ok(HlinkEncodeResult::Continue),
    }
}

// ---------------------------------------------------------------------------
// Decode hard-link back-reference
// ---------------------------------------------------------------------------

/// Result of decoding a hard-link field.
pub enum HlinkDecodeResult {
    /// Not a hard-link duplicate -- continue decoding remaining fields.
    Continue,
    /// Duplicate entry cloned from a previous entry.
    Abbreviated(FileEntry),
}

/// Decode the hard-link back-reference field.
///
/// C ref: flist.c recv_file_entry
///
/// If the entry is a hard-link duplicate (HLINKED but not HLINK_FIRST),
/// reads the back-reference varint. If the first occurrence is in
/// `prev_entries` (same sub-flist), clones its metadata and returns
/// `Abbreviated`. Otherwise falls through to read all fields normally
/// (cross-sub-flist duplicate with full metadata on wire).
///
/// If it is the first occurrence (HLINKED + HLINK_FIRST), no varint
/// is read -- the XMIT_HLINK_FIRST flag alone signals first occurrence.
///
/// If not hard-linked at all, returns `Continue` with no bytes read.
pub async fn decode_hlink<R: AsyncRead + Unpin>(
    r: &mut R,
    flags: XmitFlags,
    opts: &FileListOptions,
    hlink_decoder: &mut HardLinkDecoder,
    prev_entries: &[FileEntry],
    name: Vec<u8>,
    state: &mut DeltaState,
) -> Result<HlinkDecodeResult> {
    if !opts.preserve_hard_links || !flags.hlinked() {
        tracing::trace!(
            preserve = opts.preserve_hard_links,
            hlinked = flags.hlinked(),
            name = %String::from_utf8_lossy(&name),
            "decode_hlink: skipping (not hardlinked)"
        );
        return Ok(HlinkDecodeResult::Continue);
    }

    tracing::trace!(
        hlink_first = flags.hlink_first(),
        name = %String::from_utf8_lossy(&name),
        prev_count = prev_entries.len(),
        ndx_start = state.ndx_start,
        "decode_hlink: detected hardlink flags"
    );

    if !flags.hlink_first() {
        // Duplicate: read the back-reference index (absolute NDX).
        let first_ndx = read_varint(r).await? as i32;
        // Convert absolute NDX to local prev_entries position.
        let local_idx = (first_ndx - state.ndx_start) as usize;
        tracing::trace!(
            first_ndx,
            local_idx,
            ndx_start = state.ndx_start,
            prev_count = prev_entries.len(),
            name = %String::from_utf8_lossy(&name),
            "decode_hlink: duplicate back-reference"
        );

        // Abbreviated duplicate: first occurrence is in prev_entries
        // (same sub-flist). Clone metadata and skip remaining fields.
        if let Some(first) = prev_entries.get(local_idx) {
            let entry_index = prev_entries.len() as i32;
            hlink_decoder.record_duplicate(entry_index, first_ndx);
            let mut entry = first.clone();
            entry.hlink_source = Some(first.name.clone());
            entry.name = name;
            entry.flags = flags.raw();
            super::state::update_delta_state(state, &entry);
            return Ok(HlinkDecodeResult::Abbreviated(entry));
        }
        // Unabbreviated duplicate: first occurrence is in a previous
        // sub-flist. All metadata fields follow on the wire; fall
        // through to the normal field-reading code below.
    }

    // XMIT_HLINK_FIRST: first occurrence, no varint to read.
    // Continue reading all metadata fields normally.
    Ok(HlinkDecodeResult::Continue)
}
