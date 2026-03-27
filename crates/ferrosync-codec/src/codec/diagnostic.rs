//! Diagnostic decoder for wire conformance testing.
//!
//! The diagnostic decoder reads file list wire bytes and produces a
//! `Vec<DecodedField>` describing each field's offset, length, raw bytes,
//! and decoded value. This enables field-by-field comparison between
//! ferrosync's output and real rsync's output.

use std::io::Cursor;

use super::flags::DecodedFlags;
use super::options::FileListOptions;
use super::state::DeltaState;
use ferrosync_types::error::ProtocolError;

type Result<T> = std::result::Result<T, ProtocolError>;

/// A single decoded field from the wire, with diagnostic metadata.
#[derive(Debug, Clone)]
pub struct DecodedField {
    /// Human-readable field name (e.g., "mtime", "uid", "hlink_backref").
    pub name: &'static str,
    /// Byte offset in the stream where this field starts.
    pub offset: usize,
    /// Number of bytes consumed by this field.
    pub length: usize,
    /// The actual wire bytes.
    pub raw_bytes: Vec<u8>,
    /// Human-readable decoded value.
    pub decoded_value: String,
}

/// All decoded fields for a single file list entry.
#[derive(Debug, Clone)]
pub struct DecodedEntry {
    /// The fields in wire order.
    pub fields: Vec<DecodedField>,
}

/// Result of diagnostic decoding -- either an entry or end-of-list.
#[derive(Debug)]
pub enum DiagnosticResult {
    /// A fully decoded entry with field-level diagnostics.
    Entry(DecodedEntry),
    /// End of file list.
    EndOfList { io_error: i32 },
}

/// Diagnostic decoder that wraps a byte buffer and tracks positions.
///
/// Uses the `FieldVisitor` pattern via `DiagnosticDecoder` visitor.
/// The field traversal order is defined once in `traverse_fields`,
/// shared with the real encoder and decoder -- divergence is impossible.
pub async fn diagnostic_decode_entry(
    data: &[u8],
    offset: &mut usize,
    state: &mut DeltaState,
    opts: &FileListOptions,
) -> Result<DiagnosticResult> {
    use super::visitor;

    let mut diag = visitor::DiagnosticDecoder {
        data,
        offset: *offset,
        fields: Vec::new(),
    };

    // --- Flags ---
    let flags_start = diag.offset;
    let mut cursor = Cursor::new(&data[diag.offset..]);
    let flags = match super::flags::decode_xmit_flags(&mut cursor, opts).await? {
        DecodedFlags::Entry(f) => f,
        DecodedFlags::EndOfList { io_error } => {
            let consumed = cursor.position() as usize;
            *offset = diag.offset + consumed;
            return Ok(DiagnosticResult::EndOfList { io_error });
        }
    };
    let consumed = cursor.position() as usize;
    diag.record(
        "xmit_flags",
        consumed,
        flags_start,
        format!("0x{:04x}", flags.raw()),
    );

    // --- Filename ---
    let field_start = diag.offset;
    let mut cursor = Cursor::new(&data[diag.offset..]);
    let name = super::fields::decode_filename(&mut cursor, state, flags, opts, None).await?;
    let consumed = cursor.position() as usize;
    diag.record(
        "filename",
        consumed,
        field_start,
        String::from_utf8_lossy(&name).to_string(),
    );

    // --- Hard-link back-reference ---
    if opts.preserve_hard_links && flags.hlinked() {
        let field_start = diag.offset;
        let mut cursor = Cursor::new(&data[diag.offset..]);
        let ndx = ferrosync_protocol::varint::read_varint(&mut cursor).await? as i32;
        let consumed = cursor.position() as usize;
        let field_name = if flags.hlink_first() {
            "hlink_self_ref"
        } else {
            "hlink_backref"
        };
        diag.record(field_name, consumed, field_start, format!("{ndx}"));

        if !flags.hlink_first() {
            // Abbreviated entry -- update state and return.
            state.prev_name = name;
            *offset = diag.offset;
            return Ok(DiagnosticResult::Entry(DecodedEntry {
                fields: diag.fields,
            }));
        }
    }

    // --- Metadata fields via visitor traversal ---
    let mut values = visitor::FieldValues {
        name,
        ..Default::default()
    };
    {
        let mut ctx = visitor::FieldContext {
            flags,
            state,
            opts,
            values: &mut values,
        };
        visitor::traverse_fields(&mut diag, &mut ctx).await?;
    }

    // --- Update delta state (shared with real decoder) ---
    values.update_state(state);

    *offset = diag.offset;
    Ok(DiagnosticResult::Entry(DecodedEntry {
        fields: diag.fields,
    }))
}

/// Decode all entries from a byte buffer, returning field-level diagnostics.
pub async fn diagnostic_decode_all(
    data: &[u8],
    opts: &FileListOptions,
) -> Result<Vec<DecodedEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut state = DeltaState::default();

    while let DiagnosticResult::Entry(entry) =
        diagnostic_decode_entry(data, &mut offset, &mut state, opts).await?
    {
        entries.push(entry);
    }

    Ok(entries)
}

/// Compare two sets of decoded entries field-by-field.
///
/// Returns a formatted divergence report, or `None` if they match.
pub fn compare_decoded(
    label_a: &str,
    entries_a: &[DecodedEntry],
    label_b: &str,
    entries_b: &[DecodedEntry],
) -> Option<String> {
    if entries_a.len() != entries_b.len() {
        return Some(format!(
            "Entry count mismatch: {label_a} has {} entries, {label_b} has {}",
            entries_a.len(),
            entries_b.len()
        ));
    }

    let mut report = String::new();

    for (entry_idx, (ea, eb)) in entries_a.iter().zip(entries_b.iter()).enumerate() {
        let max_fields = ea.fields.len().max(eb.fields.len());
        for field_idx in 0..max_fields {
            let fa = ea.fields.get(field_idx);
            let fb = eb.fields.get(field_idx);

            match (fa, fb) {
                (Some(a), Some(b)) => {
                    if a.raw_bytes != b.raw_bytes {
                        report.push_str(&format!(
                            "DIVERGENCE at field \"{}\" (entry {entry_idx}):\n\
                             \x20 {label_a}: offset={}, bytes=[{}], decoded={}\n\
                             \x20 {label_b}: offset={}, bytes=[{}], decoded={}\n\n",
                            a.name,
                            a.offset,
                            hex_bytes(&a.raw_bytes),
                            a.decoded_value,
                            b.offset,
                            hex_bytes(&b.raw_bytes),
                            b.decoded_value,
                        ));
                    }
                }
                (Some(a), None) => {
                    report.push_str(&format!(
                        "MISSING in {label_b}: field \"{}\" (entry {entry_idx})\n\
                         \x20 {label_a}: offset={}, bytes=[{}], decoded={}\n\n",
                        a.name,
                        a.offset,
                        hex_bytes(&a.raw_bytes),
                        a.decoded_value,
                    ));
                }
                (None, Some(b)) => {
                    report.push_str(&format!(
                        "EXTRA in {label_b}: field \"{}\" (entry {entry_idx})\n\
                         \x20 {label_b}: offset={}, bytes=[{}], decoded={}\n\n",
                        b.name,
                        b.offset,
                        hex_bytes(&b.raw_bytes),
                        b.decoded_value,
                    ));
                }
                (None, None) => {}
            }
        }
    }

    if report.is_empty() {
        None
    } else {
        Some(report)
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
