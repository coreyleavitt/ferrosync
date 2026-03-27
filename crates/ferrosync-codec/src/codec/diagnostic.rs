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
/// Uses the same decode logic as the real decoder but captures byte
/// ranges for each field, enabling field-by-field comparison.
pub async fn diagnostic_decode_entry(
    data: &[u8],
    offset: &mut usize,
    state: &mut DeltaState,
    opts: &FileListOptions,
) -> Result<DiagnosticResult> {
    let mut fields = Vec::new();

    // --- Flags ---
    let flags_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let flags = match super::flags::decode_xmit_flags(&mut cursor, opts).await? {
        DecodedFlags::Entry(f) => f,
        DecodedFlags::EndOfList { io_error } => {
            let consumed = cursor.position() as usize;
            *offset += consumed;
            return Ok(DiagnosticResult::EndOfList { io_error });
        }
    };
    let consumed = cursor.position() as usize;
    fields.push(DecodedField {
        name: "xmit_flags",
        offset: flags_start,
        length: consumed,
        raw_bytes: data[flags_start..flags_start + consumed].to_vec(),
        decoded_value: format!("0x{:04x}", flags.raw()),
    });
    *offset += consumed;

    // --- Filename ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let name = super::fields::decode_filename(&mut cursor, state, flags, opts, None).await?;
    let consumed = cursor.position() as usize;
    fields.push(DecodedField {
        name: "filename",
        offset: field_start,
        length: consumed,
        raw_bytes: data[field_start..field_start + consumed].to_vec(),
        decoded_value: String::from_utf8_lossy(&name).to_string(),
    });
    *offset += consumed;

    // --- Hard-link back-reference ---
    if opts.preserve_hard_links && flags.hlinked() {
        let field_start = *offset;
        let mut cursor = Cursor::new(&data[*offset..]);
        let ndx = ferrosync_protocol::varint::read_varint(&mut cursor).await? as i32;
        let consumed = cursor.position() as usize;
        fields.push(DecodedField {
            name: if flags.hlink_first() {
                "hlink_self_ref"
            } else {
                "hlink_backref"
            },
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{ndx}"),
        });
        *offset += consumed;

        if !flags.hlink_first() {
            // Abbreviated entry -- update state and return.
            state.prev_name = name;
            return Ok(DiagnosticResult::Entry(DecodedEntry { fields }));
        }
    }

    // --- File length ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let len = super::fields::decode_file_length(&mut cursor, opts).await?;
    let consumed = cursor.position() as usize;
    fields.push(DecodedField {
        name: "file_length",
        offset: field_start,
        length: consumed,
        raw_bytes: data[field_start..field_start + consumed].to_vec(),
        decoded_value: format!("{len}"),
    });
    *offset += consumed;

    // --- Modification time ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let mtime = super::fields::decode_mtime(&mut cursor, state, flags, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "mtime",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{mtime}"),
        });
    }
    *offset += consumed;

    // --- Mtime nanoseconds ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let mtime_nsec = super::fields::decode_mtime_nsec(&mut cursor, flags, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "mtime_nsec",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{mtime_nsec}"),
        });
    }
    *offset += consumed;

    // --- File mode ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let mode = super::fields::decode_mode(&mut cursor, state, flags).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "mode",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("0o{mode:06o}"),
        });
    }
    *offset += consumed;

    // --- UID ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let (uid, user_name) = super::fields::decode_uid(&mut cursor, state, flags, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "uid",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{uid} ({})", String::from_utf8_lossy(&user_name)),
        });
    }
    *offset += consumed;

    // --- GID ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let (gid, group_name) = super::fields::decode_gid(&mut cursor, state, flags, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "gid",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{gid} ({})", String::from_utf8_lossy(&group_name)),
        });
    }
    *offset += consumed;

    // --- Device numbers ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let rdev = super::fields::decode_rdev(&mut cursor, mode, state, flags, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "rdev",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: format!("{rdev}"),
        });
    }
    *offset += consumed;

    // --- Symlink target ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let link_target = super::fields::decode_symlink(&mut cursor, mode, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "symlink_target",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: String::from_utf8_lossy(&link_target).to_string(),
        });
    }
    *offset += consumed;

    // --- File checksum ---
    let field_start = *offset;
    let mut cursor = Cursor::new(&data[*offset..]);
    let checksum = super::fields::decode_checksum(&mut cursor, mode, opts).await?;
    let consumed = cursor.position() as usize;
    if consumed > 0 {
        fields.push(DecodedField {
            name: "checksum",
            offset: field_start,
            length: consumed,
            raw_bytes: data[field_start..field_start + consumed].to_vec(),
            decoded_value: hex::encode(&checksum),
        });
    }
    *offset += consumed;

    // Update delta state.
    state.prev_name = name;
    state.prev_mtime = mtime;
    state.prev_mode = mode;
    state.prev_uid = uid;
    state.prev_gid = gid;
    state.prev_rdev = rdev;
    state.prev_rdev_major = (rdev >> 8) as u32;
    state.prev_user_name = user_name;
    state.prev_group_name = group_name;

    Ok(DiagnosticResult::Entry(DecodedEntry { fields }))
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

// Conditionally use hex crate or inline implementation.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
