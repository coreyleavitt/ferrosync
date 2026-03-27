//! Extended attribute types and rsync wire format encoding.
//!
//! Implements the rsync wire protocol xattr encoding (xattrs.c: send_xattr /
//! receive_xattr). The wire format uses varint-based dedup indexing where
//! `ndx+1` is sent (0 = new xattr set inline, 1+ = reference to index 0+).
//!
//! Phase 1: always sends full attribute values (no MAX_FULL_DATUM
//! abbreviation). This is wire-compatible with rsync which handles both
//! full and abbreviated values on receive.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::protocol::varint::{read_varint, write_varint};

// Re-export xattr type definitions from ferrosync-types.
pub use ferrosync_types::entry::{ExtendedAttributes, XattrEntry};

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// XattrEncoder / XattrDecoder -- wire format with dedup
// ---------------------------------------------------------------------------

/// Maintains dedup list for encoding xattrs on the wire.
///
/// rsync deduplicates xattr sets by maintaining a list of previously sent
/// sets. When encoding, if an xattr set matches a previously sent one,
/// only its index+1 is sent.
#[derive(Default)]
pub struct XattrEncoder {
    seen: Vec<ExtendedAttributes>,
}

impl XattrEncoder {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Maintains dedup list for decoding xattrs from the wire.
#[derive(Default)]
pub struct XattrDecoder {
    seen: Vec<ExtendedAttributes>,
}

impl XattrDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Wire encode/decode
// ---------------------------------------------------------------------------

/// Encode xattr data for a file entry.
///
/// Wire format (from rsync xattrs.c send_xattr):
/// ```text
/// varint: ndx+1    -- 0 = new xattr set follows, >0 = reference (ndx = value-1)
/// If ndx+1 == 0 (new):
///   varint: count
///   for each:
///     varint: name_len   (includes null terminator)
///     varint: datum_len
///     bytes[name_len]: name (null-terminated)
///     bytes[datum_len]: value
/// ```
pub async fn encode_xattrs<W: AsyncWrite + Unpin>(
    w: &mut W,
    xattrs: &Option<ExtendedAttributes>,
    encoder: &mut XattrEncoder,
) -> Result<()> {
    let empty = ExtendedAttributes::default();
    let xa = xattrs.as_ref().unwrap_or(&empty);

    // Check for duplicate in previously sent sets.
    if let Some(idx) = encoder.seen.iter().position(|prev| prev == xa) {
        // ndx+1: reference to index `idx`, so send idx+1.
        write_varint(w, (idx + 1) as u32).await?;
        return Ok(());
    }

    // New xattr set: add to dedup list and send inline.
    encoder.seen.push(xa.clone());

    // ndx+1 = 0 means new.
    write_varint(w, 0).await?;

    // Count of entries.
    write_varint(w, xa.entries.len() as u32).await?;

    for entry in &xa.entries {
        // name_len includes the null terminator (already stored in entry.name).
        write_varint(w, entry.name.len() as u32).await?;
        // datum_len.
        write_varint(w, entry.value.len() as u32).await?;
        // name bytes (null-terminated).
        w.write_all(&entry.name).await?;
        // value bytes.
        w.write_all(&entry.value).await?;
    }

    Ok(())
}

/// Decode xattr data for a file entry.
pub async fn decode_xattrs<R: AsyncRead + Unpin>(
    r: &mut R,
    decoder: &mut XattrDecoder,
) -> Result<Option<ExtendedAttributes>> {
    let ndx_plus_one = read_varint(r).await?;

    if ndx_plus_one != 0 {
        // Reference to previously received xattr set.
        let idx = (ndx_plus_one - 1) as usize;
        if idx >= decoder.seen.len() {
            return Err(ProtocolError::Handshake {
                message: format!(
                    "xattr dedup index {} out of range (list has {} entries)",
                    ndx_plus_one,
                    decoder.seen.len()
                ),
            });
        }
        let xa = decoder.seen[idx].clone();
        if xa.entries.is_empty() {
            return Ok(None);
        }
        return Ok(Some(xa));
    }

    // New xattr set inline.
    let count = read_varint(r).await? as usize;
    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        let name_len = read_varint(r).await? as usize;
        let datum_len = read_varint(r).await? as usize;

        let mut name = vec![0u8; name_len];
        r.read_exact(&mut name).await?;

        let mut value = vec![0u8; datum_len];
        r.read_exact(&mut value).await?;

        entries.push(XattrEntry { name, value });
    }

    let xa = ExtendedAttributes { entries };
    decoder.seen.push(xa.clone());

    if xa.entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(xa))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_encode_decode_roundtrip() {
        let xa = ExtendedAttributes {
            entries: vec![
                XattrEntry {
                    name: b"user.color\0".to_vec(),
                    value: b"blue".to_vec(),
                },
                XattrEntry {
                    name: b"user.size\0".to_vec(),
                    value: b"42".to_vec(),
                },
            ],
        };

        let mut buf = Vec::new();
        let mut encoder = XattrEncoder::new();
        encode_xattrs(&mut buf, &Some(xa.clone()), &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();
        let decoded = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();

        assert_eq!(decoded, Some(xa));
    }

    #[tokio::test]
    async fn test_encode_decode_empty() {
        let xa = ExtendedAttributes::default();

        let mut buf = Vec::new();
        let mut encoder = XattrEncoder::new();
        encode_xattrs(&mut buf, &Some(xa), &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();
        let decoded = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();

        assert_eq!(decoded, None);
    }

    #[tokio::test]
    async fn test_encode_decode_none() {
        let mut buf = Vec::new();
        let mut encoder = XattrEncoder::new();
        encode_xattrs(&mut buf, &None, &mut encoder).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();
        let decoded = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();

        assert_eq!(decoded, None);
    }

    #[tokio::test]
    async fn test_dedup() {
        let xa1 = ExtendedAttributes {
            entries: vec![XattrEntry {
                name: b"user.tag\0".to_vec(),
                value: b"important".to_vec(),
            }],
        };
        let xa2 = ExtendedAttributes {
            entries: vec![XattrEntry {
                name: b"user.level\0".to_vec(),
                value: b"3".to_vec(),
            }],
        };

        let mut buf = Vec::new();
        let mut encoder = XattrEncoder::new();

        // Send xa1 (new, gets index 0).
        encode_xattrs(&mut buf, &Some(xa1.clone()), &mut encoder)
            .await
            .unwrap();
        let first_len = buf.len();

        // Send xa2 (new, gets index 1).
        encode_xattrs(&mut buf, &Some(xa2.clone()), &mut encoder)
            .await
            .unwrap();
        let second_len = buf.len() - first_len;

        // Send xa1 again (dedup, should be just ndx+1 = 1).
        encode_xattrs(&mut buf, &Some(xa1.clone()), &mut encoder)
            .await
            .unwrap();
        let third_len = buf.len() - first_len - second_len;

        // The dedup reference should be much smaller than the full xattr set.
        assert!(third_len < first_len, "dedup reference should be shorter");
        // Specifically, it should be just a varint(1) = 1 byte.
        assert_eq!(third_len, 1);

        // Now decode and verify.
        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();

        let d1 = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();
        assert_eq!(d1, Some(xa1.clone()));

        let d2 = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();
        assert_eq!(d2, Some(xa2));

        let d3 = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();
        assert_eq!(d3, Some(xa1));
    }

    #[tokio::test]
    async fn test_binary_value() {
        let xa = ExtendedAttributes {
            entries: vec![XattrEntry {
                name: b"user.binary\0".to_vec(),
                value: vec![0x00, 0xFF, 0x80, 0x01],
            }],
        };

        let mut buf = Vec::new();
        let mut encoder = XattrEncoder::new();
        encode_xattrs(&mut buf, &Some(xa.clone()), &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();
        let decoded = decode_xattrs(&mut cursor, &mut decoder).await.unwrap();

        assert_eq!(decoded, Some(xa));
    }

    #[tokio::test]
    async fn test_dedup_index_out_of_range() {
        // Manually construct a wire message with an invalid dedup index.
        let mut buf = Vec::new();
        // ndx+1 = 5, but decoder has no entries.
        write_varint(&mut buf, 5).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = XattrDecoder::new();
        let result = decode_xattrs(&mut cursor, &mut decoder).await;
        assert!(result.is_err());
    }
}
