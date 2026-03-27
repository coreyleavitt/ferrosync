//! POSIX ACL types, binary parsing, and rsync wire format encoding.
//!
//! Implements reading/writing Linux kernel POSIX ACL xattr binary format
//! (`system.posix_acl_access` / `system.posix_acl_default`) and the rsync
//! wire protocol ACL encoding (acls.c: send_rsync_acl / recv_rsync_acl).

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProtocolError;
use crate::protocol::varint::{read_varint, write_varint};

// Re-export ACL type definitions from ferrosync-types.
pub use ferrosync_types::entry::{AceKind, Acl, PosixAce, PosixAcl, PosixAclEntries};

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Linux kernel POSIX ACL binary format
// ---------------------------------------------------------------------------

/// Version field for POSIX ACL xattr binary format.
const POSIX_ACL_XATTR_VERSION: u32 = 2;

// ACL entry tag values (from Linux include/uapi/linux/posix_acl_xattr.h).
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

/// Sentinel ID for non-named entries in the binary format.
const ACL_UNDEFINED_ID: u32 = 0xFFFF_FFFF;

/// Parse a Linux kernel POSIX ACL xattr binary blob into `PosixAclEntries`.
///
/// Format:
/// - u32 LE: version (must be 2)
/// - For each entry:
///   - u16 LE: tag
///   - u16 LE: permissions (0-7)
///   - u32 LE: id (uid/gid for named entries, 0xFFFFFFFF otherwise)
pub fn parse_posix_acl_binary(data: &[u8]) -> Result<PosixAclEntries> {
    if data.len() < 4 {
        return Err(ProtocolError::Handshake {
            message: "ACL xattr too short for version header".into(),
        });
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != POSIX_ACL_XATTR_VERSION {
        return Err(ProtocolError::Handshake {
            message: format!(
                "unsupported POSIX ACL xattr version: {version}, expected {POSIX_ACL_XATTR_VERSION}"
            ),
        });
    }

    let entry_data = &data[4..];
    if !entry_data.len().is_multiple_of(8) {
        return Err(ProtocolError::Handshake {
            message: "ACL xattr entry data not aligned to 8 bytes".into(),
        });
    }

    let mut entries = PosixAclEntries::default();

    for chunk in entry_data.chunks_exact(8) {
        let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let perm = u16::from_le_bytes([chunk[2], chunk[3]]) as u32;
        let id = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

        match tag {
            ACL_USER_OBJ => entries.user_obj = Some(perm),
            ACL_USER => entries.named.push(PosixAce {
                kind: AceKind::User,
                id,
                name: None,
                access: perm,
            }),
            ACL_GROUP_OBJ => entries.group_obj = Some(perm),
            ACL_GROUP => entries.named.push(PosixAce {
                kind: AceKind::Group,
                id,
                name: None,
                access: perm,
            }),
            ACL_MASK => entries.mask = Some(perm),
            ACL_OTHER => entries.other = Some(perm),
            _ => {
                return Err(ProtocolError::Handshake {
                    message: format!("unknown ACL entry tag: 0x{tag:04x}"),
                });
            }
        }
    }

    Ok(entries)
}

/// Serialize `PosixAclEntries` back to the Linux kernel binary format.
pub fn serialize_posix_acl_binary(acl: &PosixAclEntries) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 8 * 6);
    buf.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());

    let mut push_entry = |tag: u16, perm: u32, id: u32| {
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(&(perm as u16).to_le_bytes());
        buf.extend_from_slice(&id.to_le_bytes());
    };

    if let Some(perm) = acl.user_obj {
        push_entry(ACL_USER_OBJ, perm, ACL_UNDEFINED_ID);
    }
    for ace in &acl.named {
        if ace.kind == AceKind::User {
            push_entry(ACL_USER, ace.access, ace.id);
        }
    }
    if let Some(perm) = acl.group_obj {
        push_entry(ACL_GROUP_OBJ, perm, ACL_UNDEFINED_ID);
    }
    for ace in &acl.named {
        if ace.kind == AceKind::Group {
            push_entry(ACL_GROUP, ace.access, ace.id);
        }
    }
    if let Some(perm) = acl.mask {
        push_entry(ACL_MASK, perm, ACL_UNDEFINED_ID);
    }
    if let Some(perm) = acl.other {
        push_entry(ACL_OTHER, perm, ACL_UNDEFINED_ID);
    }

    buf
}

// ---------------------------------------------------------------------------
// rsync wire format flags
// ---------------------------------------------------------------------------

/// Bit flags for the XMIT ACL header byte (rsync acls.c).
const XMIT_USER_OBJ: u8 = 0x01;
const XMIT_GROUP_OBJ: u8 = 0x02;
const XMIT_MASK_OBJ: u8 = 0x04;
const XMIT_OTHER_OBJ: u8 = 0x08;
const XMIT_NAME_LIST: u8 = 0x10;

/// Named entry flags in access_and_flags byte.
const XFLAG_NAME_FOLLOWS: u32 = 0x01;
const XFLAG_NAME_IS_USER: u32 = 0x02;

// ---------------------------------------------------------------------------
// AclEncoder / AclDecoder -- wire format with dedup
// ---------------------------------------------------------------------------

/// Maintains dedup lists for encoding ACLs on the wire.
///
/// rsync deduplicates ACLs by maintaining separate access and default
/// ACL lists. When encoding, if an ACL matches a previously sent one,
/// only its 1-based index is sent.
#[derive(Default)]
pub struct AclEncoder {
    access_list: Vec<PosixAclEntries>,
    default_list: Vec<PosixAclEntries>,
}

impl AclEncoder {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Maintains dedup lists for decoding ACLs from the wire.
#[derive(Default)]
pub struct AclDecoder {
    access_list: Vec<PosixAclEntries>,
    default_list: Vec<PosixAclEntries>,
}

impl AclDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Wire encode helpers
// ---------------------------------------------------------------------------

/// Encode one ACL (access or default) to the wire.
///
/// Writes either:
/// - `varint(1-based index)` if the ACL matches a previously sent one
/// - `varint(0) + flags_byte + fields` for a new ACL
async fn encode_one_acl<W: AsyncWrite + Unpin>(
    w: &mut W,
    acl: &PosixAclEntries,
    dedup_list: &mut Vec<PosixAclEntries>,
) -> Result<()> {
    // Check for duplicate.
    if let Some(idx) = dedup_list.iter().position(|prev| prev == acl) {
        // 1-based index.
        write_varint(w, (idx + 1) as u32).await?;
        return Ok(());
    }

    // New ACL: add to dedup list and send inline.
    dedup_list.push(acl.clone());
    write_varint(w, 0).await?;

    // Compute flags byte.
    let mut flags: u8 = 0;
    if acl.user_obj.is_some() {
        flags |= XMIT_USER_OBJ;
    }
    if acl.group_obj.is_some() {
        flags |= XMIT_GROUP_OBJ;
    }
    if acl.mask.is_some() {
        flags |= XMIT_MASK_OBJ;
    }
    if acl.other.is_some() {
        flags |= XMIT_OTHER_OBJ;
    }
    if !acl.named.is_empty() {
        flags |= XMIT_NAME_LIST;
    }

    use tokio::io::AsyncWriteExt;
    w.write_all(&[flags]).await?;

    if let Some(perm) = acl.user_obj {
        write_varint(w, perm).await?;
    }
    if let Some(perm) = acl.group_obj {
        write_varint(w, perm).await?;
    }
    if let Some(perm) = acl.mask {
        write_varint(w, perm).await?;
    }
    if let Some(perm) = acl.other {
        write_varint(w, perm).await?;
    }

    if !acl.named.is_empty() {
        write_varint(w, acl.named.len() as u32).await?;
        for ace in &acl.named {
            let mut access_and_flags = ace.access << 2;
            if ace.name.is_some() {
                access_and_flags |= XFLAG_NAME_FOLLOWS;
            }
            if ace.kind == AceKind::User {
                access_and_flags |= XFLAG_NAME_IS_USER;
            }
            write_varint(w, ace.id).await?;
            write_varint(w, access_and_flags).await?;
            if let Some(ref name) = ace.name {
                write_varint(w, name.len() as u32).await?;
                use tokio::io::AsyncWriteExt;
                w.write_all(name).await?;
            }
        }
    }

    Ok(())
}

/// Decode one ACL (access or default) from the wire.
async fn decode_one_acl<R: AsyncRead + Unpin>(
    r: &mut R,
    dedup_list: &mut Vec<PosixAclEntries>,
) -> Result<PosixAclEntries> {
    let ndx = read_varint(r).await?;
    if ndx > 0 {
        // Reference to previously received ACL (1-based index).
        let idx = (ndx - 1) as usize;
        if idx >= dedup_list.len() {
            return Err(ProtocolError::Handshake {
                message: format!(
                    "ACL dedup index {ndx} out of range (list has {} entries)",
                    dedup_list.len()
                ),
            });
        }
        return Ok(dedup_list[idx].clone());
    }

    // New ACL inline.
    use tokio::io::AsyncReadExt;
    let mut flags_buf = [0u8; 1];
    r.read_exact(&mut flags_buf).await?;
    let flags = flags_buf[0];

    let user_obj = if flags & XMIT_USER_OBJ != 0 {
        Some(read_varint(r).await?)
    } else {
        None
    };
    let group_obj = if flags & XMIT_GROUP_OBJ != 0 {
        Some(read_varint(r).await?)
    } else {
        None
    };
    let mask = if flags & XMIT_MASK_OBJ != 0 {
        Some(read_varint(r).await?)
    } else {
        None
    };
    let other = if flags & XMIT_OTHER_OBJ != 0 {
        Some(read_varint(r).await?)
    } else {
        None
    };

    let mut named = Vec::new();
    if flags & XMIT_NAME_LIST != 0 {
        let count = read_varint(r).await? as usize;
        named.reserve(count);
        for _ in 0..count {
            let id = read_varint(r).await?;
            let access_and_flags = read_varint(r).await?;
            let access = access_and_flags >> 2;
            let has_name = access_and_flags & XFLAG_NAME_FOLLOWS != 0;
            let is_user = access_and_flags & XFLAG_NAME_IS_USER != 0;
            let kind = if is_user {
                AceKind::User
            } else {
                AceKind::Group
            };
            let name = if has_name {
                let name_len = read_varint(r).await? as usize;
                let mut name_buf = vec![0u8; name_len];
                r.read_exact(&mut name_buf).await?;
                Some(name_buf)
            } else {
                None
            };
            named.push(PosixAce {
                kind,
                id,
                name,
                access,
            });
        }
    }

    let acl = PosixAclEntries {
        user_obj,
        group_obj,
        mask,
        other,
        named,
    };
    dedup_list.push(acl.clone());
    Ok(acl)
}

// ---------------------------------------------------------------------------
// Per-file ACL encode/decode (called from codec)
// ---------------------------------------------------------------------------

/// Encode ACL data for a file entry.
///
/// For non-symlinks: sends access ACL. For directories: also sends default ACL.
/// The `acl` field may be `None` if the file has no ACL (sends empty ACL).
pub async fn encode_acl<W: AsyncWrite + Unpin>(
    w: &mut W,
    acl: &Option<Acl>,
    mode: u32,
    encoder: &mut AclEncoder,
) -> Result<()> {
    let is_dir = (mode & crate::filelist::entry::S_IFMT) == crate::filelist::entry::S_IFDIR;

    let empty = PosixAclEntries::default();

    let (access, default) = match acl {
        Some(Acl::Posix(ref posix)) => (&posix.access, posix.default.as_ref()),
        None => (&empty, None),
    };

    encode_one_acl(w, access, &mut encoder.access_list).await?;
    if is_dir {
        let default_acl = default.unwrap_or(&empty);
        encode_one_acl(w, default_acl, &mut encoder.default_list).await?;
    }

    Ok(())
}

/// Decode ACL data for a file entry.
///
/// Returns `Some(Acl)` with the decoded ACL data.
pub async fn decode_acl<R: AsyncRead + Unpin>(
    r: &mut R,
    mode: u32,
    decoder: &mut AclDecoder,
) -> Result<Option<Acl>> {
    let is_dir = (mode & crate::filelist::entry::S_IFMT) == crate::filelist::entry::S_IFDIR;

    let access = decode_one_acl(r, &mut decoder.access_list).await?;
    let default = if is_dir {
        let d = decode_one_acl(r, &mut decoder.default_list).await?;
        if d == PosixAclEntries::default() {
            None
        } else {
            Some(d)
        }
    } else {
        None
    };

    // Return None if the access ACL is empty and there's no default.
    if access == PosixAclEntries::default() && default.is_none() {
        return Ok(None);
    }

    Ok(Some(Acl::Posix(PosixAcl { access, default })))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_serialize_roundtrip_minimal() {
        // Minimal ACL: user_obj, group_obj, other (no mask, no named).
        let mut data = Vec::new();
        data.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        // user_obj: rwx (7)
        data.extend_from_slice(&ACL_USER_OBJ.to_le_bytes());
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
        // group_obj: r-x (5)
        data.extend_from_slice(&ACL_GROUP_OBJ.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
        // other: r-- (4)
        data.extend_from_slice(&ACL_OTHER.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());

        let parsed = parse_posix_acl_binary(&data).unwrap();
        assert_eq!(parsed.user_obj, Some(7));
        assert_eq!(parsed.group_obj, Some(5));
        assert_eq!(parsed.other, Some(4));
        assert_eq!(parsed.mask, None);
        assert!(parsed.named.is_empty());

        let serialized = serialize_posix_acl_binary(&parsed);
        let reparsed = parse_posix_acl_binary(&serialized).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn test_parse_serialize_roundtrip_with_named() {
        let mut data = Vec::new();
        data.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        // user_obj: rwx
        data.extend_from_slice(&ACL_USER_OBJ.to_le_bytes());
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
        // user:1000 rw-
        data.extend_from_slice(&ACL_USER.to_le_bytes());
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(&1000u32.to_le_bytes());
        // group_obj: r-x
        data.extend_from_slice(&ACL_GROUP_OBJ.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
        // group:100 r--
        data.extend_from_slice(&ACL_GROUP.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&100u32.to_le_bytes());
        // mask: rw-
        data.extend_from_slice(&ACL_MASK.to_le_bytes());
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
        // other: r--
        data.extend_from_slice(&ACL_OTHER.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());

        let parsed = parse_posix_acl_binary(&data).unwrap();
        assert_eq!(parsed.user_obj, Some(7));
        assert_eq!(parsed.group_obj, Some(5));
        assert_eq!(parsed.mask, Some(6));
        assert_eq!(parsed.other, Some(4));
        assert_eq!(parsed.named.len(), 2);
        assert_eq!(parsed.named[0].kind, AceKind::User);
        assert_eq!(parsed.named[0].id, 1000);
        assert_eq!(parsed.named[0].access, 6);
        assert_eq!(parsed.named[1].kind, AceKind::Group);
        assert_eq!(parsed.named[1].id, 100);
        assert_eq!(parsed.named[1].access, 4);

        let serialized = serialize_posix_acl_binary(&parsed);
        let reparsed = parse_posix_acl_binary(&serialized).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn test_parse_invalid_version() {
        let data = 99u32.to_le_bytes();
        assert!(parse_posix_acl_binary(&data).is_err());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(parse_posix_acl_binary(&[0, 1]).is_err());
    }

    #[test]
    fn test_parse_unaligned() {
        let mut data = Vec::new();
        data.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        data.push(0xFF); // extra byte making it 5 total (not divisible by 8)
        assert!(parse_posix_acl_binary(&data).is_err());
    }

    #[tokio::test]
    async fn test_wire_encode_decode_roundtrip() {
        let acl = PosixAclEntries {
            user_obj: Some(7),
            group_obj: Some(5),
            mask: Some(6),
            other: Some(4),
            named: vec![
                PosixAce {
                    kind: AceKind::User,
                    id: 1000,
                    name: Some(b"testuser".to_vec()),
                    access: 6,
                },
                PosixAce {
                    kind: AceKind::Group,
                    id: 100,
                    name: None,
                    access: 4,
                },
            ],
        };

        let mut buf = Vec::new();
        let mut dedup = Vec::new();
        encode_one_acl(&mut buf, &acl, &mut dedup).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decode_dedup = Vec::new();
        let decoded = decode_one_acl(&mut cursor, &mut decode_dedup)
            .await
            .unwrap();

        assert_eq!(decoded.user_obj, acl.user_obj);
        assert_eq!(decoded.group_obj, acl.group_obj);
        assert_eq!(decoded.mask, acl.mask);
        assert_eq!(decoded.other, acl.other);
        assert_eq!(decoded.named.len(), acl.named.len());
        assert_eq!(decoded.named[0].kind, AceKind::User);
        assert_eq!(decoded.named[0].id, 1000);
        assert_eq!(decoded.named[0].access, 6);
        assert_eq!(decoded.named[0].name, Some(b"testuser".to_vec()));
        assert_eq!(decoded.named[1].kind, AceKind::Group);
        assert_eq!(decoded.named[1].id, 100);
        assert_eq!(decoded.named[1].access, 4);
        assert_eq!(decoded.named[1].name, None);
    }

    #[tokio::test]
    async fn test_wire_dedup() {
        let acl1 = PosixAclEntries {
            user_obj: Some(7),
            group_obj: Some(5),
            mask: None,
            other: Some(4),
            named: Vec::new(),
        };
        let acl2 = PosixAclEntries {
            user_obj: Some(6),
            group_obj: Some(4),
            mask: None,
            other: Some(0),
            named: Vec::new(),
        };

        let mut buf = Vec::new();
        let mut dedup = Vec::new();

        // Send acl1 (new, gets index 1).
        encode_one_acl(&mut buf, &acl1, &mut dedup).await.unwrap();
        let first_len = buf.len();

        // Send acl2 (new, gets index 2).
        encode_one_acl(&mut buf, &acl2, &mut dedup).await.unwrap();
        let second_len = buf.len() - first_len;

        // Send acl1 again (dedup, should be just the index).
        encode_one_acl(&mut buf, &acl1, &mut dedup).await.unwrap();
        let third_len = buf.len() - first_len - second_len;

        // The dedup reference should be much smaller than the full ACL.
        assert!(third_len < first_len, "dedup reference should be shorter");
        // Specifically, it should be just a varint(1) = 1 byte.
        assert_eq!(third_len, 1);

        // Now decode and verify.
        let mut cursor = Cursor::new(&buf);
        let mut decode_dedup = Vec::new();

        let d1 = decode_one_acl(&mut cursor, &mut decode_dedup)
            .await
            .unwrap();
        assert_eq!(d1, acl1);

        let d2 = decode_one_acl(&mut cursor, &mut decode_dedup)
            .await
            .unwrap();
        assert_eq!(d2, acl2);

        let d3 = decode_one_acl(&mut cursor, &mut decode_dedup)
            .await
            .unwrap();
        assert_eq!(d3, acl1);
    }

    #[tokio::test]
    async fn test_encode_decode_file_acl() {
        // Regular file: only access ACL.
        let acl = Some(Acl::Posix(PosixAcl {
            access: PosixAclEntries {
                user_obj: Some(7),
                group_obj: Some(5),
                mask: None,
                other: Some(4),
                named: Vec::new(),
            },
            default: None,
        }));

        let mode = crate::filelist::entry::S_IFREG | 0o644;
        let mut buf = Vec::new();
        let mut encoder = AclEncoder::new();
        encode_acl(&mut buf, &acl, mode, &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = AclDecoder::new();
        let decoded = decode_acl(&mut cursor, mode, &mut decoder).await.unwrap();

        assert_eq!(decoded, acl);
    }

    #[tokio::test]
    async fn test_encode_decode_dir_acl() {
        // Directory: access + default ACL.
        let acl = Some(Acl::Posix(PosixAcl {
            access: PosixAclEntries {
                user_obj: Some(7),
                group_obj: Some(5),
                mask: Some(7),
                other: Some(5),
                named: vec![PosixAce {
                    kind: AceKind::User,
                    id: 1000,
                    name: None,
                    access: 7,
                }],
            },
            default: Some(PosixAclEntries {
                user_obj: Some(7),
                group_obj: Some(5),
                mask: Some(7),
                other: Some(5),
                named: Vec::new(),
            }),
        }));

        let mode = crate::filelist::entry::S_IFDIR | 0o755;
        let mut buf = Vec::new();
        let mut encoder = AclEncoder::new();
        encode_acl(&mut buf, &acl, mode, &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = AclDecoder::new();
        let decoded = decode_acl(&mut cursor, mode, &mut decoder).await.unwrap();

        assert_eq!(decoded, acl);
    }

    #[tokio::test]
    async fn test_encode_decode_none_acl() {
        // No ACL: sends empty and decodes as None.
        let mode = crate::filelist::entry::S_IFREG | 0o644;
        let mut buf = Vec::new();
        let mut encoder = AclEncoder::new();
        encode_acl(&mut buf, &None, mode, &mut encoder)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut decoder = AclDecoder::new();
        let decoded = decode_acl(&mut cursor, mode, &mut decoder).await.unwrap();

        assert_eq!(decoded, None);
    }
}
