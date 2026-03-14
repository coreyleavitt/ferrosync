//! XMIT-flag codec for rsync file list entries.
//!
//! The rsync file list wire format uses delta encoding: each entry's fields
//! are compared against the previous entry, and XMIT flags indicate which
//! fields have changed. This module provides `FileListDecoder` and
//! `FileListEncoder` that maintain the necessary delta state.
//!
//! Supports protocol versions 27-31.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::protocol::varint::{
    self, read_byte, read_int, read_varint, read_varint30, read_varlong, read_varlong30,
    write_byte, write_int, write_varint, write_varint30, write_varlong, write_varlong30,
};

use super::entry::{FileEntry, S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT, S_IFREG, S_IFSOCK, WIRE_S_IFLNK};
use super::xmit::*;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Transfer options that affect wire format
// ---------------------------------------------------------------------------

/// Options that control which fields are present in the file list wire format.
#[derive(Debug, Clone)]
pub struct FileListOptions {
    /// Negotiated protocol version.
    pub protocol_version: u8,
    /// True if XMIT flags are sent as varints (proto >= 30 with CF_VARINT_FLIST_FLAGS).
    pub xfer_flags_as_varint: bool,
    /// True if uid is preserved (-o).
    pub preserve_uid: bool,
    /// True if gid is preserved (-g).
    pub preserve_gid: bool,
    /// True if device files are preserved (--devices).
    pub preserve_devices: bool,
    /// True if special files are preserved (--specials).
    pub preserve_specials: bool,
    /// True if symlinks are preserved (-l).
    pub preserve_links: bool,
    /// True if hard links are preserved (-H).
    pub preserve_hard_links: bool,
    /// True if always computing checksums (-c).
    pub always_checksum: bool,
    /// Length of the file-level checksum (typically 16 for MD4/MD5).
    pub checksum_len: usize,
}

impl Default for FileListOptions {
    fn default() -> Self {
        Self {
            protocol_version: 31,
            xfer_flags_as_varint: true,
            preserve_uid: false,
            preserve_gid: false,
            preserve_devices: false,
            preserve_specials: false,
            preserve_links: false,
            preserve_hard_links: false,
            always_checksum: false,
            checksum_len: 16,
        }
    }
}

impl FileListOptions {
    /// Create codec options from a negotiated protocol and transfer options.
    ///
    /// This bridges the handshake output to the file list codec, ensuring
    /// protocol version-specific behavior is correctly applied.
    pub fn from_protocol(
        proto: &crate::protocol::handshake::NegotiatedProtocol,
        opts: &crate::options::TransferOptions,
    ) -> Self {
        Self {
            protocol_version: proto.version,
            xfer_flags_as_varint: proto.varint_flist_flags,
            preserve_uid: opts.preserve_owner(),
            preserve_gid: opts.preserve_group() || opts.preserve_owner(),
            preserve_devices: opts.preserve_devices(),
            preserve_specials: opts.preserve_specials(),
            preserve_links: opts.preserve_links(),
            preserve_hard_links: false,
            always_checksum: opts.checksum_mode(),
            checksum_len: proto.checksum.digest_len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Delta state shared between encoder and decoder
// ---------------------------------------------------------------------------

/// Delta state maintained across sequential file entry encode/decode calls.
#[derive(Debug, Clone, Default)]
pub struct DeltaState {
    /// Previous entry's full filename (for prefix compression).
    pub prev_name: Vec<u8>,
    /// Previous modification time.
    pub prev_mtime: i64,
    /// Previous file mode.
    pub prev_mode: u32,
    /// Previous uid.
    pub prev_uid: u32,
    /// Previous gid.
    pub prev_gid: u32,
    /// Previous device number (major << 8 | minor).
    pub prev_rdev: u64,
    /// Previous rdev major.
    pub prev_rdev_major: u32,
    /// Previous username.
    pub prev_user_name: Vec<u8>,
    /// Previous group name.
    pub prev_group_name: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Result of reading a file list entry -- either an entry or end-of-list.
#[derive(Debug)]
pub enum ReadEntryResult {
    /// A file entry was read.
    Entry(FileEntry),
    /// End of file list, with optional I/O error code.
    EndOfList { io_error: i32 },
}

/// Decode a single file entry from the wire.
///
/// Returns `ReadEntryResult::Entry` with the decoded entry, or
/// `ReadEntryResult::EndOfList` when the end-of-list marker is encountered.
pub async fn recv_file_entry<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &mut DeltaState,
    opts: &FileListOptions,
) -> Result<ReadEntryResult> {
    // Read XMIT flags.
    let flags = if opts.xfer_flags_as_varint {
        let f = read_varint(r).await?;
        if f == 0 {
            let io_error = read_varint(r).await? as i32;
            return Ok(ReadEntryResult::EndOfList { io_error });
        }
        f
    } else {
        let first_byte = read_byte(r).await?;
        if first_byte == 0 {
            return Ok(ReadEntryResult::EndOfList { io_error: 0 });
        }
        let mut f = first_byte as u32;
        if opts.protocol_version >= 28 && (f & XMIT_EXTENDED_FLAGS) != 0 {
            let second_byte = read_byte(r).await?;
            f |= (second_byte as u32) << 8;
            if f == (XMIT_EXTENDED_FLAGS | XMIT_IO_ERROR_ENDLIST) {
                let io_error = read_varint(r).await? as i32;
                return Ok(ReadEntryResult::EndOfList { io_error });
            }
        }
        f
    };

    let pv = opts.protocol_version;

    // --- Filename ---
    let prefix_len = if (flags & XMIT_SAME_NAME) != 0 {
        read_byte(r).await? as usize
    } else {
        0
    };

    let suffix_len = if (flags & XMIT_LONG_NAME) != 0 {
        read_varint30(r, pv).await? as usize
    } else {
        read_byte(r).await? as usize
    };

    // Guard against malicious name lengths (MAXPATHLEN is typically 4096).
    const MAX_NAME_LEN: usize = 64 * 1024;
    if prefix_len + suffix_len > MAX_NAME_LEN {
        return Err(ProtocolError::WireValueOutOfRange {
            field: "filename_len",
            value: (prefix_len + suffix_len) as i64,
            max: MAX_NAME_LEN as i64,
        });
    }

    let mut name = Vec::with_capacity(prefix_len + suffix_len);
    if prefix_len > 0 {
        if prefix_len > state.prev_name.len() {
            return Err(ProtocolError::Handshake {
                message: format!(
                    "filename prefix length {prefix_len} exceeds previous name length {}",
                    state.prev_name.len()
                ),
            });
        }
        name.extend_from_slice(&state.prev_name[..prefix_len]);
    }
    if suffix_len > 0 {
        let start = name.len();
        name.resize(start + suffix_len, 0);
        r.read_exact(&mut name[start..]).await?;
    }

    // --- File length ---
    let len = read_varlong30(r, 3, pv).await?;

    // --- Modification time ---
    let mtime = if (flags & XMIT_SAME_TIME) != 0 {
        state.prev_mtime
    } else if pv >= 30 {
        read_varlong(r, 4).await?
    } else {
        read_int(r).await? as i64
    };

    // --- Mtime nanoseconds (proto >= 31) ---
    let mtime_nsec = if pv >= 31 && (flags & XMIT_MOD_NSEC) != 0 {
        read_varint(r).await?
    } else {
        0
    };

    // --- File mode ---
    let mode = if (flags & XMIT_SAME_MODE) != 0 {
        state.prev_mode
    } else {
        read_int(r).await? as u32
    };

    // --- UID ---
    let (uid, user_name) = if opts.preserve_uid && (flags & XMIT_SAME_UID) == 0 {
        let uid = if pv >= 30 {
            read_varint(r).await?
        } else {
            read_int(r).await? as u32
        };
        let uname = if pv >= 30 && (flags & XMIT_USER_NAME_FOLLOWS) != 0 {
            let namelen = read_byte(r).await? as usize;
            let mut buf = vec![0u8; namelen];
            r.read_exact(&mut buf).await?;
            buf
        } else {
            state.prev_user_name.clone()
        };
        (uid, uname)
    } else {
        (state.prev_uid, state.prev_user_name.clone())
    };

    // --- GID ---
    let (gid, group_name) = if opts.preserve_gid && (flags & XMIT_SAME_GID) == 0 {
        let gid = if pv >= 30 {
            read_varint(r).await?
        } else {
            read_int(r).await? as u32
        };
        let gname = if pv >= 30 && (flags & XMIT_GROUP_NAME_FOLLOWS) != 0 {
            let namelen = read_byte(r).await? as usize;
            let mut buf = vec![0u8; namelen];
            r.read_exact(&mut buf).await?;
            buf
        } else {
            state.prev_group_name.clone()
        };
        (gid, gname)
    } else {
        (state.prev_gid, state.prev_group_name.clone())
    };

    // --- Device numbers ---
    let rdev = if should_send_rdev(mode, opts) {
        read_rdev(r, flags, state, opts).await?
    } else {
        0
    };

    // --- Symlink target ---
    let link_target = if (mode & S_IFMT) == WIRE_S_IFLNK && opts.preserve_links {
        let link_len = read_varint30(r, pv).await? as usize;
        if link_len > MAX_NAME_LEN {
            return Err(ProtocolError::WireValueOutOfRange {
                field: "symlink_target_len",
                value: link_len as i64,
                max: MAX_NAME_LEN as i64,
            });
        }
        let mut buf = vec![0u8; link_len];
        r.read_exact(&mut buf).await?;
        buf
    } else {
        Vec::new()
    };

    // --- File checksum ---
    let checksum = if opts.always_checksum && ((mode & S_IFMT) == S_IFREG || pv < 28) {
        let mut buf = vec![0u8; opts.checksum_len];
        r.read_exact(&mut buf).await?;
        buf
    } else {
        Vec::new()
    };

    // Update delta state.
    state.prev_name = name.clone();
    state.prev_mtime = mtime;
    state.prev_mode = mode;
    state.prev_uid = uid;
    state.prev_gid = gid;
    state.prev_rdev = rdev;
    state.prev_rdev_major = (rdev >> 8) as u32;
    state.prev_user_name = user_name.clone();
    state.prev_group_name = group_name.clone();

    Ok(ReadEntryResult::Entry(FileEntry {
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
        flags,
        user_name,
        group_name,
    }))
}

/// Determine if rdev should be sent for this file mode.
fn should_send_rdev(mode: u32, opts: &FileListOptions) -> bool {
    let ft = mode & S_IFMT;
    let is_device = ft == S_IFBLK || ft == S_IFCHR;
    let is_special = ft == S_IFIFO || ft == S_IFSOCK;

    if opts.preserve_devices && is_device {
        return true;
    }
    if opts.preserve_specials && is_special && opts.protocol_version < 31 {
        return true;
    }
    false
}

/// Read device number from the wire.
async fn read_rdev<R: AsyncRead + Unpin>(
    r: &mut R,
    flags: u32,
    state: &DeltaState,
    opts: &FileListOptions,
) -> Result<u64> {
    let pv = opts.protocol_version;

    if pv < 28 {
        // Proto < 28: single int for rdev if not XMIT_SAME_RDEV_PRE28.
        if (flags & XMIT_SAME_RDEV_PRE28) != 0 {
            return Ok(state.prev_rdev);
        }
        return Ok(read_int(r).await? as u64);
    }

    // Proto >= 28: major and minor separately.
    let major = if (flags & XMIT_SAME_RDEV_MAJOR) != 0 {
        state.prev_rdev_major
    } else {
        read_varint30(r, pv).await?
    };

    let minor = if pv >= 30 {
        read_varint(r).await?
    } else if (flags & XMIT_RDEV_MINOR_8_PRE30) != 0 {
        read_byte(r).await? as u32
    } else {
        read_int(r).await? as u32
    };

    Ok(((major as u64) << 8) | (minor as u64))
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Encode a file entry to the wire format.
pub async fn send_file_entry<W: AsyncWrite + Unpin>(
    w: &mut W,
    entry: &FileEntry,
    state: &mut DeltaState,
    opts: &FileListOptions,
) -> Result<()> {
    let pv = opts.protocol_version;

    // --- Compute XMIT flags ---
    let mut flags = entry.flags & XMIT_TOP_DIR; // Preserve TOP_DIR if set.

    // Filename prefix compression.
    let common_prefix = common_prefix_len(&state.prev_name, &entry.name);
    if common_prefix > 0 {
        flags |= XMIT_SAME_NAME;
    }
    let suffix_len = entry.name.len() - common_prefix;
    if suffix_len > 255 {
        flags |= XMIT_LONG_NAME;
    }

    if entry.mtime == state.prev_mtime {
        flags |= XMIT_SAME_TIME;
    }
    if entry.mode == state.prev_mode {
        flags |= XMIT_SAME_MODE;
    }
    if opts.preserve_uid && entry.uid == state.prev_uid {
        flags |= XMIT_SAME_UID;
    }
    if opts.preserve_gid && entry.gid == state.prev_gid {
        flags |= XMIT_SAME_GID;
    }

    // Device flags.
    if should_send_rdev(entry.mode, opts) && pv >= 28 {
        let major = entry.rdev_major();
        if major == state.prev_rdev_major {
            flags |= XMIT_SAME_RDEV_MAJOR;
        }
    } else if should_send_rdev(entry.mode, opts) && pv < 28 && entry.rdev == state.prev_rdev {
        flags |= XMIT_SAME_RDEV_PRE28;
    }

    // Mtime nanoseconds (proto >= 31).
    if pv >= 31 && entry.mtime_nsec != 0 {
        flags |= XMIT_MOD_NSEC;
    }

    // Username/group name follows (proto >= 30).
    if opts.preserve_uid
        && (flags & XMIT_SAME_UID) == 0
        && pv >= 30
        && !entry.user_name.is_empty()
        && entry.user_name != state.prev_user_name
    {
        flags |= XMIT_USER_NAME_FOLLOWS;
    }
    if opts.preserve_gid
        && (flags & XMIT_SAME_GID) == 0
        && pv >= 30
        && !entry.group_name.is_empty()
        && entry.group_name != state.prev_group_name
    {
        flags |= XMIT_GROUP_NAME_FOLLOWS;
    }

    // --- Write XMIT flags ---
    write_xmit_flags(w, flags, opts).await?;

    // --- Filename ---
    if (flags & XMIT_SAME_NAME) != 0 {
        write_byte(w, common_prefix as u8).await?;
    }
    if (flags & XMIT_LONG_NAME) != 0 {
        write_varint30(w, suffix_len as u32, pv).await?;
    } else {
        write_byte(w, suffix_len as u8).await?;
    }
    w.write_all(&entry.name[common_prefix..]).await?;

    // --- File length ---
    write_varlong30(w, entry.len, 3, pv).await?;

    // --- Modification time ---
    if (flags & XMIT_SAME_TIME) == 0 {
        if pv >= 30 {
            write_varlong(w, entry.mtime, 4).await?;
        } else {
            write_int(w, entry.mtime as i32).await?;
        }
    }

    // --- Mtime nanoseconds ---
    if pv >= 31 && (flags & XMIT_MOD_NSEC) != 0 {
        write_varint(w, entry.mtime_nsec).await?;
    }

    // --- File mode ---
    if (flags & XMIT_SAME_MODE) == 0 {
        write_int(w, entry.mode as i32).await?;
    }

    // --- UID ---
    if opts.preserve_uid && (flags & XMIT_SAME_UID) == 0 {
        if pv >= 30 {
            write_varint(w, entry.uid).await?;
            if (flags & XMIT_USER_NAME_FOLLOWS) != 0 {
                write_byte(w, entry.user_name.len() as u8).await?;
                w.write_all(&entry.user_name).await?;
            }
        } else {
            write_int(w, entry.uid as i32).await?;
        }
    }

    // --- GID ---
    if opts.preserve_gid && (flags & XMIT_SAME_GID) == 0 {
        if pv >= 30 {
            write_varint(w, entry.gid).await?;
            if (flags & XMIT_GROUP_NAME_FOLLOWS) != 0 {
                write_byte(w, entry.group_name.len() as u8).await?;
                w.write_all(&entry.group_name).await?;
            }
        } else {
            write_int(w, entry.gid as i32).await?;
        }
    }

    // --- Device numbers ---
    if should_send_rdev(entry.mode, opts) {
        write_rdev(w, entry, flags, state, opts).await?;
    }

    // --- Symlink target ---
    if (entry.mode & S_IFMT) == WIRE_S_IFLNK && opts.preserve_links {
        write_varint30(w, entry.link_target.len() as u32, pv).await?;
        w.write_all(&entry.link_target).await?;
    }

    // --- File checksum ---
    if opts.always_checksum && ((entry.mode & S_IFMT) == S_IFREG || pv < 28) {
        let csum = if entry.checksum.len() >= opts.checksum_len {
            &entry.checksum[..opts.checksum_len]
        } else {
            // Pad with zeros if checksum is shorter.
            let mut padded = entry.checksum.clone();
            padded.resize(opts.checksum_len, 0);
            w.write_all(&padded).await?;
            // Update delta state and return.
            update_delta_state(state, entry);
            return Ok(());
        };
        w.write_all(csum).await?;
    }

    // Update delta state.
    update_delta_state(state, entry);
    Ok(())
}

/// Write XMIT flags to the wire.
async fn write_xmit_flags<W: AsyncWrite + Unpin>(
    w: &mut W,
    flags: u32,
    opts: &FileListOptions,
) -> Result<()> {
    if opts.xfer_flags_as_varint {
        // Varint mode: if flags would be 0, send XMIT_EXTENDED_FLAGS instead.
        let wire_flags = if flags == 0 {
            XMIT_EXTENDED_FLAGS
        } else {
            flags
        };
        write_varint(w, wire_flags).await?;
    } else if opts.protocol_version >= 28 {
        if (flags & 0xFF00) != 0 || flags == 0 {
            let wire_flags = flags | XMIT_EXTENDED_FLAGS;
            varint::write_shortint(w, wire_flags as u16).await?;
        } else {
            write_byte(w, flags as u8).await?;
        }
    } else {
        let mut low = (flags & 0xFF) as u8;
        if low == 0 {
            low = XMIT_TOP_DIR as u8;
        }
        write_byte(w, low).await?;
    }
    Ok(())
}

/// Write the end-of-file-list marker.
pub async fn write_end_of_flist<W: AsyncWrite + Unpin>(
    w: &mut W,
    io_error: i32,
    opts: &FileListOptions,
) -> Result<()> {
    if opts.xfer_flags_as_varint {
        write_varint(w, 0).await?;
        write_varint(w, io_error as u32).await?;
    } else if io_error != 0 {
        varint::write_shortint(w, (XMIT_EXTENDED_FLAGS | XMIT_IO_ERROR_ENDLIST) as u16).await?;
        write_varint(w, io_error as u32).await?;
    } else {
        write_byte(w, 0).await?;
    }
    Ok(())
}

/// Write device number to the wire.
async fn write_rdev<W: AsyncWrite + Unpin>(
    w: &mut W,
    entry: &FileEntry,
    flags: u32,
    _state: &DeltaState,
    opts: &FileListOptions,
) -> Result<()> {
    let pv = opts.protocol_version;

    if pv < 28 {
        if (flags & XMIT_SAME_RDEV_PRE28) == 0 {
            write_int(w, entry.rdev as i32).await?;
        }
        return Ok(());
    }

    // Proto >= 28: major and minor separately.
    if (flags & XMIT_SAME_RDEV_MAJOR) == 0 {
        write_varint30(w, entry.rdev_major(), pv).await?;
    }

    let minor = entry.rdev_minor();
    if pv >= 30 {
        write_varint(w, minor).await?;
    } else {
        write_int(w, minor as i32).await?;
    }

    Ok(())
}

/// Update delta state after encoding/decoding an entry.
fn update_delta_state(state: &mut DeltaState, entry: &FileEntry) {
    state.prev_name.clone_from(&entry.name);
    state.prev_mtime = entry.mtime;
    state.prev_mode = entry.mode;
    state.prev_uid = entry.uid;
    state.prev_gid = entry.gid;
    state.prev_rdev = entry.rdev;
    state.prev_rdev_major = entry.rdev_major();
    state.prev_user_name.clone_from(&entry.user_name);
    state.prev_group_name.clone_from(&entry.group_name);
}

/// Compute the length of the common prefix between two byte slices.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    // Cap at 255 since the prefix length is sent as a single byte.
    let max = a.len().min(b.len()).min(255);
    a.iter()
        .zip(b.iter())
        .take(max)
        .take_while(|(x, y)| x == y)
        .count()
}

#[cfg(test)]
mod tests {
    use super::super::entry::S_IFDIR;
    use super::*;
    use std::io::Cursor;

    fn default_opts() -> FileListOptions {
        FileListOptions {
            protocol_version: 31,
            xfer_flags_as_varint: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_roundtrip_simple_file() {
        let opts = default_opts();
        let entry = FileEntry {
            name: b"hello.txt".to_vec(),
            len: 1234,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        let result = recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap();

        match result {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.name, b"hello.txt");
                assert_eq!(decoded.len, 1234);
                assert_eq!(decoded.mtime, 1700000000);
                assert_eq!(decoded.mode, S_IFREG | 0o644);
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry, got end of list"),
        }

        // Read end of list.
        let result = recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap();
        match result {
            ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 0),
            ReadEntryResult::Entry(_) => panic!("expected end of list"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_multiple_entries_prefix_compression() {
        let opts = default_opts();
        let entries = vec![
            FileEntry {
                name: b"src/main.rs".to_vec(),
                len: 100,
                mtime: 1700000000,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"src/lib.rs".to_vec(),
                len: 200,
                mtime: 1700000001,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"src/main_test.rs".to_vec(),
                len: 300,
                mtime: 1700000002,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        for entry in &entries {
            send_file_entry(&mut buf, entry, &mut enc_state, &opts)
                .await
                .unwrap();
        }
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        for expected in &entries {
            match recv_file_entry(&mut cursor, &mut dec_state, &opts)
                .await
                .unwrap()
            {
                ReadEntryResult::Entry(decoded) => {
                    assert_eq!(decoded.name, expected.name);
                    assert_eq!(decoded.len, expected.len);
                    assert_eq!(decoded.mtime, expected.mtime);
                    assert_eq!(decoded.mode, expected.mode);
                }
                ReadEntryResult::EndOfList { .. } => panic!("unexpected end of list"),
            }
        }
    }

    #[tokio::test]
    async fn test_roundtrip_directory() {
        let opts = default_opts();
        let entry = FileEntry {
            name: b"mydir".to_vec(),
            len: 0,
            mtime: 1700000000,
            mode: S_IFDIR | 0o755,
            flags: XMIT_TOP_DIR,
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.name, b"mydir");
                assert_eq!(decoded.mode, S_IFDIR | 0o755);
                assert!(decoded.is_dir());
                assert_eq!(decoded.flags & XMIT_TOP_DIR, XMIT_TOP_DIR);
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_with_uid_gid() {
        let opts = FileListOptions {
            preserve_uid: true,
            preserve_gid: true,
            ..default_opts()
        };

        let entry = FileEntry {
            name: b"owned.txt".to_vec(),
            len: 50,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            uid: 1000,
            gid: 100,
            user_name: b"alice".to_vec(),
            group_name: b"users".to_vec(),
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.uid, 1000);
                assert_eq!(decoded.gid, 100);
                assert_eq!(decoded.user_name, b"alice");
                assert_eq!(decoded.group_name, b"users");
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_symlink() {
        let opts = FileListOptions {
            preserve_links: true,
            ..default_opts()
        };

        let entry = FileEntry {
            name: b"link.txt".to_vec(),
            len: 0,
            mtime: 1700000000,
            mode: WIRE_S_IFLNK | 0o777,
            link_target: b"/tmp/target".to_vec(),
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert!(decoded.is_symlink());
                assert_eq!(decoded.link_target, b"/tmp/target");
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_with_checksum() {
        let opts = FileListOptions {
            always_checksum: true,
            checksum_len: 16,
            ..default_opts()
        };

        let checksum = vec![0xAA; 16];
        let entry = FileEntry {
            name: b"data.bin".to_vec(),
            len: 4096,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            checksum: checksum.clone(),
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.checksum, checksum);
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_same_mode_time() {
        let opts = default_opts();

        let entry1 = FileEntry {
            name: b"a.txt".to_vec(),
            len: 100,
            mtime: 1700000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        };
        let entry2 = FileEntry {
            name: b"b.txt".to_vec(),
            len: 200,
            mtime: 1700000000,     // Same mtime
            mode: S_IFREG | 0o644, // Same mode
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry1, &mut enc_state, &opts)
            .await
            .unwrap();
        let size_first = buf.len();
        send_file_entry(&mut buf, &entry2, &mut enc_state, &opts)
            .await
            .unwrap();
        let size_second = buf.len() - size_first;
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        // Second entry should be smaller due to delta encoding.
        assert!(
            size_second < size_first,
            "second entry ({size_second}) should be smaller than first ({size_first})"
        );

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(d) => assert_eq!(d.name, b"a.txt"),
            _ => panic!("expected entry"),
        }
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(d) => {
                assert_eq!(d.name, b"b.txt");
                assert_eq!(d.mtime, 1700000000);
                assert_eq!(d.mode, S_IFREG | 0o644);
            }
            _ => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_roundtrip_mtime_nsec() {
        let opts = default_opts();
        let entry = FileEntry {
            name: b"precise.txt".to_vec(),
            len: 42,
            mtime: 1700000000,
            mtime_nsec: 123456789,
            mode: S_IFREG | 0o644,
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.mtime_nsec, 123456789);
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }

    #[tokio::test]
    async fn test_end_of_list_with_error() {
        let opts = default_opts();

        let mut buf = Vec::new();
        write_end_of_flist(&mut buf, 5, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 5),
            ReadEntryResult::Entry(_) => panic!("expected end of list"),
        }
    }

    #[tokio::test]
    async fn test_end_of_list_legacy() {
        let opts = FileListOptions {
            protocol_version: 28,
            xfer_flags_as_varint: false,
            ..Default::default()
        };

        let mut buf = Vec::new();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();
        assert_eq!(buf, &[0x00]); // Single zero byte.

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 0),
            ReadEntryResult::Entry(_) => panic!("expected end of list"),
        }
    }

    #[tokio::test]
    async fn test_common_prefix_len() {
        assert_eq!(common_prefix_len(b"", b""), 0);
        assert_eq!(common_prefix_len(b"abc", b"abd"), 2);
        assert_eq!(common_prefix_len(b"abc", b"abc"), 3);
        assert_eq!(common_prefix_len(b"src/main.rs", b"src/lib.rs"), 4);
    }

    #[tokio::test]
    async fn test_roundtrip_proto27() {
        let opts = FileListOptions {
            protocol_version: 27,
            xfer_flags_as_varint: false,
            ..Default::default()
        };

        let entry = FileEntry {
            name: b"old.txt".to_vec(),
            len: 500,
            mtime: 1600000000,
            mode: S_IFREG | 0o644,
            ..Default::default()
        };

        let mut buf = Vec::new();
        let mut enc_state = DeltaState::default();
        send_file_entry(&mut buf, &entry, &mut enc_state, &opts)
            .await
            .unwrap();
        write_end_of_flist(&mut buf, 0, &opts).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let mut dec_state = DeltaState::default();
        match recv_file_entry(&mut cursor, &mut dec_state, &opts)
            .await
            .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.name, b"old.txt");
                assert_eq!(decoded.len, 500);
                assert_eq!(decoded.mtime, 1600000000);
            }
            ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
        }
    }
}
