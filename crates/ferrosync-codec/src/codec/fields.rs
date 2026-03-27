//! Per-field encode/decode functions for file list entries.
//!
//! Each field in the XMIT wire format has a symmetric pair of functions:
//! `encode_<field>` and `decode_<field>`. The orchestrators in `mod.rs`
//! call these in identical order, making field-ordering mismatches
//! impossible by construction.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use ferrosync_protocol::varint::{
    read_byte, read_int, read_varint, read_varint30, read_varlong, read_varlong30, write_byte,
    write_int, write_varint, write_varint30, write_varlong, write_varlong30,
};
use ferrosync_protocol::wire_format::{DeviceCodec, FlagsCodec, IntCodec};
use ferrosync_types::error::ProtocolError;

use super::flags::{common_prefix_len, should_send_rdev, XmitFlags};
use super::options::FileListOptions;
use super::state::DeltaState;
use crate::entry::{S_IFMT, S_IFREG, WIRE_S_IFLNK};

type Result<T> = std::result::Result<T, ProtocolError>;

/// Maximum allowed name/path length on the wire.
const MAX_NAME_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Filename
// ---------------------------------------------------------------------------

/// Encode filename with prefix compression.
pub async fn encode_filename<W: AsyncWrite + Unpin>(
    w: &mut W,
    wire_name: &[u8],
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    let codec = opts.wire.int_codec;
    let common_prefix = common_prefix_len(&state.prev_name, wire_name);

    if flags.same_name() {
        write_byte(w, common_prefix as u8).await?;
    }

    let suffix_len = wire_name.len() - common_prefix;
    if flags.long_name() {
        write_varint30(w, suffix_len as u32, codec).await?;
    } else {
        write_byte(w, suffix_len as u8).await?;
    }

    w.write_all(&wire_name[common_prefix..]).await?;
    Ok(())
}

/// Decode filename with prefix decompression.
pub async fn decode_filename<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
    iconv: Option<&crate::iconv::FilenameConverter>,
) -> Result<Vec<u8>> {
    let codec = opts.wire.int_codec;

    let prefix_len = if flags.same_name() {
        read_byte(r).await? as usize
    } else {
        0
    };

    let suffix_len = if flags.long_name() {
        read_varint30(r, codec).await? as usize
    } else {
        read_byte(r).await? as usize
    };

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

    // Filename encoding conversion (--iconv).
    let name = if let Some(conv) = iconv {
        conv.from_wire(&name)
    } else {
        name
    };

    Ok(name)
}

// ---------------------------------------------------------------------------
// File length
// ---------------------------------------------------------------------------

/// Encode file length.
pub async fn encode_file_length<W: AsyncWrite + Unpin>(
    w: &mut W,
    len: i64,
    opts: &FileListOptions,
) -> Result<()> {
    write_varlong30(w, len, 3, opts.wire.int_codec).await
}

/// Decode file length.
pub async fn decode_file_length<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
) -> Result<i64> {
    read_varlong30(r, 3, opts.wire.int_codec).await
}

// ---------------------------------------------------------------------------
// Modification time
// ---------------------------------------------------------------------------

/// Encode modification time (only if not SAME_TIME).
pub async fn encode_mtime<W: AsyncWrite + Unpin>(
    w: &mut W,
    mtime: i64,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    if flags.same_time() {
        return Ok(());
    }
    if opts.wire.int_codec == IntCodec::Compact {
        write_varlong(w, mtime, 4).await
    } else {
        write_int(w, mtime as i32).await
    }
}

/// Decode modification time.
pub async fn decode_mtime<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<i64> {
    if flags.same_time() {
        return Ok(state.prev_mtime);
    }
    if opts.wire.int_codec == IntCodec::Compact {
        read_varlong(r, 4).await
    } else {
        Ok(read_int(r).await? as i64)
    }
}

// ---------------------------------------------------------------------------
// Mtime nanoseconds
// ---------------------------------------------------------------------------

/// Encode mtime nanoseconds (proto >= 31).
pub async fn encode_mtime_nsec<W: AsyncWrite + Unpin>(
    w: &mut W,
    mtime_nsec: u32,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    if opts.wire.has_nanoseconds && flags.mod_nsec() {
        write_varint(w, mtime_nsec).await?;
    }
    Ok(())
}

/// Decode mtime nanoseconds (proto >= 31).
pub async fn decode_mtime_nsec<R: AsyncRead + Unpin>(
    r: &mut R,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<u32> {
    if opts.wire.has_nanoseconds && flags.mod_nsec() {
        read_varint(r).await
    } else {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// File mode
// ---------------------------------------------------------------------------

/// Encode file mode (only if not SAME_MODE).
pub async fn encode_mode<W: AsyncWrite + Unpin>(
    w: &mut W,
    mode: u32,
    flags: XmitFlags,
) -> Result<()> {
    if flags.same_mode() {
        return Ok(());
    }
    write_int(w, mode as i32).await
}

/// Decode file mode.
pub async fn decode_mode<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &DeltaState,
    flags: XmitFlags,
) -> Result<u32> {
    if flags.same_mode() {
        Ok(state.prev_mode)
    } else {
        Ok(read_int(r).await? as u32)
    }
}

// ---------------------------------------------------------------------------
// UID
// ---------------------------------------------------------------------------

/// Encode uid and optional inline username.
pub async fn encode_uid<W: AsyncWrite + Unpin>(
    w: &mut W,
    uid: u32,
    user_name: &[u8],
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    if !opts.preserve_uid || flags.same_uid() {
        return Ok(());
    }

    if opts.wire.int_codec == IntCodec::Compact {
        write_varint(w, uid).await?;
        if flags.user_name_follows() {
            write_byte(w, user_name.len() as u8).await?;
            w.write_all(user_name).await?;
        }
    } else {
        write_int(w, uid as i32).await?;
    }
    Ok(())
}

/// Decode uid and optional inline username.
pub async fn decode_uid<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<(u32, Vec<u8>)> {
    if !opts.preserve_uid || flags.same_uid() {
        return Ok((state.prev_uid, state.prev_user_name.clone()));
    }

    let uid = if opts.wire.int_codec == IntCodec::Compact {
        read_varint(r).await?
    } else {
        read_int(r).await? as u32
    };

    let user_name = if opts.wire.has_inline_names && flags.user_name_follows() {
        let namelen = read_byte(r).await? as usize;
        let mut buf = vec![0u8; namelen];
        r.read_exact(&mut buf).await?;
        buf
    } else {
        state.prev_user_name.clone()
    };

    Ok((uid, user_name))
}

// ---------------------------------------------------------------------------
// GID
// ---------------------------------------------------------------------------

/// Encode gid and optional inline group name.
pub async fn encode_gid<W: AsyncWrite + Unpin>(
    w: &mut W,
    gid: u32,
    group_name: &[u8],
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    if !opts.preserve_gid || flags.same_gid() {
        return Ok(());
    }

    if opts.wire.int_codec == IntCodec::Compact {
        write_varint(w, gid).await?;
        if flags.group_name_follows() {
            write_byte(w, group_name.len() as u8).await?;
            w.write_all(group_name).await?;
        }
    } else {
        write_int(w, gid as i32).await?;
    }
    Ok(())
}

/// Decode gid and optional inline group name.
pub async fn decode_gid<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<(u32, Vec<u8>)> {
    if !opts.preserve_gid || flags.same_gid() {
        return Ok((state.prev_gid, state.prev_group_name.clone()));
    }

    let gid = if opts.wire.int_codec == IntCodec::Compact {
        read_varint(r).await?
    } else {
        read_int(r).await? as u32
    };

    let group_name = if opts.wire.has_inline_names && flags.group_name_follows() {
        let namelen = read_byte(r).await? as usize;
        let mut buf = vec![0u8; namelen];
        r.read_exact(&mut buf).await?;
        buf
    } else {
        state.prev_group_name.clone()
    };

    Ok((gid, group_name))
}

// ---------------------------------------------------------------------------
// Device numbers (rdev)
// ---------------------------------------------------------------------------

/// Encode device number (major/minor or single int).
pub async fn encode_rdev<W: AsyncWrite + Unpin>(
    w: &mut W,
    mode: u32,
    rdev: u64,
    rdev_major: u32,
    rdev_minor: u32,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<()> {
    if !should_send_rdev(mode, opts) {
        return Ok(());
    }

    let codec = opts.wire.int_codec;

    match opts.wire.device_codec {
        DeviceCodec::SingleInt => {
            if !flags.same_rdev_pre28() {
                write_int(w, rdev as i32).await?;
            }
        }
        DeviceCodec::MajorMinor { varint_minor } => {
            if !flags.same_rdev_major() {
                write_varint30(w, rdev_major, codec).await?;
            }
            if varint_minor {
                write_varint(w, rdev_minor).await?;
            } else {
                write_int(w, rdev_minor as i32).await?;
            }
        }
    }
    Ok(())
}

/// Decode device number.
pub async fn decode_rdev<R: AsyncRead + Unpin>(
    r: &mut R,
    mode: u32,
    state: &DeltaState,
    flags: XmitFlags,
    opts: &FileListOptions,
) -> Result<u64> {
    if !should_send_rdev(mode, opts) {
        return Ok(0);
    }

    let codec = opts.wire.int_codec;

    match opts.wire.device_codec {
        DeviceCodec::SingleInt => {
            if flags.same_rdev_pre28() {
                Ok(state.prev_rdev)
            } else {
                Ok(read_int(r).await? as u64)
            }
        }
        DeviceCodec::MajorMinor { varint_minor } => {
            let major = if flags.same_rdev_major() {
                state.prev_rdev_major
            } else {
                read_varint30(r, codec).await?
            };

            let minor = if varint_minor {
                read_varint(r).await?
            } else {
                read_int(r).await? as u32
            };

            Ok(((major as u64) << 8) | (minor as u64))
        }
    }
}

// ---------------------------------------------------------------------------
// Symlink target
// ---------------------------------------------------------------------------

/// Encode symlink target.
pub async fn encode_symlink<W: AsyncWrite + Unpin>(
    w: &mut W,
    mode: u32,
    link_target: &[u8],
    opts: &FileListOptions,
) -> Result<()> {
    if (mode & S_IFMT) != WIRE_S_IFLNK || !opts.preserve_links {
        return Ok(());
    }
    write_varint30(w, link_target.len() as u32, opts.wire.int_codec).await?;
    w.write_all(link_target).await?;
    Ok(())
}

/// Decode symlink target.
pub async fn decode_symlink<R: AsyncRead + Unpin>(
    r: &mut R,
    mode: u32,
    opts: &FileListOptions,
) -> Result<Vec<u8>> {
    if (mode & S_IFMT) != WIRE_S_IFLNK || !opts.preserve_links {
        return Ok(Vec::new());
    }

    let link_len = read_varint30(r, opts.wire.int_codec).await? as usize;
    if link_len > MAX_NAME_LEN {
        return Err(ProtocolError::WireValueOutOfRange {
            field: "symlink_target_len",
            value: link_len as i64,
            max: MAX_NAME_LEN as i64,
        });
    }
    let mut buf = vec![0u8; link_len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// File checksum
// ---------------------------------------------------------------------------

/// Encode file-level checksum.
pub async fn encode_checksum<W: AsyncWrite + Unpin>(
    w: &mut W,
    mode: u32,
    checksum: &[u8],
    opts: &FileListOptions,
) -> Result<()> {
    let checksum_for_all_types = opts.wire.flags_codec == FlagsCodec::Byte;
    if !opts.always_checksum || ((mode & S_IFMT) != S_IFREG && !checksum_for_all_types) {
        return Ok(());
    }

    if checksum.len() >= opts.checksum_len {
        w.write_all(&checksum[..opts.checksum_len]).await?;
    } else {
        // Pad with zeros if checksum is shorter.
        let mut padded = checksum.to_vec();
        padded.resize(opts.checksum_len, 0);
        w.write_all(&padded).await?;
    }
    Ok(())
}

/// Decode file-level checksum.
pub async fn decode_checksum<R: AsyncRead + Unpin>(
    r: &mut R,
    mode: u32,
    opts: &FileListOptions,
) -> Result<Vec<u8>> {
    let checksum_for_all_types = opts.wire.flags_codec == FlagsCodec::Byte;
    if !opts.always_checksum || ((mode & S_IFMT) != S_IFREG && !checksum_for_all_types) {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; opts.checksum_len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
