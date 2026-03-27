//! Rsync-compatible batch mode (`--write-batch` / `--read-batch`).
//!
//! Records the sender's wire data to a file during a push/pull, so it can
//! be replayed later without a network connection. The batch file format
//! matches rsync's native format:
//!
//! ```text
//! Header:
//!   protocol_version  : i32 LE
//!   compat_flags      : varint (proto >= 30) or absent
//!   checksum_seed      : i32 LE
//!   stream_flags       : i32 LE
//! Body:
//!   Raw sender-side wire bytes (file list + delta data)
//! ```
//!
//! The stream flags bitmap captures transfer options that must match between
//! write and read. On read-batch, flags override the caller's config and
//! mismatches are logged.

use std::io::{self, Write as StdWrite};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use ferrosync_types::options::TransferConfig;

// ---------------------------------------------------------------------------
// Stream flags -- match rsync batch.c flag_ptr/flag_name arrays
// ---------------------------------------------------------------------------

/// Bit 0: recurse
pub const FLAG_RECURSE: u32 = 1 << 0;
/// Bit 1: preserve_uid (owner)
pub const FLAG_PRESERVE_UID: u32 = 1 << 1;
/// Bit 2: preserve_gid (group)
pub const FLAG_PRESERVE_GID: u32 = 1 << 2;
/// Bit 3: preserve_links (symlinks)
pub const FLAG_PRESERVE_LINKS: u32 = 1 << 3;
/// Bit 4: preserve_devices
pub const FLAG_PRESERVE_DEVICES: u32 = 1 << 4;
/// Bit 5: preserve_hard_links
pub const FLAG_PRESERVE_HARD_LINKS: u32 = 1 << 5;
/// Bit 6: always_checksum
pub const FLAG_ALWAYS_CHECKSUM: u32 = 1 << 6;
/// Bit 7: preserve_acls
pub const FLAG_PRESERVE_ACLS: u32 = 1 << 7;
/// Bit 8: preserve_xattrs
pub const FLAG_PRESERVE_XATTRS: u32 = 1 << 8;
/// Bit 9: iconv (character set conversion)
pub const FLAG_ICONV: u32 = 1 << 9;
/// Bit 10: preserve_perms
pub const FLAG_PRESERVE_PERMS: u32 = 1 << 10;
/// Bit 11: preserve_executability (not tracked separately in our config)
pub const FLAG_PRESERVE_EXECUTABILITY: u32 = 1 << 11;
/// Bit 12: preserve_times
pub const FLAG_PRESERVE_TIMES: u32 = 1 << 12;

/// Build a stream flags bitmap from transfer configuration.
pub fn compute_stream_flags(config: &TransferConfig) -> u32 {
    let mut flags = 0u32;
    if config.recursive() {
        flags |= FLAG_RECURSE;
    }
    if config.preserve_owner() {
        flags |= FLAG_PRESERVE_UID;
    }
    if config.preserve_group() {
        flags |= FLAG_PRESERVE_GID;
    }
    if config.preserve_links() {
        flags |= FLAG_PRESERVE_LINKS;
    }
    if config.preserve_devices() {
        flags |= FLAG_PRESERVE_DEVICES;
    }
    if config.preserve_hard_links() {
        flags |= FLAG_PRESERVE_HARD_LINKS;
    }
    if config.checksum_mode() {
        flags |= FLAG_ALWAYS_CHECKSUM;
    }
    if config.preserve_acls() {
        flags |= FLAG_PRESERVE_ACLS;
    }
    if config.preserve_xattrs() {
        flags |= FLAG_PRESERVE_XATTRS;
    }
    if config.iconv().is_some() {
        flags |= FLAG_ICONV;
    }
    if config.preserve_perms() {
        flags |= FLAG_PRESERVE_PERMS;
    }
    if config.preserve_times() {
        flags |= FLAG_PRESERVE_TIMES;
    }
    flags
}

/// Flag name for logging when overriding options on read-batch.
const FLAG_NAMES: &[(u32, &str)] = &[
    (FLAG_RECURSE, "recurse"),
    (FLAG_PRESERVE_UID, "preserve_uid"),
    (FLAG_PRESERVE_GID, "preserve_gid"),
    (FLAG_PRESERVE_LINKS, "preserve_links"),
    (FLAG_PRESERVE_DEVICES, "preserve_devices"),
    (FLAG_PRESERVE_HARD_LINKS, "preserve_hard_links"),
    (FLAG_ALWAYS_CHECKSUM, "always_checksum"),
    (FLAG_PRESERVE_ACLS, "preserve_acls"),
    (FLAG_PRESERVE_XATTRS, "preserve_xattrs"),
    (FLAG_ICONV, "iconv"),
    (FLAG_PRESERVE_PERMS, "preserve_perms"),
    (FLAG_PRESERVE_EXECUTABILITY, "preserve_executability"),
    (FLAG_PRESERVE_TIMES, "preserve_times"),
];

/// Override transfer config fields from a stream flags bitmap.
///
/// Logs when a flag is being set or cleared relative to the current config,
/// matching rsync's "Setting/Clearing the X option" messages.
pub fn apply_stream_flags(flags: u32, config: &mut TransferConfig) {
    let current = compute_stream_flags(config);

    for &(bit, name) in FLAG_NAMES {
        let in_batch = flags & bit != 0;
        let in_config = current & bit != 0;
        if in_batch != in_config {
            if in_batch {
                tracing::info!("Setting the {} option to match the batch file", name);
            } else {
                tracing::info!("Clearing the {} option to match the batch file", name);
            }
        }
    }

    use ferrosync_types::options::DirectoryMode;

    config.traversal.dir_mode = if flags & FLAG_RECURSE != 0 {
        DirectoryMode::Recurse
    } else {
        DirectoryMode::default()
    };
    config.preservation.owner = flags & FLAG_PRESERVE_UID != 0;
    config.preservation.group = flags & FLAG_PRESERVE_GID != 0;
    config.preservation.links = flags & FLAG_PRESERVE_LINKS != 0;
    config.preservation.devices = flags & FLAG_PRESERVE_DEVICES != 0;
    config.preservation.hard_links = flags & FLAG_PRESERVE_HARD_LINKS != 0;
    config.file_selection.checksum_mode = flags & FLAG_ALWAYS_CHECKSUM != 0;
    config.preservation.acls = flags & FLAG_PRESERVE_ACLS != 0;
    config.preservation.xattrs = flags & FLAG_PRESERVE_XATTRS != 0;
    config.preservation.perms = flags & FLAG_PRESERVE_PERMS != 0;
    config.preservation.times = flags & FLAG_PRESERVE_TIMES != 0;
}

// ---------------------------------------------------------------------------
// Batch header I/O (synchronous -- header is only ~16 bytes)
// ---------------------------------------------------------------------------

/// Write the rsync-format batch header to a file.
///
/// Format:
///   `protocol_version` : i32 LE
///   `compat_flags`     : varint (proto >= 30)
///   `checksum_seed`    : i32 LE
///   `stream_flags`     : i32 LE
pub fn write_batch_header(
    file: &mut dyn StdWrite,
    version: u8,
    compat_flags: u32,
    seed: i32,
    config: &TransferConfig,
) -> io::Result<()> {
    // Protocol version.
    file.write_all(&(version as i32).to_le_bytes())?;

    // Compat flags (varint for proto >= 30).
    if version >= 30 {
        write_varint_sync(file, compat_flags)?;
    }

    // Checksum seed.
    file.write_all(&seed.to_le_bytes())?;

    // Stream flags.
    let stream_flags = compute_stream_flags(config);
    file.write_all(&(stream_flags as i32).to_le_bytes())?;

    file.flush()?;
    Ok(())
}

/// Read the rsync-format batch header from a file.
///
/// Returns `(protocol_version, compat_flags, seed, stream_flags)`.
pub fn read_batch_header(file: &mut dyn std::io::Read) -> io::Result<(u8, u32, i32, u32)> {
    // Protocol version.
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    let version = i32::from_le_bytes(buf) as u8;

    // Compat flags.
    let compat_flags = if version >= 30 {
        read_varint_sync(file)?
    } else {
        0
    };

    // Checksum seed.
    file.read_exact(&mut buf)?;
    let seed = i32::from_le_bytes(buf);

    // Stream flags.
    file.read_exact(&mut buf)?;
    let stream_flags = i32::from_le_bytes(buf) as u32;

    Ok((version, compat_flags, seed, stream_flags))
}

/// Write the companion shell script for `--read-batch` replay.
///
/// rsync writes a `.sh` file alongside the batch file with the command
/// to replay it.
pub fn write_batch_shell_file(batch_path: &Path) -> io::Result<()> {
    let sh_path = batch_path.with_extension("sh");
    let batch_name = batch_path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    let script = format!(
        "#!/bin/sh\n\
         \n\
         # This script was auto-generated by ferrosync --write-batch.\n\
         # Usage: {} DEST\n\
         \n\
         ferrosync --read-batch={} \"${{1:-DEST}}\"\n",
        sh_path.display(),
        batch_name,
    );

    std::fs::write(&sh_path, script)?;

    // Make executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&sh_path, perms)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DualWriter -- tees writes to both wire and batch file
// ---------------------------------------------------------------------------

/// An `AsyncWrite` adapter that writes to both the inner wire writer and a
/// local batch file. The batch file receives a copy of every byte sent over
/// the wire, allowing later replay with `--read-batch`.
///
/// The batch file is written synchronously (page-cache I/O on a local file
/// is effectively non-blocking) while the wire write is delegated normally.
pub struct DualWriter<W> {
    wire: W,
    batch: io::BufWriter<std::fs::File>,
}

impl<W> DualWriter<W> {
    /// Create a new `DualWriter` wrapping `wire` and teeing to `batch_file`.
    pub fn new(wire: W, batch_file: std::fs::File) -> Self {
        Self {
            wire,
            batch: io::BufWriter::with_capacity(64 * 1024, batch_file),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for DualWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Poll the wire first to find out how many bytes it accepts.
        let result = Pin::new(&mut self.wire).poll_write(cx, buf);

        // Only tee to batch the exact number of bytes the wire accepted.
        // This avoids duplicating bytes on short writes or pending polls.
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                if let Err(e) = self.batch.write_all(&buf[..*n]) {
                    return Poll::Ready(Err(e));
                }
            }
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush batch file.
        if let Err(e) = self.batch.flush() {
            return Poll::Ready(Err(e));
        }
        // Flush wire.
        Pin::new(&mut self.wire).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush batch file before shutdown.
        if let Err(e) = self.batch.flush() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.wire).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Sync varint I/O (for batch header only)
// ---------------------------------------------------------------------------

/// Write a u32 as rsync's varint encoding (synchronous).
///
/// Rsync's varint format:
/// - If value fits in 1 byte (< 0xFE): write 1 byte
/// - If value fits in 2 bytes (< 0xFEFF): write 0xFE marker + 2 LE bytes
/// - Otherwise: write 0xFF marker + 4 LE bytes (only 3 needed for our range)
fn write_varint_sync(w: &mut dyn StdWrite, val: u32) -> io::Result<()> {
    if val < 0xFE {
        w.write_all(&[val as u8])
    } else if val < 0x10000 {
        w.write_all(&[0xFE])?;
        w.write_all(&(val as u16).to_le_bytes())
    } else {
        w.write_all(&[0xFF])?;
        // rsync writes 4 bytes for the "3 or more bytes" case but the
        // high byte is implicitly the number of extra bytes. For compat
        // flags this never exceeds 32 bits, so write all 4.
        w.write_all(&val.to_le_bytes())
    }
}

/// Read a varint from rsync's encoding (synchronous).
fn read_varint_sync(r: &mut dyn std::io::Read) -> io::Result<u32> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    match b[0] {
        0xFE => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u32)
        }
        0xFF => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf))
        }
        v => Ok(v as u32),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_flags_roundtrip() {
        let config = TransferConfig::builder()
            .recursive(true)
            .preserve_owner(true)
            .preserve_group(true)
            .preserve_links(true)
            .preserve_devices(true)
            .preserve_perms(true)
            .preserve_times(true)
            .preserve_hard_links(true)
            .preserve_acls(true)
            .preserve_xattrs(true)
            .checksum_mode(true)
            .build();

        let flags = compute_stream_flags(&config);
        assert_ne!(flags, 0);

        let mut config2 = TransferConfig::default();
        apply_stream_flags(flags, &mut config2);

        assert!(config2.recursive());
        assert!(config2.preserve_owner());
        assert!(config2.preserve_group());
        assert!(config2.preserve_links());
        assert!(config2.preserve_devices());
        assert!(config2.preserve_perms());
        assert!(config2.preserve_times());
        assert!(config2.preserve_hard_links());
        assert!(config2.preserve_acls());
        assert!(config2.preserve_xattrs());
        assert!(config2.checksum_mode());
    }

    #[test]
    fn test_stream_flags_empty_config() {
        let config = TransferConfig::default();
        let flags = compute_stream_flags(&config);
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_batch_header_roundtrip() {
        let config = TransferConfig::builder()
            .recursive(true)
            .preserve_times(true)
            .preserve_perms(true)
            .build();

        let mut buf = Vec::new();
        write_batch_header(&mut buf, 31, 0xFF, 12345, &config).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let (version, compat, seed, stream_flags) = read_batch_header(&mut cursor).unwrap();

        assert_eq!(version, 31);
        assert_eq!(compat, 0xFF);
        assert_eq!(seed, 12345);

        let expected_flags = FLAG_RECURSE | FLAG_PRESERVE_TIMES | FLAG_PRESERVE_PERMS;
        assert_eq!(stream_flags, expected_flags);
    }

    #[test]
    fn test_batch_header_roundtrip_proto29() {
        // Proto < 30: no compat_flags varint.
        let config = TransferConfig::default();
        let mut buf = Vec::new();
        write_batch_header(&mut buf, 29, 0, 42, &config).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let (version, compat, seed, stream_flags) = read_batch_header(&mut cursor).unwrap();

        assert_eq!(version, 29);
        assert_eq!(compat, 0);
        assert_eq!(seed, 42);
        assert_eq!(stream_flags, 0);
    }

    #[test]
    fn test_varint_sync_roundtrip_small() {
        let mut buf = Vec::new();
        write_varint_sync(&mut buf, 42).unwrap();
        assert_eq!(buf.len(), 1);

        let mut cursor = std::io::Cursor::new(&buf);
        assert_eq!(read_varint_sync(&mut cursor).unwrap(), 42);
    }

    #[test]
    fn test_varint_sync_roundtrip_medium() {
        let mut buf = Vec::new();
        write_varint_sync(&mut buf, 0x1234).unwrap();
        assert_eq!(buf.len(), 3); // 0xFE + 2 bytes

        let mut cursor = std::io::Cursor::new(&buf);
        assert_eq!(read_varint_sync(&mut cursor).unwrap(), 0x1234);
    }

    #[test]
    fn test_varint_sync_roundtrip_large() {
        let mut buf = Vec::new();
        write_varint_sync(&mut buf, 0x12345678).unwrap();
        assert_eq!(buf.len(), 5); // 0xFF + 4 bytes

        let mut cursor = std::io::Cursor::new(&buf);
        assert_eq!(read_varint_sync(&mut cursor).unwrap(), 0x12345678);
    }
}
