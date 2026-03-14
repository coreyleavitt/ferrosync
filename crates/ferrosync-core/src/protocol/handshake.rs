//! Protocol version negotiation and capability handshake.
//!
//! Rsync negotiation proceeds in stages:
//!
//! 1. Exchange 4-byte LE protocol version; use the minimum.
//! 2. (proto >= 30) Exchange compatibility flags.
//! 3. (proto >= 30, with `CF_VARINT_FLIST_FLAGS`) Negotiate checksum and
//!    compression algorithm names.
//! 4. Exchange checksum seed (4 bytes LE).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::delta::chunker::ChunkingStrategy;
use crate::error::ProtocolError;
use crate::protocol::varint;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Supported protocol range
// ---------------------------------------------------------------------------

/// Minimum protocol version we support.
pub const MIN_PROTOCOL_VERSION: u8 = 27;

/// Maximum protocol version we advertise.
pub const MAX_PROTOCOL_VERSION: u8 = 31;

// ---------------------------------------------------------------------------
// Compatibility flags (CF_*)
// ---------------------------------------------------------------------------

/// Compatibility flag bits exchanged in protocol >= 30.
pub mod compat_flags {
    /// Incremental recursive file list.
    pub const INC_RECURSE: u32 = 1 << 0;
    /// Receiver can set symlink timestamps.
    pub const SYMLINK_TIMES: u32 = 1 << 1;
    /// Sender supports symlink iconv.
    pub const SYMLINK_ICONV: u32 = 1 << 2;
    /// Safe incremental flist (flist sorting fix).
    pub const SAFE_FLIST: u32 = 1 << 3;
    /// Avoid xattr optimization.
    pub const AVOID_XATTR_OPTIM: u32 = 1 << 4;
    /// Proper checksum seed ordering fix.
    pub const CHKSUM_SEED_FIX: u32 = 1 << 5;
    /// Inplace partial directory support.
    pub const INPLACE_PARTIAL_DIR: u32 = 1 << 6;
    /// Varint flist flags + negotiated strings.
    pub const VARINT_FLIST_FLAGS: u32 = 1 << 7;
    /// Include uid 0/gid 0 names.
    pub const ID0_NAMES: u32 = 1 << 8;

    /// Default flags we advertise as a modern client.
    pub const DEFAULT: u32 = SAFE_FLIST
        | AVOID_XATTR_OPTIM
        | CHKSUM_SEED_FIX
        | INPLACE_PARTIAL_DIR
        | VARINT_FLIST_FLAGS
        | ID0_NAMES;
}

// ---------------------------------------------------------------------------
// Checksum algorithm
// ---------------------------------------------------------------------------

/// Negotiated checksum algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType {
    None,
    Md4,
    Md5,
    Blake3,
    Xxh3,
    Xxh128,
}

impl ChecksumType {
    /// Default for a given protocol version (when negotiation is not used).
    pub fn default_for_version(version: u8) -> Self {
        if version >= 30 {
            Self::Md5
        } else {
            Self::Md4
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Md4 => "md4",
            Self::Md5 => "md5",
            Self::Blake3 => "blake3",
            Self::Xxh3 => "xxh3",
            Self::Xxh128 => "xxh128",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "md4" => Some(Self::Md4),
            "md5" => Some(Self::Md5),
            "blake3" => Some(Self::Blake3),
            "xxh3" => Some(Self::Xxh3),
            "xxh128" => Some(Self::Xxh128),
            _ => None,
        }
    }

    /// Digest length in bytes for this algorithm.
    ///
    /// This is the number of bytes written/read on the wire for file-level
    /// checksums. Use this instead of `MAX_DIGEST_LEN` for wire I/O.
    pub fn digest_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Md4 => 16,
            Self::Md5 => 16,
            Self::Blake3 => 32,
            Self::Xxh3 => 8,
            Self::Xxh128 => 16,
        }
    }
}

/// Negotiated compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressType {
    None,
    Zlib,
    Zlibx,
    Zstd,
    Lz4,
}

impl CompressType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zlib => "zlib",
            Self::Zlibx => "zlibx",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "zlib" => Some(Self::Zlib),
            "zlibx" => Some(Self::Zlibx),
            "zstd" => Some(Self::Zstd),
            "lz4" => Some(Self::Lz4),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Negotiated protocol state
// ---------------------------------------------------------------------------

/// Result of the protocol handshake -- threaded through all codecs.
#[derive(Debug, Clone)]
pub struct NegotiatedProtocol {
    /// Agreed protocol version (min of both sides).
    pub version: u8,
    /// Compatibility flags (proto >= 30).
    pub compat_flags: u32,
    /// Whether incremental file lists are enabled (proto >= 30 + flag).
    pub incremental_flist: bool,
    /// Whether flist XMIT flags use varint encoding.
    pub varint_flist_flags: bool,
    /// Negotiated checksum algorithm.
    pub checksum: ChecksumType,
    /// Negotiated compression algorithm.
    pub compress: CompressType,
    /// Whether to use proper checksum seed ordering.
    pub proper_seed_order: bool,
    /// Checksum seed exchanged during handshake.
    pub seed: i32,
    /// Chunking strategy for delta transfer.
    ///
    /// Defaults to `Fixed` for rsync compatibility. When both sides are
    /// ferrosync, this can be upgraded to `FastCDC` via out-of-band
    /// negotiation (wire negotiation not yet implemented).
    pub chunking: ChunkingStrategy,
}

impl NegotiatedProtocol {
    /// Whether this protocol version uses compact varint encoding.
    pub fn uses_varint(&self) -> bool {
        self.version >= 30
    }
}

// ---------------------------------------------------------------------------
// Client-side capability string
// ---------------------------------------------------------------------------

/// Build the capability string that goes in the `-e.` option for remote rsync.
///
/// Returns a string like `.iLsfxCIvu` (without the leading `e`).
pub fn build_capability_string(
    inc_recurse: bool,
    symlink_times: bool,
    iconv: bool,
) -> String {
    let mut caps = String::from(".");
    if inc_recurse {
        caps.push('i');
    }
    if symlink_times {
        caps.push('L');
    }
    if iconv {
        caps.push('s');
    }
    caps.push('f'); // safe flist
    caps.push('x'); // avoid xattr optim
    caps.push('C'); // checksum seed fix
    caps.push('I'); // inplace partial dir
    caps.push('v'); // varint flist flags + negotiated strings
    caps.push('u'); // id0 names
    caps
}

// ---------------------------------------------------------------------------
// VString encoding (used for checksum/compression list negotiation)
// ---------------------------------------------------------------------------

/// Read a vstring (length-prefixed string).
///
/// - Length 0-127: 1-byte prefix.
/// - Length 128-32767: 2-byte prefix (first byte = `len/256 + 0x80`).
async fn read_vstring<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let first = varint::read_byte(r).await?;
    let len = if first & 0x80 != 0 {
        let second = varint::read_byte(r).await?;
        ((first as usize & 0x7F) << 8) | second as usize
    } else {
        first as usize
    };

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Write a vstring (length-prefixed string).
async fn write_vstring<W: AsyncWrite + Unpin>(w: &mut W, s: &str) -> Result<()> {
    let len = s.len();
    if len > 32767 {
        return Err(ProtocolError::Handshake {
            message: format!("vstring too long: {len}"),
        });
    }
    if len <= 127 {
        w.write_all(&[len as u8]).await?;
    } else {
        w.write_all(&[((len >> 8) as u8) | 0x80, (len & 0xFF) as u8])
            .await?;
    }
    w.write_all(s.as_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Checksum/compression negotiation
// ---------------------------------------------------------------------------

/// Our supported checksum algorithms in priority order.
const CHECKSUM_LIST: &str = "blake3 xxh128 xxh3 md5 md4 none";

/// Our supported compression algorithms in priority order.
const COMPRESS_LIST: &str = "zstd lz4 zlibx zlib none";

/// Negotiate an algorithm: pick the first entry from the sender's list that
/// the receiver also supports.
fn negotiate_algorithm<T: Copy>(
    sender_list: &str,
    receiver_list: &str,
    parse_fn: fn(&str) -> Option<T>,
) -> Result<T> {
    for name in sender_list.split_whitespace() {
        if receiver_list.split_whitespace().any(|r| r == name) {
            if let Some(algo) = parse_fn(name) {
                return Ok(algo);
            }
        }
    }
    Err(ProtocolError::Handshake {
        message: format!(
            "no common algorithm: sender=[{sender_list}], receiver=[{receiver_list}]"
        ),
    })
}

// ---------------------------------------------------------------------------
// Handshake execution
// ---------------------------------------------------------------------------

/// Perform the client-side handshake.
///
/// The caller must have already established the transport (SSH subprocess or
/// daemon connection) and be ready to send/receive on the provided streams.
///
/// `am_sender`: true if we are pushing files, false if pulling.
/// `use_compress`: true if compression was requested.
pub async fn client_handshake<R, W>(
    r: &mut R,
    w: &mut W,
    am_sender: bool,
    use_compress: bool,
) -> Result<NegotiatedProtocol>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Step 1: Exchange protocol version.
    varint::write_int(w, MAX_PROTOCOL_VERSION as i32).await?;
    w.flush().await?;

    let remote_version = varint::read_int(r).await? as u8;
    let version = MAX_PROTOCOL_VERSION.min(remote_version);

    if version < MIN_PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            version: remote_version,
        });
    }

    // Step 2: Compatibility flags (proto >= 30).
    //
    // rsync 3.2+ (proto 32) sends compat_flags as a varint to support
    // flags above bit 7. Even when the negotiated version is < 32, the
    // server may still use varint encoding (its code path is based on
    // its own version, not the negotiated one). Using read_varint is
    // safe for all proto >= 30 since values < 128 encode identically
    // as both a single byte and a varint.
    let mut flags = 0u32;
    if version >= 30 {
        flags = varint::read_varint(r).await?;
    }

    let varint_flist_flags = flags & compat_flags::VARINT_FLIST_FLAGS != 0;
    let do_negotiated_strings = varint_flist_flags;
    let proper_seed_order = flags & compat_flags::CHKSUM_SEED_FIX != 0;
    let incremental_flist = flags & compat_flags::INC_RECURSE != 0;

    // Step 3: Checksum/compression negotiation (proto >= 30, with 'v').
    let mut checksum = ChecksumType::default_for_version(version);
    let mut compress = if use_compress {
        CompressType::Zlib
    } else {
        CompressType::None
    };

    if do_negotiated_strings {
        // Checksum negotiation: both sides exchange lists.
        write_vstring(w, CHECKSUM_LIST).await?;
        let remote_checksums = read_vstring(r).await?;

        checksum = if am_sender {
            negotiate_algorithm(CHECKSUM_LIST, &remote_checksums, ChecksumType::from_name)?
        } else {
            negotiate_algorithm(&remote_checksums, CHECKSUM_LIST, ChecksumType::from_name)?
        };

        // Compression negotiation (only if compressing).
        if use_compress {
            write_vstring(w, COMPRESS_LIST).await?;
            let remote_compress = read_vstring(r).await?;

            compress = if am_sender {
                negotiate_algorithm(
                    COMPRESS_LIST,
                    &remote_compress,
                    CompressType::from_name,
                )?
            } else {
                negotiate_algorithm(
                    &remote_compress,
                    COMPRESS_LIST,
                    CompressType::from_name,
                )?
            };
        }

        w.flush().await?;
    }

    // Step 4: Checksum seed.
    let seed = varint::read_int(r).await?;

    Ok(NegotiatedProtocol {
        version,
        compat_flags: flags,
        incremental_flist,
        varint_flist_flags,
        checksum,
        compress,
        proper_seed_order,
        seed,
        chunking: ChunkingStrategy::default(),
    })
}

/// Perform the server-side handshake (used when running as `--server`).
///
/// `client_info`: the capability characters from the client's `-e.` option
/// (e.g., ".iLsfxCIvu").
/// `am_sender`: true if we (the server) are the sender.
/// `use_compress`: true if compression was requested.
pub async fn server_handshake<R, W>(
    r: &mut R,
    w: &mut W,
    client_info: &str,
    am_sender: bool,
    use_compress: bool,
) -> Result<NegotiatedProtocol>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Step 1: Exchange protocol version.
    let remote_version = varint::read_int(r).await? as u8;
    varint::write_int(w, MAX_PROTOCOL_VERSION as i32).await?;

    let version = MAX_PROTOCOL_VERSION.min(remote_version);
    if version < MIN_PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            version: remote_version,
        });
    }

    // Step 2: Build and send compat_flags (proto >= 30).
    //
    // Always use varint encoding for consistency with modern rsync.
    let mut flags = 0u32;
    if version >= 30 {
        flags = build_compat_flags_from_client_info(client_info);
        varint::write_varint(w, flags).await?;
    }

    let varint_flist_flags = flags & compat_flags::VARINT_FLIST_FLAGS != 0;
    let do_negotiated_strings = varint_flist_flags;
    let proper_seed_order = flags & compat_flags::CHKSUM_SEED_FIX != 0;
    let incremental_flist = flags & compat_flags::INC_RECURSE != 0;

    // Step 3: Checksum/compression negotiation.
    let mut checksum = ChecksumType::default_for_version(version);
    let mut compress = if use_compress {
        CompressType::Zlib
    } else {
        CompressType::None
    };

    if do_negotiated_strings {
        let remote_checksums = read_vstring(r).await?;
        write_vstring(w, CHECKSUM_LIST).await?;

        checksum = if am_sender {
            negotiate_algorithm(CHECKSUM_LIST, &remote_checksums, ChecksumType::from_name)?
        } else {
            negotiate_algorithm(&remote_checksums, CHECKSUM_LIST, ChecksumType::from_name)?
        };

        if use_compress {
            let remote_compress = read_vstring(r).await?;
            write_vstring(w, COMPRESS_LIST).await?;

            compress = if am_sender {
                negotiate_algorithm(
                    COMPRESS_LIST,
                    &remote_compress,
                    CompressType::from_name,
                )?
            } else {
                negotiate_algorithm(
                    &remote_compress,
                    COMPRESS_LIST,
                    CompressType::from_name,
                )?
            };
        }
    }

    // Step 4: Send checksum seed.
    let seed = generate_seed();
    varint::write_int(w, seed).await?;
    w.flush().await?;

    Ok(NegotiatedProtocol {
        version,
        compat_flags: flags,
        incremental_flist,
        varint_flist_flags,
        checksum,
        compress,
        proper_seed_order,
        seed,
        chunking: ChunkingStrategy::default(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse client capability characters into compat_flags.
fn build_compat_flags_from_client_info(info: &str) -> u32 {
    let mut flags = 0u32;

    // Server's own capabilities.
    flags |= compat_flags::INC_RECURSE;

    #[cfg(unix)]
    {
        flags |= compat_flags::SYMLINK_TIMES;
    }

    // Client capabilities parsed from the info string.
    for ch in info.chars() {
        match ch {
            'f' => flags |= compat_flags::SAFE_FLIST,
            'x' => flags |= compat_flags::AVOID_XATTR_OPTIM,
            'C' => flags |= compat_flags::CHKSUM_SEED_FIX,
            'I' => flags |= compat_flags::INPLACE_PARTIAL_DIR,
            'v' => flags |= compat_flags::VARINT_FLIST_FLAGS,
            'u' => flags |= compat_flags::ID0_NAMES,
            'i' => {} // already set INC_RECURSE above
            'L' => {} // receiver_symlink_times, handled separately
            's' => {} // sender_symlink_iconv, handled separately
            _ => {}   // ignore unknown
        }
    }

    flags
}

/// Generate a checksum seed (matches rsync: time ^ (pid << 6)).
fn generate_seed() -> i32 {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i32;
    let pid = std::process::id() as i32;
    secs ^ (pid << 6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_build_capability_string() {
        let caps = build_capability_string(true, true, false);
        assert_eq!(caps, ".iLfxCIvu");

        let caps = build_capability_string(false, false, false);
        assert_eq!(caps, ".fxCIvu");
    }

    #[test]
    fn test_build_compat_flags_from_client_info() {
        let flags = build_compat_flags_from_client_info(".iLsfxCIvu");
        assert!(flags & compat_flags::SAFE_FLIST != 0);
        assert!(flags & compat_flags::AVOID_XATTR_OPTIM != 0);
        assert!(flags & compat_flags::CHKSUM_SEED_FIX != 0);
        assert!(flags & compat_flags::INPLACE_PARTIAL_DIR != 0);
        assert!(flags & compat_flags::VARINT_FLIST_FLAGS != 0);
        assert!(flags & compat_flags::ID0_NAMES != 0);
        assert!(flags & compat_flags::INC_RECURSE != 0);
    }

    #[test]
    fn test_negotiate_checksum() {
        let sender = "md5 md4 none";
        let receiver = "md4 none";
        let result =
            negotiate_algorithm(sender, receiver, ChecksumType::from_name).unwrap();
        assert_eq!(result, ChecksumType::Md4);
    }

    #[test]
    fn test_negotiate_checksum_md5() {
        let sender = "md5 md4 none";
        let receiver = "md5 md4 none";
        let result =
            negotiate_algorithm(sender, receiver, ChecksumType::from_name).unwrap();
        assert_eq!(result, ChecksumType::Md5);
    }

    #[test]
    fn test_negotiate_no_common() {
        let sender = "md5";
        let receiver = "none";
        assert!(negotiate_algorithm(sender, receiver, ChecksumType::from_name).is_err());
    }

    #[tokio::test]
    async fn test_vstring_roundtrip_short() {
        let mut buf = Vec::new();
        write_vstring(&mut buf, "hello").await.unwrap();
        assert_eq!(buf[0], 5); // 1-byte length

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_vstring(&mut cursor).await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_vstring_roundtrip_long() {
        let long_str = "a".repeat(200);
        let mut buf = Vec::new();
        write_vstring(&mut buf, &long_str).await.unwrap();
        assert_eq!(buf[0] & 0x80, 0x80); // 2-byte length prefix

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_vstring(&mut cursor).await.unwrap(), long_str);
    }

    #[tokio::test]
    async fn test_client_server_handshake() {
        // Simulate a client-server handshake via in-memory pipes.
        // We'll run the server side manually to construct the expected byte stream.

        // Build what the server would send:
        let mut server_output = Vec::new();

        // Server sends its protocol version.
        varint::write_int(&mut server_output, 31).await.unwrap();

        // Server sends compat_flags as varint.
        let flags = compat_flags::DEFAULT | compat_flags::INC_RECURSE;
        varint::write_varint(&mut server_output, flags).await.unwrap();

        // Server reads client's checksum list, then sends its own.
        // For this test, we pre-write the server's response.
        write_vstring(&mut server_output, CHECKSUM_LIST)
            .await
            .unwrap();

        // Checksum seed.
        varint::write_int(&mut server_output, 12345).await.unwrap();

        // What the client should send:
        let mut client_expected = Vec::new();
        // Client sends protocol version.
        varint::write_int(&mut client_expected, MAX_PROTOCOL_VERSION as i32)
            .await
            .unwrap();
        // Client sends checksum list.
        write_vstring(&mut client_expected, CHECKSUM_LIST)
            .await
            .unwrap();

        // Run the client handshake against the server's pre-built output.
        let mut server_read = Cursor::new(server_output);
        let mut client_write = Vec::new();

        let result = client_handshake(
            &mut server_read,
            &mut client_write,
            false, // am_sender = false (pulling)
            false, // no compression
        )
        .await
        .unwrap();

        assert_eq!(result.version, 31);
        assert_eq!(result.checksum, ChecksumType::Blake3);
        assert_eq!(result.seed, 12345);
        assert!(result.varint_flist_flags);
        assert!(result.incremental_flist);
        assert!(result.proper_seed_order);

        // Verify the client sent the expected bytes.
        assert_eq!(&client_write[..4], &client_expected[..4]); // version
    }

    #[test]
    fn test_checksum_type_names() {
        assert_eq!(ChecksumType::Md5.name(), "md5");
        assert_eq!(ChecksumType::from_name("md5"), Some(ChecksumType::Md5));
        assert_eq!(ChecksumType::from_name("unknown"), None);
        assert_eq!(ChecksumType::Blake3.name(), "blake3");
        assert_eq!(ChecksumType::from_name("blake3"), Some(ChecksumType::Blake3));
        assert_eq!(ChecksumType::Xxh3.name(), "xxh3");
        assert_eq!(ChecksumType::from_name("xxh3"), Some(ChecksumType::Xxh3));
        assert_eq!(ChecksumType::Xxh128.name(), "xxh128");
        assert_eq!(ChecksumType::from_name("xxh128"), Some(ChecksumType::Xxh128));
    }

    #[test]
    fn test_checksum_digest_lengths() {
        assert_eq!(ChecksumType::None.digest_len(), 0);
        assert_eq!(ChecksumType::Md4.digest_len(), 16);
        assert_eq!(ChecksumType::Md5.digest_len(), 16);
        assert_eq!(ChecksumType::Blake3.digest_len(), 32);
        assert_eq!(ChecksumType::Xxh3.digest_len(), 8);
        assert_eq!(ChecksumType::Xxh128.digest_len(), 16);
    }

    #[test]
    fn test_compress_type_names() {
        assert_eq!(CompressType::Zlib.name(), "zlib");
        assert_eq!(CompressType::from_name("zlibx"), Some(CompressType::Zlibx));
        assert_eq!(CompressType::from_name("lz4"), Some(CompressType::Lz4));
    }

    #[test]
    fn test_checksum_default_for_version() {
        assert_eq!(
            ChecksumType::default_for_version(27),
            ChecksumType::Md4
        );
        assert_eq!(
            ChecksumType::default_for_version(30),
            ChecksumType::Md5
        );
        assert_eq!(
            ChecksumType::default_for_version(31),
            ChecksumType::Md5
        );
    }

    #[test]
    fn test_negotiate_ferrosync_to_ferrosync_picks_blake3() {
        // When both sides are ferrosync, the first common entry wins.
        // Our CHECKSUM_LIST starts with blake3, so ferrosync-to-ferrosync
        // should negotiate blake3.
        let result = negotiate_algorithm(
            CHECKSUM_LIST,
            CHECKSUM_LIST,
            ChecksumType::from_name,
        )
        .unwrap();
        assert_eq!(result, ChecksumType::Blake3);
    }

    #[test]
    fn test_negotiate_ferrosync_to_rsync_falls_back_to_md5() {
        // Standard rsync only supports "md5 md4 none".
        let rsync_list = "md5 md4 none";
        let result = negotiate_algorithm(
            CHECKSUM_LIST,
            rsync_list,
            ChecksumType::from_name,
        )
        .unwrap();
        assert_eq!(result, ChecksumType::Md5);
    }

    #[test]
    fn test_negotiate_rsync_sender_ferrosync_receiver() {
        // rsync is sender, ferrosync is receiver -- rsync's list is checked
        // in order against ferrosync's supported set.
        let rsync_list = "md5 md4 none";
        let result = negotiate_algorithm(
            rsync_list,
            CHECKSUM_LIST,
            ChecksumType::from_name,
        )
        .unwrap();
        assert_eq!(result, ChecksumType::Md5);
    }

    #[test]
    fn test_negotiate_xxh128_when_no_blake3() {
        // If one side does not support blake3, fall back to next common.
        let limited = "xxh128 md5 none";
        let result = negotiate_algorithm(
            CHECKSUM_LIST,
            limited,
            ChecksumType::from_name,
        )
        .unwrap();
        assert_eq!(result, ChecksumType::Xxh128);
    }
}
