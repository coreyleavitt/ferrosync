//! Protocol enums and constants shared across crates.
//!
//! These types capture negotiated protocol state (checksum algorithm,
//! compression algorithm, chunking strategy, wire codec choices) without
//! any implementation logic. They live in `ferrosync-types` so that both
//! `ferrosync-core`'s delta and protocol modules can depend on them
//! without circular imports.

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

// ---------------------------------------------------------------------------
// Compression algorithm
// ---------------------------------------------------------------------------

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
// Chunking strategy
// ---------------------------------------------------------------------------

/// Strategy for splitting data into blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkingStrategy {
    /// Traditional fixed-size blocks (rsync-compatible default).
    Fixed {
        /// Block size in bytes.
        block_size: usize,
    },
    /// FastCDC content-defined chunking with variable-size blocks.
    FastCDC {
        /// Minimum chunk size in bytes.
        min: usize,
        /// Average (target) chunk size in bytes.
        avg: usize,
        /// Maximum chunk size in bytes.
        max: usize,
    },
}

impl Default for ChunkingStrategy {
    fn default() -> Self {
        Self::Fixed { block_size: 700 }
    }
}

impl ChunkingStrategy {
    /// Default CDC parameters: min=2KB, avg=8KB, max=64KB.
    pub fn default_cdc() -> Self {
        Self::FastCDC {
            min: 2 * 1024,
            avg: 8 * 1024,
            max: 64 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire codec enums
// ---------------------------------------------------------------------------

/// Integer encoding strategy on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntCodec {
    /// Proto < 30: 4-byte LE, sentinel longint, fixed NDX.
    Fixed,
    /// Proto >= 30: varint, varlong, delta-encoded NDX.
    Compact,
}

/// XMIT flag encoding in file list entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagsCodec {
    /// Proto < 28: single byte.
    Byte,
    /// Proto 28-29: byte + optional extended byte.
    ByteExtended,
    /// Proto >= 30 with CF_VARINT_FLIST_FLAGS.
    Varint,
}

/// Device number encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCodec {
    /// Proto < 28: single integer.
    SingleInt,
    /// Proto >= 28: separate major/minor (varint_minor when proto >= 30).
    MajorMinor { varint_minor: bool },
}
