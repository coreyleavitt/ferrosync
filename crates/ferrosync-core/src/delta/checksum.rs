//! Checksum algorithms for rsync block and file-level verification.
//!
//! rsync uses a two-level checksum scheme:
//! - **Rolling checksum** (checksum1): A fast, Adler-32-like hash used to find
//!   candidate block matches via a hash table lookup.
//! - **Strong checksum** (checksum2): MD4 (proto < 30) or MD5 (proto >= 30),
//!   used to verify candidate matches and for whole-file verification.

use crate::protocol::handshake::ChecksumType;

/// Maximum digest length for any supported checksum algorithm.
///
/// Sized to accommodate future algorithms (e.g., BLAKE3 = 32 bytes).
/// Use [`ChecksumType::digest_len()`] for the actual length of a specific algorithm.
pub const MAX_DIGEST_LEN: usize = 32;

/// CHAR_OFFSET for protocol >= 30 rolling checksum.
pub const CHAR_OFFSET_V30: u32 = 0;

/// CHAR_OFFSET for protocol < 30 rolling checksum.
pub const CHAR_OFFSET_OLD: u32 = 31;

/// Compute rsync's rolling checksum (checksum1) over a data block.
///
/// This is a modified Adler-32 where `s1` accumulates byte values (plus a
/// per-protocol offset) and `s2` accumulates the running `s1` totals.
pub fn checksum1(data: &[u8], char_offset: u32) -> u32 {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for &byte in data {
        s1 = s1.wrapping_add(byte as u32 + char_offset);
        s2 = s2.wrapping_add(s1);
    }
    (s1 & 0xFFFF) | (s2 << 16)
}

/// Compute a strong checksum (checksum2) over a data block.
///
/// Seeded with the transfer's checksum seed to prevent precomputed collision
/// attacks. Returns the full digest (16 bytes for both MD4 and MD5).
///
/// When `proper_seed_order` is true (modern rsync, CF_CHKSUM_SEED_FIX),
/// the seed is hashed before the data. When false (older rsync), the seed
/// is hashed after the data.
pub fn checksum2(
    data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
    proper_seed_order: bool,
) -> Vec<u8> {
    let seed_bytes = seed.to_le_bytes();
    match checksum_type {
        ChecksumType::Md4 => {
            use md4::{Digest, Md4};
            let mut h = Md4::new();
            if proper_seed_order {
                h.update(seed_bytes);
                h.update(data);
            } else {
                h.update(data);
                h.update(seed_bytes);
            }
            h.finalize().to_vec()
        }
        ChecksumType::Md5 => {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            if proper_seed_order {
                h.update(seed_bytes);
                h.update(data);
            } else {
                h.update(data);
                h.update(seed_bytes);
            }
            h.finalize().to_vec()
        }
        ChecksumType::Blake3 => {
            let mut h = blake3::Hasher::new();
            if proper_seed_order {
                h.update(&seed_bytes);
                h.update(data);
            } else {
                h.update(data);
                h.update(&seed_bytes);
            }
            h.finalize().as_bytes().to_vec()
        }
        ChecksumType::Xxh3 => {
            // XOR seed into the xxh3 seed parameter.
            let hash = xxhash_rust::xxh3::xxh3_64_with_seed(data, seed as u64);
            hash.to_le_bytes().to_vec()
        }
        ChecksumType::Xxh128 => {
            let hash = xxhash_rust::xxh3::xxh3_128_with_seed(data, seed as u64);
            hash.to_le_bytes().to_vec()
        }
        ChecksumType::None => vec![0; checksum_type.digest_len()],
    }
}

/// Compute a whole-file transfer checksum for final verification.
///
/// Unlike block-level `checksum2`, the file-level transfer checksum does
/// NOT include the seed for MD5 and modern MD4. Only old MD4 variants
/// (not used since protocol 30) hash the seed. This matches rsync's
/// `sum_init`/`sum_update`/`sum_end` flow.
pub fn file_checksum(data: &[u8], _seed: i32, checksum_type: ChecksumType) -> Vec<u8> {
    match checksum_type {
        ChecksumType::Md4 => {
            use md4::{Digest, Md4};
            let mut h = Md4::new();
            h.update(data);
            h.finalize().to_vec()
        }
        ChecksumType::Md5 => {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            h.update(data);
            h.finalize().to_vec()
        }
        ChecksumType::Blake3 => {
            let mut h = blake3::Hasher::new();
            h.update(data);
            h.finalize().as_bytes().to_vec()
        }
        ChecksumType::Xxh3 => {
            let hash = xxhash_rust::xxh3::xxh3_64(data);
            hash.to_le_bytes().to_vec()
        }
        ChecksumType::Xxh128 => {
            let hash = xxhash_rust::xxh3::xxh3_128(data);
            hash.to_le_bytes().to_vec()
        }
        ChecksumType::None => vec![0; checksum_type.digest_len()],
    }
}

/// Incremental file-level checksum for streaming verification.
///
/// Wraps the same hash algorithms as [`file_checksum`] but supports
/// incremental `update` calls followed by a single `finalize`.
/// This allows computing the file checksum without buffering the
/// entire file in memory.
#[allow(clippy::large_enum_variant)]
pub enum IncrementalChecksum {
    Md4(md4::Md4),
    Md5(md5::Md5),
    Blake3(Box<blake3::Hasher>),
    Xxh3(xxhash_rust::xxh3::Xxh3),
    Xxh128(xxhash_rust::xxh3::Xxh3),
    None(usize),
}

impl IncrementalChecksum {
    /// Create a new incremental checksum for the given algorithm.
    pub fn new(checksum_type: ChecksumType) -> Self {
        match checksum_type {
            ChecksumType::Md4 => {
                use md4::Digest;
                IncrementalChecksum::Md4(md4::Md4::new())
            }
            ChecksumType::Md5 => {
                use md5::Digest;
                IncrementalChecksum::Md5(md5::Md5::new())
            }
            ChecksumType::Blake3 => IncrementalChecksum::Blake3(Box::new(blake3::Hasher::new())),
            ChecksumType::Xxh3 => {
                IncrementalChecksum::Xxh3(xxhash_rust::xxh3::Xxh3::new())
            }
            ChecksumType::Xxh128 => {
                IncrementalChecksum::Xxh128(xxhash_rust::xxh3::Xxh3::new())
            }
            ChecksumType::None => IncrementalChecksum::None(checksum_type.digest_len()),
        }
    }

    /// Feed more data into the checksum.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            IncrementalChecksum::Md4(h) => {
                use md4::Digest;
                h.update(data);
            }
            IncrementalChecksum::Md5(h) => {
                use md5::Digest;
                h.update(data);
            }
            IncrementalChecksum::Blake3(h) => {
                h.update(data);
            }
            IncrementalChecksum::Xxh3(h) | IncrementalChecksum::Xxh128(h) => {
                h.update(data);
            }
            IncrementalChecksum::None(_) => {}
        }
    }

    /// Finalize and return the digest bytes.
    pub fn finalize(self) -> Vec<u8> {
        match self {
            IncrementalChecksum::Md4(h) => {
                use md4::Digest;
                h.finalize().to_vec()
            }
            IncrementalChecksum::Md5(h) => {
                use md5::Digest;
                h.finalize().to_vec()
            }
            IncrementalChecksum::Blake3(h) => h.finalize().as_bytes().to_vec(),
            IncrementalChecksum::Xxh3(h) => {
                let hash = h.digest();
                hash.to_le_bytes().to_vec()
            }
            IncrementalChecksum::Xxh128(h) => {
                let hash = h.digest128();
                hash.to_le_bytes().to_vec()
            }
            IncrementalChecksum::None(len) => vec![0; len],
        }
    }
}

/// State for an incremental rolling checksum that can be updated byte-by-byte
/// as a window slides over the data.
#[derive(Debug, Clone)]
pub struct RollingChecksum {
    s1: u32,
    s2: u32,
    count: u32,
    char_offset: u32,
}

impl RollingChecksum {
    pub fn new(char_offset: u32) -> Self {
        Self {
            s1: 0,
            s2: 0,
            count: 0,
            char_offset,
        }
    }

    /// Reset and compute the checksum over an entire block.
    pub fn compute(&mut self, data: &[u8]) {
        self.s1 = 0;
        self.s2 = 0;
        self.count = data.len() as u32;
        for &byte in data {
            self.s1 = self.s1.wrapping_add(byte as u32 + self.char_offset);
            self.s2 = self.s2.wrapping_add(self.s1);
        }
    }

    /// Roll the window forward: remove `old_byte` from the left, add
    /// `new_byte` on the right.
    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        self.s1 = self
            .s1
            .wrapping_add(new_byte as u32)
            .wrapping_sub(old_byte as u32);
        self.s2 = self
            .s2
            .wrapping_add(self.s1)
            .wrapping_sub(self.count.wrapping_mul(old_byte as u32 + self.char_offset));
    }

    /// Get the current digest value.
    pub fn digest(&self) -> u32 {
        (self.s1 & 0xFFFF) | (self.s2 << 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum1_empty() {
        assert_eq!(checksum1(b"", CHAR_OFFSET_V30), 0);
    }

    #[test]
    fn test_checksum1_deterministic() {
        let c1 = checksum1(b"hello world", CHAR_OFFSET_V30);
        let c2 = checksum1(b"hello world", CHAR_OFFSET_V30);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_checksum1_different_data() {
        let c1 = checksum1(b"hello", CHAR_OFFSET_V30);
        let c2 = checksum1(b"world", CHAR_OFFSET_V30);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_checksum1_char_offset() {
        let c1 = checksum1(b"test", CHAR_OFFSET_V30);
        let c2 = checksum1(b"test", CHAR_OFFSET_OLD);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_rolling_matches_batch() {
        let data = b"hello world";
        let batch = checksum1(data, CHAR_OFFSET_V30);
        let mut rolling = RollingChecksum::new(CHAR_OFFSET_V30);
        rolling.compute(data);
        assert_eq!(rolling.digest(), batch);
    }

    #[test]
    fn test_rolling_slide() {
        // Compute checksum of "ello " by sliding from "hello" one byte right.
        let data = b"hello world";
        let block_len = 5;

        // Batch checksum of the second window.
        let expected = checksum1(&data[1..1 + block_len], CHAR_OFFSET_V30);

        // Rolling checksum: start at first window, slide forward.
        let mut rolling = RollingChecksum::new(CHAR_OFFSET_V30);
        rolling.compute(&data[..block_len]);
        rolling.roll(data[0], data[block_len]);
        assert_eq!(rolling.digest(), expected);
    }

    #[test]
    fn test_checksum2_md5() {
        let c = checksum2(b"test data", 12345, ChecksumType::Md5, true);
        assert_eq!(c.len(), ChecksumType::Md5.digest_len());
        // Verify determinism.
        assert_eq!(c, checksum2(b"test data", 12345, ChecksumType::Md5, true));
    }

    #[test]
    fn test_checksum2_md4() {
        let c = checksum2(b"test data", 12345, ChecksumType::Md4, true);
        assert_eq!(c.len(), ChecksumType::Md4.digest_len());
    }

    #[test]
    fn test_checksum2_different_seeds() {
        let c1 = checksum2(b"same data", 1, ChecksumType::Md5, true);
        let c2 = checksum2(b"same data", 2, ChecksumType::Md5, true);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_checksum2_seed_order() {
        // When proper_seed_order is true, seed goes before data.
        // When false, seed goes after data. Results should differ.
        let c_proper = checksum2(b"test", 42, ChecksumType::Md5, true);
        let c_old = checksum2(b"test", 42, ChecksumType::Md5, false);
        assert_ne!(c_proper, c_old);
    }

    #[test]
    fn test_file_checksum_no_seed() {
        // file_checksum does NOT include the seed (unlike checksum2).
        let data = b"file contents";
        let seed = 42;
        // With seed, checksum2 differs from seedless file_checksum.
        assert_ne!(
            file_checksum(data, seed, ChecksumType::Md5),
            checksum2(data, seed, ChecksumType::Md5, true),
        );
        // file_checksum is plain MD5 of data.
        use md5::{Digest, Md5};
        let expected = Md5::digest(data).to_vec();
        assert_eq!(file_checksum(data, seed, ChecksumType::Md5), expected);
    }

    // -----------------------------------------------------------------------
    // BLAKE3 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blake3_file_checksum_empty() {
        let c = file_checksum(b"", 0, ChecksumType::Blake3);
        assert_eq!(c.len(), 32);
        // Known BLAKE3 hash of empty input.
        let expected = blake3::hash(b"");
        assert_eq!(c, expected.as_bytes().as_slice());
    }

    #[test]
    fn test_blake3_file_checksum_hello_world() {
        let c = file_checksum(b"hello world", 0, ChecksumType::Blake3);
        assert_eq!(c.len(), 32);
        let expected = blake3::hash(b"hello world");
        assert_eq!(c, expected.as_bytes().as_slice());
    }

    #[test]
    fn test_blake3_checksum2_deterministic() {
        let c1 = checksum2(b"test data", 42, ChecksumType::Blake3, true);
        let c2 = checksum2(b"test data", 42, ChecksumType::Blake3, true);
        assert_eq!(c1.len(), 32);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_blake3_checksum2_seed_order() {
        let c_proper = checksum2(b"test", 42, ChecksumType::Blake3, true);
        let c_old = checksum2(b"test", 42, ChecksumType::Blake3, false);
        assert_ne!(c_proper, c_old);
    }

    #[test]
    fn test_blake3_checksum2_different_seeds() {
        let c1 = checksum2(b"same", 1, ChecksumType::Blake3, true);
        let c2 = checksum2(b"same", 2, ChecksumType::Blake3, true);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_blake3_file_checksum_ignores_seed() {
        let c1 = file_checksum(b"data", 1, ChecksumType::Blake3);
        let c2 = file_checksum(b"data", 999, ChecksumType::Blake3);
        assert_eq!(c1, c2);
    }

    // -----------------------------------------------------------------------
    // XXH3 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_xxh3_checksum2_deterministic() {
        let c1 = checksum2(b"test data", 42, ChecksumType::Xxh3, true);
        let c2 = checksum2(b"test data", 42, ChecksumType::Xxh3, true);
        assert_eq!(c1.len(), 8);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_xxh3_checksum2_known_vector() {
        // Verify against the xxhash-rust crate directly.
        let hash = xxhash_rust::xxh3::xxh3_64_with_seed(b"hello", 0);
        let c = checksum2(b"hello", 0, ChecksumType::Xxh3, true);
        assert_eq!(c, hash.to_le_bytes());
    }

    #[test]
    fn test_xxh3_checksum2_different_seeds() {
        let c1 = checksum2(b"same", 1, ChecksumType::Xxh3, true);
        let c2 = checksum2(b"same", 2, ChecksumType::Xxh3, true);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_xxh3_file_checksum() {
        let c = file_checksum(b"hello world", 0, ChecksumType::Xxh3);
        assert_eq!(c.len(), 8);
        let expected = xxhash_rust::xxh3::xxh3_64(b"hello world");
        assert_eq!(c, expected.to_le_bytes());
    }

    #[test]
    fn test_xxh3_file_checksum_ignores_seed() {
        let c1 = file_checksum(b"data", 1, ChecksumType::Xxh3);
        let c2 = file_checksum(b"data", 999, ChecksumType::Xxh3);
        assert_eq!(c1, c2);
    }

    // -----------------------------------------------------------------------
    // XXH128 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_xxh128_checksum2_deterministic() {
        let c1 = checksum2(b"test data", 42, ChecksumType::Xxh128, true);
        let c2 = checksum2(b"test data", 42, ChecksumType::Xxh128, true);
        assert_eq!(c1.len(), 16);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_xxh128_checksum2_known_vector() {
        let hash = xxhash_rust::xxh3::xxh3_128_with_seed(b"hello", 0);
        let c = checksum2(b"hello", 0, ChecksumType::Xxh128, true);
        assert_eq!(c, hash.to_le_bytes());
    }

    #[test]
    fn test_xxh128_checksum2_different_seeds() {
        let c1 = checksum2(b"same", 1, ChecksumType::Xxh128, true);
        let c2 = checksum2(b"same", 2, ChecksumType::Xxh128, true);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_xxh128_file_checksum() {
        let c = file_checksum(b"hello world", 0, ChecksumType::Xxh128);
        assert_eq!(c.len(), 16);
        let expected = xxhash_rust::xxh3::xxh3_128(b"hello world");
        assert_eq!(c, expected.to_le_bytes());
    }

    #[test]
    fn test_xxh128_file_checksum_ignores_seed() {
        let c1 = file_checksum(b"data", 1, ChecksumType::Xxh128);
        let c2 = file_checksum(b"data", 999, ChecksumType::Xxh128);
        assert_eq!(c1, c2);
    }

    // -----------------------------------------------------------------------
    // IncrementalChecksum tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_incremental_matches_batch_md5() {
        let data = b"hello world, this is a test of incremental checksumming";
        let batch = file_checksum(data, 0, ChecksumType::Md5);
        let mut inc = IncrementalChecksum::new(ChecksumType::Md5);
        inc.update(&data[..10]);
        inc.update(&data[10..30]);
        inc.update(&data[30..]);
        assert_eq!(inc.finalize(), batch);
    }

    #[test]
    fn test_incremental_matches_batch_blake3() {
        let data = b"blake3 incremental test data";
        let batch = file_checksum(data, 0, ChecksumType::Blake3);
        let mut inc = IncrementalChecksum::new(ChecksumType::Blake3);
        inc.update(&data[..5]);
        inc.update(&data[5..]);
        assert_eq!(inc.finalize(), batch);
    }

    #[test]
    fn test_incremental_matches_batch_xxh3() {
        let data = b"xxh3 incremental test data";
        let batch = file_checksum(data, 0, ChecksumType::Xxh3);
        let mut inc = IncrementalChecksum::new(ChecksumType::Xxh3);
        inc.update(&data[..8]);
        inc.update(&data[8..]);
        assert_eq!(inc.finalize(), batch);
    }

    #[test]
    fn test_incremental_matches_batch_xxh128() {
        let data = b"xxh128 incremental test data";
        let batch = file_checksum(data, 0, ChecksumType::Xxh128);
        let mut inc = IncrementalChecksum::new(ChecksumType::Xxh128);
        inc.update(&data[..12]);
        inc.update(&data[12..]);
        assert_eq!(inc.finalize(), batch);
    }

    #[test]
    fn test_incremental_matches_batch_md4() {
        let data = b"md4 incremental test data";
        let batch = file_checksum(data, 0, ChecksumType::Md4);
        let mut inc = IncrementalChecksum::new(ChecksumType::Md4);
        inc.update(data);
        assert_eq!(inc.finalize(), batch);
    }

    #[test]
    fn test_incremental_empty_data() {
        let batch = file_checksum(b"", 0, ChecksumType::Md5);
        let inc = IncrementalChecksum::new(ChecksumType::Md5);
        assert_eq!(inc.finalize(), batch);
    }
}
