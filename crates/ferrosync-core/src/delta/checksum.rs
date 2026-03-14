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
pub fn checksum2(data: &[u8], seed: i32, checksum_type: ChecksumType) -> Vec<u8> {
    match checksum_type {
        ChecksumType::Md4 => {
            use md4::{Digest, Md4};
            let mut h = Md4::new();
            h.update(seed.to_le_bytes());
            h.update(data);
            h.finalize().to_vec()
        }
        ChecksumType::Md5 => {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            h.update(seed.to_le_bytes());
            h.update(data);
            h.finalize().to_vec()
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
        ChecksumType::None => vec![0; checksum_type.digest_len()],
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
        self.s1 = self.s1
            .wrapping_add(new_byte as u32)
            .wrapping_sub(old_byte as u32);
        self.s2 = self.s2
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
        let c = checksum2(b"test data", 12345, ChecksumType::Md5);
        assert_eq!(c.len(), ChecksumType::Md5.digest_len());
        // Verify determinism.
        assert_eq!(c, checksum2(b"test data", 12345, ChecksumType::Md5));
    }

    #[test]
    fn test_checksum2_md4() {
        let c = checksum2(b"test data", 12345, ChecksumType::Md4);
        assert_eq!(c.len(), ChecksumType::Md4.digest_len());
    }

    #[test]
    fn test_checksum2_different_seeds() {
        let c1 = checksum2(b"same data", 1, ChecksumType::Md5);
        let c2 = checksum2(b"same data", 2, ChecksumType::Md5);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_file_checksum_no_seed() {
        // file_checksum does NOT include the seed (unlike checksum2).
        let data = b"file contents";
        let seed = 42;
        // With seed, checksum2 differs from seedless file_checksum.
        assert_ne!(
            file_checksum(data, seed, ChecksumType::Md5),
            checksum2(data, seed, ChecksumType::Md5),
        );
        // file_checksum is plain MD5 of data.
        use md5::{Digest, Md5};
        let expected = Md5::digest(data).to_vec();
        assert_eq!(file_checksum(data, seed, ChecksumType::Md5), expected);
    }
}
