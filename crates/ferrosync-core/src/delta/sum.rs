//! Block signature structures and wire-format codec.
//!
//! The generator sends block signatures to the sender so it can identify
//! matching blocks. The wire format is:
//!
//! ```text
//! sum_head: count(i32) + blength(i32) + s2length(i32) + remainder(i32)
//! For each block:
//!   sum1: rolling checksum (4 bytes, little-endian u32)
//!   sum2: strong checksum (s2length bytes)
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::protocol::handshake::ChecksumType;
use crate::protocol::varint;

use super::checksum::{self, MAX_DIGEST_LEN};

type Result<T> = std::result::Result<T, ProtocolError>;

/// Header describing the block signature parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SumHead {
    /// Number of blocks.
    pub count: i32,
    /// Block length in bytes (all blocks except possibly the last).
    pub blength: i32,
    /// Strong checksum length (truncated from full digest for wire efficiency).
    pub s2length: i32,
    /// Length of the last (possibly shorter) block.
    pub remainder: i32,
}

/// A single block's checksums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumEntry {
    /// Rolling checksum (checksum1).
    pub sum1: u32,
    /// Strong checksum (checksum2), truncated to s2length bytes.
    pub sum2: Vec<u8>,
}

/// Complete set of block signatures for a file.
#[derive(Debug, Clone)]
pub struct SumStruct {
    pub head: SumHead,
    pub sums: Vec<SumEntry>,
}

/// Compute appropriate block length for a file of the given size.
///
/// Matches rsync's heuristic: roughly sqrt(file_len), clamped to
/// [700, MAX_BLOCK_SIZE] and rounded to a multiple of 8.
pub fn compute_block_length(file_len: i64) -> i32 {
    const MIN_BLOCK_LEN: i32 = 700;
    const MAX_BLOCK_LEN: i32 = 1 << 17; // 128 KiB

    if file_len <= 0 {
        return MIN_BLOCK_LEN;
    }

    let blength = (file_len as f64).sqrt() as i32;
    let blength = blength.clamp(MIN_BLOCK_LEN, MAX_BLOCK_LEN);
    (blength + 7) & !7 // round up to multiple of 8
}

/// Compute the strong checksum length based on file size and block count.
///
/// Enough bytes to make accidental collision probability negligible.
pub fn compute_s2length(file_len: i64, blength: i32) -> i32 {
    if file_len <= 0 {
        return 2;
    }

    let block_count = (file_len + blength as i64 - 1) / blength as i64;
    // P(false match) ~ block_count / 2^(s2length*8)
    // Want P < 2^-80, so s2length >= (80 + log2(block_count)) / 8
    let bits_needed = 80.0 + (block_count as f64).log2();
    let s2length = (bits_needed / 8.0).ceil() as i32;
    s2length.min(MAX_DIGEST_LEN as i32).max(2)
}

/// Compute block signatures for a file.
pub fn compute_signatures(
    data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
) -> SumStruct {
    if data.is_empty() {
        return SumStruct {
            head: SumHead::default(),
            sums: Vec::new(),
        };
    }

    let file_len = data.len() as i64;
    let blength = compute_block_length(file_len);
    let s2length = compute_s2length(file_len, blength);
    let char_offset = checksum::CHAR_OFFSET_V30;

    let mut sums = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + blength as usize).min(data.len());
        let block = &data[offset..end];

        let sum1 = checksum::checksum1(block, char_offset);
        let strong = checksum::checksum2(block, seed, checksum_type);
        let sum2 = strong[..s2length as usize].to_vec();

        sums.push(SumEntry { sum1, sum2 });
        offset = end;
    }

    let remainder = if data.len().is_multiple_of(blength as usize) {
        blength
    } else {
        (data.len() % blength as usize) as i32
    };

    SumStruct {
        head: SumHead {
            count: sums.len() as i32,
            blength,
            s2length,
            remainder,
        },
        sums,
    }
}

/// Write a sum_head to the wire.
pub async fn write_sum_head<W: AsyncWrite + Unpin>(
    w: &mut W,
    head: &SumHead,
) -> Result<()> {
    varint::write_int(w, head.count).await?;
    varint::write_int(w, head.blength).await?;
    varint::write_int(w, head.s2length).await?;
    varint::write_int(w, head.remainder).await?;
    Ok(())
}

/// Read a sum_head from the wire.
pub async fn read_sum_head<R: AsyncRead + Unpin>(r: &mut R) -> Result<SumHead> {
    let count = varint::read_int(r).await?;
    let blength = varint::read_int(r).await?;
    let s2length = varint::read_int(r).await?;
    let remainder = varint::read_int(r).await?;
    Ok(SumHead {
        count,
        blength,
        s2length,
        remainder,
    })
}

/// Write block signatures to the wire.
pub async fn write_sums<W: AsyncWrite + Unpin>(
    w: &mut W,
    sums: &SumStruct,
) -> Result<()> {
    write_sum_head(w, &sums.head).await?;
    for entry in &sums.sums {
        w.write_all(&entry.sum1.to_le_bytes())
            .await
            .map_err(ProtocolError::Io)?;
        w.write_all(&entry.sum2)
            .await
            .map_err(ProtocolError::Io)?;
    }
    Ok(())
}

/// Maximum block count from the wire (16M blocks = ~16 TiB at 1 MiB/block).
const MAX_BLOCK_COUNT: i32 = 16 * 1024 * 1024;

/// Read block signatures from the wire.
pub async fn read_sums<R: AsyncRead + Unpin>(r: &mut R) -> Result<SumStruct> {
    let head = read_sum_head(r).await?;

    // Validate wire values to prevent OOM from crafted input.
    if head.count < 0 || head.count > MAX_BLOCK_COUNT {
        return Err(ProtocolError::WireValueOutOfRange {
            field: "sum_count",
            value: head.count as i64,
            max: MAX_BLOCK_COUNT as i64,
        });
    }
    if head.s2length < 0 || head.s2length > 64 {
        return Err(ProtocolError::WireValueOutOfRange {
            field: "sum_s2length",
            value: head.s2length as i64,
            max: 64,
        });
    }

    let mut sums = Vec::with_capacity(head.count as usize);

    for _ in 0..head.count {
        let mut sum1_buf = [0u8; 4];
        r.read_exact(&mut sum1_buf)
            .await
            .map_err(ProtocolError::Io)?;
        let sum1 = u32::from_le_bytes(sum1_buf);

        let mut sum2 = vec![0u8; head.s2length as usize];
        r.read_exact(&mut sum2)
            .await
            .map_err(ProtocolError::Io)?;

        sums.push(SumEntry { sum1, sum2 });
    }

    Ok(SumStruct { head, sums })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_compute_block_length_small() {
        let bl = compute_block_length(1000);
        assert!(bl >= 700);
        assert_eq!(bl % 8, 0);
    }

    #[test]
    fn test_compute_block_length_large() {
        let bl = compute_block_length(1_000_000_000);
        assert!(bl <= 1 << 17);
        assert_eq!(bl % 8, 0);
    }

    #[test]
    fn test_compute_block_length_zero() {
        assert_eq!(compute_block_length(0), 700);
    }

    #[test]
    fn test_compute_s2length_bounds() {
        let s2 = compute_s2length(10000, 700);
        assert!(s2 >= 2);
        assert!(s2 <= MAX_DIGEST_LEN as i32);
    }

    #[test]
    fn test_compute_signatures_empty() {
        let sums = compute_signatures(b"", 0, ChecksumType::Md5);
        assert_eq!(sums.head.count, 0);
        assert!(sums.sums.is_empty());
    }

    #[test]
    fn test_compute_signatures_basic() {
        let data = vec![0u8; 2000];
        let sums = compute_signatures(&data, 42, ChecksumType::Md5);
        assert!(sums.head.count > 0);
        assert_eq!(sums.sums.len(), sums.head.count as usize);
        for entry in &sums.sums {
            assert_eq!(entry.sum2.len(), sums.head.s2length as usize);
        }
    }

    #[tokio::test]
    async fn test_sum_head_roundtrip() {
        let head = SumHead {
            count: 10,
            blength: 700,
            s2length: 12,
            remainder: 300,
        };

        let mut buf = Vec::new();
        write_sum_head(&mut buf, &head).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_sum_head(&mut cursor).await.unwrap();
        assert_eq!(decoded, head);
    }

    #[tokio::test]
    async fn test_sums_roundtrip() {
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, 99, ChecksumType::Md5);

        let mut buf = Vec::new();
        write_sums(&mut buf, &sums).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_sums(&mut cursor).await.unwrap();

        assert_eq!(decoded.head, sums.head);
        assert_eq!(decoded.sums.len(), sums.sums.len());
        for (a, b) in decoded.sums.iter().zip(sums.sums.iter()) {
            assert_eq!(a.sum1, b.sum1);
            assert_eq!(a.sum2, b.sum2);
        }
    }

    #[tokio::test]
    async fn test_empty_sums_roundtrip() {
        let sums = SumStruct {
            head: SumHead::default(),
            sums: Vec::new(),
        };

        let mut buf = Vec::new();
        write_sums(&mut buf, &sums).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_sums(&mut cursor).await.unwrap();
        assert_eq!(decoded.head.count, 0);
        assert!(decoded.sums.is_empty());
    }
}
