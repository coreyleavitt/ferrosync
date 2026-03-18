//! Block matching algorithm for delta transfer.
//!
//! Given a set of block signatures from the basis file and the source file
//! data, the matcher finds matching blocks and emits a sequence of match
//! and literal-data operations.
//!
//! The algorithm:
//! 1. Build a hash table from the rolling checksums of the basis blocks.
//! 2. Slide a window over the source data, computing the rolling checksum.
//! 3. On a hash table hit, verify with the strong checksum.
//! 4. Emit `BlockMatch` for verified matches, `Data` for unmatched regions.

use std::collections::HashMap;

use super::checksum::{self, RollingChecksum};
use super::sum::SumStruct;
use crate::protocol::handshake::ChecksumType;

/// An operation emitted by the block matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOp<'a> {
    /// Literal data (bytes from source that don't match any basis block).
    Data(&'a [u8]),
    /// Matched block (index into the basis file's block signatures).
    BlockMatch(i32),
}

/// Find matching blocks between source data and basis file signatures.
///
/// Returns a sequence of `MatchOp` values representing the delta between
/// the basis (described by `sums`) and the `source` data.
///
/// - `char_offset`: rolling checksum character offset (0 for protocol >= 30,
///   31 for older protocols).
/// - `proper_seed_order`: if true, seed is hashed before data in the strong
///   checksum (protocol >= 30 with `CF_CHKSUM_SEED_FIX`).
pub fn match_blocks<'a>(
    source: &'a [u8],
    sums: &SumStruct,
    seed: i32,
    checksum_type: ChecksumType,
    char_offset: u32,
    proper_seed_order: bool,
) -> Vec<MatchOp<'a>> {
    let mut ops = Vec::new();

    if source.is_empty() {
        return ops;
    }

    if sums.head.count <= 0 || sums.head.blength <= 0 {
        ops.push(MatchOp::Data(source));
        return ops;
    }

    let blength = sums.head.blength as usize;
    let s2length = sums.head.s2length as usize;

    let hash_table = build_hash_table(&sums.sums);
    let mut rolling = RollingChecksum::new(char_offset);
    let mut pos: usize = 0;
    let mut literal_start: usize = 0;

    // Need at least blength bytes for a full block scan.
    if source.len() < blength {
        ops.push(MatchOp::Data(source));
        return ops;
    }

    // Compute initial window checksum.
    rolling.compute(&source[..blength]);

    loop {
        if pos + blength > source.len() {
            break;
        }

        let digest = rolling.digest();
        let mut matched = false;

        if let Some(candidates) = hash_table.get(&digest) {
            let window = &source[pos..pos + blength];
            let strong = checksum::checksum2(window, seed, checksum_type, proper_seed_order);
            let strong_truncated = &strong[..s2length.min(strong.len())];

            for &idx in candidates {
                if sums.sums[idx].sum2 == strong_truncated {
                    // Flush pending literal data.
                    if literal_start < pos {
                        ops.push(MatchOp::Data(&source[literal_start..pos]));
                    }
                    ops.push(MatchOp::BlockMatch(idx as i32));
                    pos += blength;
                    literal_start = pos;
                    matched = true;

                    // Recompute rolling checksum for next window.
                    if pos + blength <= source.len() {
                        rolling.compute(&source[pos..pos + blength]);
                    }
                    break;
                }
            }
        }

        if !matched {
            let old_byte = source[pos];
            pos += 1;
            if pos + blength <= source.len() {
                rolling.roll(old_byte, source[pos + blength - 1]);
            }
        }
    }

    // Flush remaining literal data.
    if literal_start < source.len() {
        ops.push(MatchOp::Data(&source[literal_start..]));
    }

    ops
}

/// Build a hash table mapping rolling checksums to block indices.
fn build_hash_table(sums: &[super::sum::SumEntry]) -> HashMap<u32, Vec<usize>> {
    let mut table: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, entry) in sums.iter().enumerate() {
        table.entry(entry.sum1).or_default().push(i);
    }
    table
}

/// Apply a sequence of match operations to reconstruct a file from the
/// basis data.
pub fn apply_ops(basis: &[u8], ops: &[MatchOp<'_>], blength: usize, remainder: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let block_count = if blength > 0 && !basis.is_empty() {
        basis.len().div_ceil(blength)
    } else {
        0
    };

    for op in ops {
        match op {
            MatchOp::Data(data) => {
                output.extend_from_slice(data);
            }
            MatchOp::BlockMatch(idx) => {
                let idx = *idx as usize;
                let offset = idx * blength;
                let len = if block_count > 0
                    && idx == block_count - 1
                    && remainder > 0
                    && remainder < blength
                {
                    remainder
                } else {
                    blength
                };
                let end = (offset + len).min(basis.len());
                if offset < basis.len() {
                    output.extend_from_slice(&basis[offset..end]);
                }
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::checksum::CHAR_OFFSET_V30;
    use crate::delta::sum::compute_signatures;

    #[test]
    fn test_identical_files() {
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(&data, &sums, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        // All blocks should match.
        let match_count = ops
            .iter()
            .filter(|op| matches!(op, MatchOp::BlockMatch(_)))
            .count();
        assert!(
            match_count > 0,
            "should have block matches for identical data"
        );

        // No (or minimal) literal data.
        let literal_bytes: usize = ops
            .iter()
            .filter_map(|op| match op {
                MatchOp::Data(d) => Some(d.len()),
                _ => None,
            })
            .sum();
        assert!(
            literal_bytes < sums.head.blength as usize,
            "minimal literal data expected"
        );
    }

    #[test]
    fn test_completely_different_files() {
        let basis = vec![0u8; 5000];
        let source = vec![0xFFu8; 5000];
        let sums = compute_signatures(&basis, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(&source, &sums, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        // No blocks should match -- all literal.
        let match_count = ops
            .iter()
            .filter(|op| matches!(op, MatchOp::BlockMatch(_)))
            .count();
        assert_eq!(match_count, 0);

        // All data should be literal.
        let literal_bytes: usize = ops
            .iter()
            .filter_map(|op| match op {
                MatchOp::Data(d) => Some(d.len()),
                _ => None,
            })
            .sum();
        assert_eq!(literal_bytes, source.len());
    }

    #[test]
    fn test_apply_ops_identical() {
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(&data, &sums, 99, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        let reconstructed = apply_ops(
            &data,
            &ops,
            sums.head.blength as usize,
            sums.head.remainder as usize,
        );
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_apply_ops_modified() {
        // Start with basis, modify a few bytes, verify reconstruction.
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        // Modify bytes in the middle.
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let sums = compute_signatures(&basis, 42, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(&source, &sums, 42, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        let reconstructed = apply_ops(
            &basis,
            &ops,
            sums.head.blength as usize,
            sums.head.remainder as usize,
        );
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn test_empty_source() {
        let basis = vec![0u8; 1000];
        let sums = compute_signatures(&basis, 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(b"", &sums, 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_empty_basis() {
        let sums = compute_signatures(b"", 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let ops = match_blocks(b"hello", &sums, 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        // Should be all literal.
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], MatchOp::Data(b"hello"));
    }

    #[test]
    fn test_source_smaller_than_block() {
        let basis = vec![0u8; 5000];
        let sums = compute_signatures(&basis, 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        // Source is smaller than one block.
        let ops = match_blocks(b"tiny", &sums, 0, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], MatchOp::Data(b"tiny"));
    }

    #[test]
    fn test_apply_ops_all_literal() {
        let ops = vec![MatchOp::Data(b"all new data")];
        let result = apply_ops(b"", &ops, 700, 0);
        assert_eq!(result, b"all new data");
    }

    #[test]
    fn test_inserted_data_between_blocks() {
        // Create basis, then source with data inserted between blocks.
        let mut basis = Vec::new();
        for i in 0..10 {
            basis.extend(vec![i as u8; 700]);
        }
        let sums = compute_signatures(&basis, 55, ChecksumType::Md5, CHAR_OFFSET_V30, true);

        // Source: first block + "INSERTED" + second block + rest.
        let mut source = Vec::new();
        source.extend(&basis[..700]);
        source.extend(b"INSERTED");
        source.extend(&basis[700..]);

        let ops = match_blocks(&source, &sums, 55, ChecksumType::Md5, CHAR_OFFSET_V30, true);
        let reconstructed = apply_ops(
            &basis,
            &ops,
            sums.head.blength as usize,
            sums.head.remainder as usize,
        );
        assert_eq!(reconstructed, source);
    }
}
