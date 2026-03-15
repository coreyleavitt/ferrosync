//! Content-defined chunking (CDC) for improved delta transfer.
//!
//! This module provides two chunking strategies:
//!
//! - **Fixed**: Traditional fixed-size blocks (rsync-compatible).
//! - **FastCDC**: Content-defined chunking that produces variable-size blocks
//!   whose boundaries are determined by the data content. This means that
//!   insertions/deletions only affect nearby chunk boundaries rather than
//!   shifting all subsequent blocks.

use fastcdc::v2020::FastCDC;

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

/// Information about a single chunk produced by the chunker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkInfo {
    /// Byte offset of this chunk within the source data.
    pub offset: usize,
    /// Length of this chunk in bytes.
    pub length: usize,
}

/// Split data into chunks according to the given strategy.
///
/// Returns a list of non-overlapping, contiguous chunks that cover
/// the entire input data with no gaps.
pub fn chunk_data(data: &[u8], strategy: &ChunkingStrategy) -> Vec<ChunkInfo> {
    if data.is_empty() {
        return Vec::new();
    }

    match strategy {
        ChunkingStrategy::Fixed { block_size } => {
            let bs = *block_size;
            if bs == 0 {
                return Vec::new();
            }
            let mut chunks = Vec::new();
            let mut offset = 0;
            while offset < data.len() {
                let length = bs.min(data.len() - offset);
                chunks.push(ChunkInfo { offset, length });
                offset += length;
            }
            chunks
        }
        ChunkingStrategy::FastCDC { min, avg, max } => {
            let chunker = FastCDC::new(data, *min as u32, *avg as u32, *max as u32);
            chunker
                .map(|chunk| ChunkInfo {
                    offset: chunk.offset,
                    length: chunk.length,
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_chunks_cover_all_data() {
        let data = vec![0u8; 5000];
        let chunks = chunk_data(&data, &ChunkingStrategy::Fixed { block_size: 700 });

        // No gaps, no overlaps, covers all data.
        assert!(!chunks.is_empty());
        assert_eq!(chunks[0].offset, 0);
        for i in 1..chunks.len() {
            assert_eq!(
                chunks[i].offset,
                chunks[i - 1].offset + chunks[i - 1].length
            );
        }
        let last = chunks.last().unwrap();
        assert_eq!(last.offset + last.length, data.len());
    }

    #[test]
    fn test_fixed_chunks_exact_multiple() {
        let data = vec![0u8; 2100];
        let chunks = chunk_data(&data, &ChunkingStrategy::Fixed { block_size: 700 });
        assert_eq!(chunks.len(), 3);
        for chunk in &chunks {
            assert_eq!(chunk.length, 700);
        }
    }

    #[test]
    fn test_fixed_chunks_remainder() {
        let data = vec![0u8; 2000];
        let chunks = chunk_data(&data, &ChunkingStrategy::Fixed { block_size: 700 });
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].length, 700);
        assert_eq!(chunks[1].length, 700);
        assert_eq!(chunks[2].length, 600);
    }

    #[test]
    fn test_fixed_empty_data() {
        let chunks = chunk_data(&[], &ChunkingStrategy::Fixed { block_size: 700 });
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_cdc_chunks_cover_all_data() {
        // Use a realistic amount of data so CDC actually has something to work with.
        let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let strategy = ChunkingStrategy::default_cdc();
        let chunks = chunk_data(&data, &strategy);

        // No gaps, no overlaps.
        assert!(!chunks.is_empty());
        assert_eq!(chunks[0].offset, 0);
        for i in 1..chunks.len() {
            assert_eq!(
                chunks[i].offset,
                chunks[i - 1].offset + chunks[i - 1].length,
                "gap or overlap at chunk {i}"
            );
        }
        let last = chunks.last().unwrap();
        assert_eq!(last.offset + last.length, data.len());
    }

    #[test]
    fn test_cdc_respects_size_bounds() {
        let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let min = 2048;
        let avg = 8192;
        let max = 65536;
        let strategy = ChunkingStrategy::FastCDC { min, avg, max };
        let chunks = chunk_data(&data, &strategy);

        // All chunks except possibly the last must respect min/max bounds.
        for (i, chunk) in chunks.iter().enumerate() {
            if i < chunks.len() - 1 {
                assert!(
                    chunk.length >= min,
                    "chunk {i} length {} < min {min}",
                    chunk.length
                );
                assert!(
                    chunk.length <= max,
                    "chunk {i} length {} > max {max}",
                    chunk.length
                );
            }
        }
    }

    #[test]
    fn test_cdc_boundary_shift_on_insert() {
        // The key property of CDC: inserting data at the beginning should
        // only change the first chunk boundary, not all of them.
        //
        // We use a simple LCG to generate pseudo-random data that produces
        // enough CDC boundaries for a meaningful test. Using min=512,
        // avg=2048, max=8192 to get many chunks from 256KB of data.
        let mut rng: u64 = 0xDEAD_BEEF;
        let base_data: Vec<u8> = (0..256_000)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();

        let strategy = ChunkingStrategy::FastCDC {
            min: 512,
            avg: 2048,
            max: 8192,
        };
        let base_chunks = chunk_data(&base_data, &strategy);

        // Ensure we have a reasonable number of chunks.
        assert!(
            base_chunks.len() >= 10,
            "expected at least 10 chunks, got {}",
            base_chunks.len()
        );

        // Insert 100 bytes at the beginning.
        let mut modified = vec![42u8; 100];
        modified.extend_from_slice(&base_data);
        let mod_chunks = chunk_data(&modified, &strategy);

        // After the first few chunks (where the insertion happened),
        // boundaries should re-synchronize. Count how many chunk boundaries
        // from the base appear (shifted by 100) in the modified version.
        let base_boundaries: Vec<usize> = base_chunks.iter().map(|c| c.offset).collect();
        let mod_boundaries: Vec<usize> = mod_chunks.iter().map(|c| c.offset).collect();

        let shifted_matches = base_boundaries
            .iter()
            .filter(|&&b| mod_boundaries.contains(&(b + 100)))
            .count();

        // Most boundaries should survive (at least 50%).
        assert!(
            shifted_matches > base_boundaries.len() / 2,
            "CDC did not re-synchronize after insert: {shifted_matches}/{} boundaries matched",
            base_boundaries.len()
        );
    }

    #[test]
    fn test_fixed_matches_current_behavior() {
        // Fixed chunking should produce the same block boundaries as
        // the traditional rsync approach: blocks of block_size except
        // possibly the last one.
        let data = vec![0u8; 10_000];
        let block_size = 700;
        let chunks = chunk_data(&data, &ChunkingStrategy::Fixed { block_size });

        let expected_count = data.len().div_ceil(block_size);
        assert_eq!(chunks.len(), expected_count);

        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.offset, i * block_size);
            if i < expected_count - 1 {
                assert_eq!(chunk.length, block_size);
            } else {
                // Last chunk may be shorter.
                assert_eq!(chunk.length, data.len() - i * block_size);
            }
        }
    }

    #[test]
    fn test_cdc_empty_data() {
        let chunks = chunk_data(&[], &ChunkingStrategy::default_cdc());
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_cdc_small_data() {
        // Data smaller than min chunk size should still produce one chunk.
        let data = vec![42u8; 1000];
        let chunks = chunk_data(&data, &ChunkingStrategy::default_cdc());
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].length, 1000);
    }

    #[test]
    fn test_default_strategy_is_fixed() {
        let strategy = ChunkingStrategy::default();
        assert!(matches!(strategy, ChunkingStrategy::Fixed { .. }));
    }
}
