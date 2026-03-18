//! Block matching algorithm for delta transfer.
//!
//! Given a set of block signatures from the basis file and the source file
//! data, the matcher finds matching blocks and emits a sequence of
//! algorithm-agnostic diff operations.
//!
//! The algorithm:
//! 1. Build a hash table from the rolling checksums of the basis blocks.
//! 2. Slide a window over the source data, computing the rolling checksum.
//! 3. On a hash table hit, verify with the strong checksum.
//! 4. Emit `Copy(BasisRef)` for verified matches, `Literal` for unmatched regions.

use std::collections::HashMap;
use std::io::Read;

use super::checksum::{self, RollingChecksum};
use super::ops::{BasisRef, DiffOp, OwnedDiffOp};
use super::sum::SumStruct;
use crate::delta::ProtocolContext;

/// Compute the byte length of a matched block, accounting for a shorter
/// last block when the basis size is not a multiple of the block length.
fn block_byte_length(idx: usize, blength: usize, block_count: usize, remainder: usize) -> u32 {
    if block_count > 0 && idx == block_count - 1 && remainder > 0 && remainder < blength {
        remainder as u32
    } else {
        blength as u32
    }
}

/// Find matching blocks between source data and basis file signatures.
///
/// Returns a sequence of [`DiffOp`] values representing the delta between
/// the basis (described by `sums`) and the `source` data.
pub fn match_blocks<'a>(
    source: &'a [u8],
    sums: &SumStruct,
    ctx: &ProtocolContext,
) -> Vec<DiffOp<'a>> {
    let mut ops = Vec::new();

    if source.is_empty() {
        return ops;
    }

    if sums.head.count <= 0 || sums.head.blength <= 0 {
        ops.push(DiffOp::Literal(source));
        return ops;
    }

    let blength = sums.head.blength as usize;
    let s2length = sums.head.s2length as usize;
    let block_count = sums.head.count as usize;
    let remainder = sums.head.remainder as usize;

    let hash_table = build_hash_table(&sums.sums);
    let mut rolling = RollingChecksum::new(ctx.char_offset);
    let mut pos: usize = 0;
    let mut literal_start: usize = 0;

    // Need at least blength bytes for a full block scan.
    if source.len() < blength {
        ops.push(DiffOp::Literal(source));
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
            let strong = checksum::checksum2(window, ctx);
            let strong_truncated = &strong[..s2length.min(strong.len())];

            for &idx in candidates {
                if sums.sums[idx].sum2 == strong_truncated {
                    // Flush pending literal data.
                    if literal_start < pos {
                        ops.push(DiffOp::Literal(&source[literal_start..pos]));
                    }
                    let block_offset = (idx as u64) * (blength as u64);
                    let block_len = block_byte_length(idx, blength, block_count, remainder);
                    ops.push(DiffOp::Copy(BasisRef {
                        offset: block_offset,
                        length: block_len,
                    }));
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
        ops.push(DiffOp::Literal(&source[literal_start..]));
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

/// Default chunk size for streaming matching (256 KiB).
pub const DEFAULT_STREAM_CHUNK: usize = 256 * 1024;

/// Streaming block matcher that processes source data incrementally.
///
/// Unlike [`match_blocks`] which requires the entire source in memory,
/// `StreamingMatcher` reads from a [`Read`] source in chunks, emitting
/// diff operations as they are discovered. The rolling checksum state
/// carries across chunk boundaries, producing identical results to the
/// batch algorithm.
pub struct StreamingMatcher {
    // Configuration (immutable after construction).
    hash_table: HashMap<u32, Vec<usize>>,
    sum2_entries: Vec<Vec<u8>>,
    blength: usize,
    s2length: usize,
    block_count: usize,
    remainder: usize,
    ctx: ProtocolContext,
    chunk_size: usize,
    no_sums: bool,

    // Mutable state across process_chunk calls.
    rolling: RollingChecksum,
    buf: Vec<u8>,
    buf_len: usize,
    pos: usize,
    literal_start: usize,
    initialized: bool,
    exhausted: bool,
    need_rolling_init: bool,
}

impl StreamingMatcher {
    /// Create a new streaming matcher from basis block signatures.
    ///
    /// - `sums`: block signatures from the basis file.
    /// - `ctx`: protocol context with checksum parameters.
    /// - `chunk_size`: number of fresh bytes to read per `process_chunk` call.
    pub fn new(sums: &SumStruct, ctx: &ProtocolContext, chunk_size: usize) -> Self {
        let no_sums = sums.head.count <= 0 || sums.head.blength <= 0;
        let blength = if no_sums {
            0
        } else {
            sums.head.blength as usize
        };
        let s2length = sums.head.s2length as usize;
        let block_count = sums.head.count as usize;
        let remainder = sums.head.remainder as usize;
        let hash_table = build_hash_table(&sums.sums);
        let sum2_entries: Vec<Vec<u8>> = sums.sums.iter().map(|e| e.sum2.clone()).collect();

        // Buffer must hold at least blength + chunk_size bytes so we can
        // keep the overlap window and read fresh data.
        let buf_capacity = blength + chunk_size;

        Self {
            hash_table,
            sum2_entries,
            blength,
            s2length,
            block_count,
            remainder,
            ctx: *ctx,
            chunk_size,
            no_sums,
            rolling: RollingChecksum::new(ctx.char_offset),
            buf: vec![0u8; buf_capacity],
            buf_len: 0,
            pos: 0,
            literal_start: 0,
            initialized: false,
            exhausted: false,
            need_rolling_init: true,
        }
    }

    /// Process the next chunk of source data.
    ///
    /// Reads up to `chunk_size` fresh bytes from `reader`, feeds them into
    /// `checksum` for whole-file verification, and returns any diff
    /// operations discovered in this chunk.
    ///
    /// Returns `(ops, done)` where `done` is true when the reader is
    /// exhausted and all remaining data has been flushed.
    pub fn process_chunk(
        &mut self,
        reader: &mut dyn Read,
        checksum: &mut checksum::IncrementalChecksum,
    ) -> std::io::Result<(Vec<OwnedDiffOp>, bool)> {
        let mut ops = Vec::new();

        // Step 1: Fill the buffer.
        if !self.initialized {
            // First call: read up to chunk_size bytes starting at offset 0.
            let bytes_read = read_fill(reader, &mut self.buf[..self.chunk_size])?;
            self.buf_len = bytes_read;
            if bytes_read > 0 {
                checksum.update(&self.buf[..bytes_read]);
            }
            if bytes_read < self.chunk_size {
                self.exhausted = true;
            }
            self.initialized = true;
        } else if self.no_sums || self.blength == 0 {
            // No sums: just read the next chunk of literal data.
            let bytes_read = read_fill(reader, &mut self.buf[..self.chunk_size])?;
            self.buf_len = bytes_read;
            if bytes_read > 0 {
                checksum.update(&self.buf[..bytes_read]);
            }
            if bytes_read < self.chunk_size {
                self.exhausted = true;
            }
        } else {
            // Subsequent calls: shift the overlap and read fresh data.
            let shift_by = self.buf_len.saturating_sub(self.blength);

            // Flush any literal data that will be discarded by the shift.
            if self.literal_start < shift_by {
                ops.push(OwnedDiffOp::Literal(
                    self.buf[self.literal_start..shift_by].to_vec(),
                ));
                self.literal_start = shift_by;
            }

            // Shift the overlap window to the front of the buffer.
            self.buf.copy_within(shift_by..self.buf_len, 0);
            self.pos -= shift_by;
            self.literal_start -= shift_by;

            // Read fresh data after the overlap.
            let bytes_read = read_fill(
                reader,
                &mut self.buf[self.blength..self.blength + self.chunk_size],
            )?;
            if bytes_read > 0 {
                checksum.update(&self.buf[self.blength..self.blength + bytes_read]);
            }
            self.buf_len = self.blength + bytes_read;
            if bytes_read < self.chunk_size {
                self.exhausted = true;
            }
        }

        // Step 2: Early returns.
        if self.buf_len == 0 {
            return Ok((ops, true));
        }

        if self.no_sums {
            if self.buf_len > 0 {
                ops.push(OwnedDiffOp::Literal(self.buf[..self.buf_len].to_vec()));
            }
            return Ok((ops, self.exhausted));
        }

        if self.buf_len < self.blength {
            ops.push(OwnedDiffOp::Literal(self.buf[..self.buf_len].to_vec()));
            return Ok((ops, true));
        }

        // Step 3: Initialize rolling checksum on the very first window.
        // For the first chunk we always need this. For subsequent chunks,
        // the rolling state carries over -- unless pos landed at 0 after
        // a match that exactly consumed the overlap, in which case
        // need_rolling_init was set.
        if self.need_rolling_init {
            self.rolling
                .compute(&self.buf[self.pos..self.pos + self.blength]);
            self.need_rolling_init = false;
        }

        // Step 4: Match loop.
        while self.pos + self.blength <= self.buf_len {
            let digest = self.rolling.digest();
            let mut matched = false;

            if let Some(candidates) = self.hash_table.get(&digest) {
                let window = &self.buf[self.pos..self.pos + self.blength];
                let strong = checksum::checksum2(window, &self.ctx);
                let strong_truncated = &strong[..self.s2length.min(strong.len())];

                for &idx in candidates {
                    if self.sum2_entries[idx] == strong_truncated {
                        // Flush pending literal data.
                        if self.literal_start < self.pos {
                            ops.push(OwnedDiffOp::Literal(
                                self.buf[self.literal_start..self.pos].to_vec(),
                            ));
                        }
                        let block_offset = (idx as u64) * (self.blength as u64);
                        let block_len =
                            block_byte_length(idx, self.blength, self.block_count, self.remainder);
                        ops.push(OwnedDiffOp::Copy(BasisRef {
                            offset: block_offset,
                            length: block_len,
                        }));
                        self.pos += self.blength;
                        self.literal_start = self.pos;
                        matched = true;

                        // Recompute rolling checksum for the next window.
                        if self.pos + self.blength <= self.buf_len {
                            self.rolling
                                .compute(&self.buf[self.pos..self.pos + self.blength]);
                        } else {
                            // Next chunk will need to initialize the rolling
                            // checksum after the buffer is refilled.
                            self.need_rolling_init = true;
                        }
                        break;
                    }
                }
            }

            if !matched {
                let old_byte = self.buf[self.pos];
                self.pos += 1;
                if self.pos + self.blength <= self.buf_len {
                    self.rolling
                        .roll(old_byte, self.buf[self.pos + self.blength - 1]);
                }
            }
        }

        // Step 5: Final flush or continue.
        if self.exhausted {
            if self.literal_start < self.buf_len {
                ops.push(OwnedDiffOp::Literal(
                    self.buf[self.literal_start..self.buf_len].to_vec(),
                ));
            }
            Ok((ops, true))
        } else {
            Ok((ops, false))
        }
    }
}

/// Read as many bytes as possible to fill the buffer, handling short reads.
fn read_fill(reader: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::ops::{apply_diffops, apply_owned_diffops};
    use crate::delta::sum::compute_signatures;
    use crate::delta::ProtocolContext;
    use crate::protocol::handshake::ChecksumType;

    fn ctx(seed: i32, ct: ChecksumType) -> ProtocolContext {
        ProtocolContext::test_default(seed, ct)
    }

    #[test]
    fn test_identical_files() {
        let c = ctx(99, ChecksumType::Md5);
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, &c);
        let ops = match_blocks(&data, &sums, &c);

        let match_count = ops
            .iter()
            .filter(|op| matches!(op, DiffOp::Copy(_)))
            .count();
        assert!(
            match_count > 0,
            "should have block matches for identical data"
        );

        let literal_bytes: usize = ops
            .iter()
            .filter_map(|op| match op {
                DiffOp::Literal(d) => Some(d.len()),
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
        let c = ctx(99, ChecksumType::Md5);
        let basis = vec![0u8; 5000];
        let source = vec![0xFFu8; 5000];
        let sums = compute_signatures(&basis, &c);
        let ops = match_blocks(&source, &sums, &c);

        let match_count = ops
            .iter()
            .filter(|op| matches!(op, DiffOp::Copy(_)))
            .count();
        assert_eq!(match_count, 0);

        let literal_bytes: usize = ops
            .iter()
            .filter_map(|op| match op {
                DiffOp::Literal(d) => Some(d.len()),
                _ => None,
            })
            .sum();
        assert_eq!(literal_bytes, source.len());
    }

    #[test]
    fn test_apply_ops_identical() {
        let c = ctx(99, ChecksumType::Md5);
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, &c);
        let ops = match_blocks(&data, &sums, &c);

        let reconstructed = apply_diffops(&data, &ops);
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_apply_ops_modified() {
        let c = ctx(42, ChecksumType::Md5);
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let sums = compute_signatures(&basis, &c);
        let ops = match_blocks(&source, &sums, &c);

        let reconstructed = apply_diffops(&basis, &ops);
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn test_empty_source() {
        let c = ctx(0, ChecksumType::Md5);
        let basis = vec![0u8; 1000];
        let sums = compute_signatures(&basis, &c);
        let ops = match_blocks(b"", &sums, &c);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_empty_basis() {
        let c = ctx(0, ChecksumType::Md5);
        let sums = compute_signatures(b"", &c);
        let ops = match_blocks(b"hello", &sums, &c);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], DiffOp::Literal(b"hello"));
    }

    #[test]
    fn test_source_smaller_than_block() {
        let c = ctx(0, ChecksumType::Md5);
        let basis = vec![0u8; 5000];
        let sums = compute_signatures(&basis, &c);
        let ops = match_blocks(b"tiny", &sums, &c);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], DiffOp::Literal(b"tiny"));
    }

    #[test]
    fn test_apply_ops_all_literal() {
        let ops = vec![DiffOp::Literal(b"all new data")];
        let result = apply_diffops(b"", &ops);
        assert_eq!(result, b"all new data");
    }

    #[test]
    fn test_inserted_data_between_blocks() {
        let c = ctx(55, ChecksumType::Md5);
        let mut basis = Vec::new();
        for i in 0..10 {
            basis.extend(vec![i as u8; 700]);
        }
        let sums = compute_signatures(&basis, &c);

        let mut source = Vec::new();
        source.extend(&basis[..700]);
        source.extend(b"INSERTED");
        source.extend(&basis[700..]);

        let ops = match_blocks(&source, &sums, &c);
        let reconstructed = apply_diffops(&basis, &ops);
        assert_eq!(reconstructed, source);
    }

    // -----------------------------------------------------------------------
    // StreamingMatcher tests
    // -----------------------------------------------------------------------

    fn streaming_match_all(
        source: &[u8],
        sums: &super::super::sum::SumStruct,
        c: &ProtocolContext,
        chunk_size: usize,
    ) -> Vec<OwnedDiffOp> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(source);
        let mut matcher = StreamingMatcher::new(sums, c, chunk_size);
        let mut inc = checksum::IncrementalChecksum::new(c.checksum_type);
        let mut all_ops = Vec::new();
        loop {
            let (ops, done) = matcher.process_chunk(&mut cursor, &mut inc).unwrap();
            all_ops.extend(ops);
            if done {
                break;
            }
        }
        all_ops
    }

    #[test]
    fn test_streaming_matches_batch_identical() {
        let c = ctx(99, ChecksumType::Md5);
        let data = vec![42u8; 5000];
        let sums = compute_signatures(&data, &c);
        let ops = streaming_match_all(&data, &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&data, &ops);
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_streaming_matches_batch_different() {
        let c = ctx(99, ChecksumType::Md5);
        let basis = vec![0u8; 5000];
        let source = vec![0xFFu8; 5000];
        let sums = compute_signatures(&basis, &c);
        let ops = streaming_match_all(&source, &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&basis, &ops);
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn test_streaming_matches_batch_modified() {
        let c = ctx(42, ChecksumType::Md5);
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let sums = compute_signatures(&basis, &c);
        let ops = streaming_match_all(&source, &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&basis, &ops);
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn test_streaming_empty_source() {
        let c = ctx(0, ChecksumType::Md5);
        let basis = vec![0u8; 1000];
        let sums = compute_signatures(&basis, &c);
        let ops = streaming_match_all(b"", &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&basis, &ops);
        assert_eq!(reconstructed, b"");
    }

    #[test]
    fn test_streaming_source_smaller_than_block() {
        let c = ctx(0, ChecksumType::Md5);
        let basis = vec![0u8; 5000];
        let sums = compute_signatures(&basis, &c);
        let ops = streaming_match_all(b"tiny", &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&basis, &ops);
        assert_eq!(reconstructed, b"tiny");
    }

    #[test]
    fn test_streaming_no_basis() {
        let c = ctx(0, ChecksumType::Md5);
        let sums = compute_signatures(b"", &c);
        let ops = streaming_match_all(b"hello", &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(b"", &ops);
        assert_eq!(reconstructed, b"hello");
    }

    #[test]
    fn test_streaming_various_chunk_sizes() {
        let c = ctx(42, ChecksumType::Md5);
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let sums = compute_signatures(&basis, &c);
        let blength = sums.head.blength as usize;

        for chunk_size in [1024, blength + 1, 256 * 1024] {
            let ops = streaming_match_all(&source, &sums, &c, chunk_size);
            let reconstructed = apply_owned_diffops(&basis, &ops);
            assert_eq!(
                reconstructed, source,
                "failed with chunk_size={}",
                chunk_size
            );
        }
    }

    #[test]
    fn test_streaming_inserted_data() {
        let c = ctx(55, ChecksumType::Md5);
        let mut basis = Vec::new();
        for i in 0..10 {
            basis.extend(vec![i as u8; 700]);
        }
        let sums = compute_signatures(&basis, &c);

        let mut source = Vec::new();
        source.extend(&basis[..700]);
        source.extend(b"INSERTED");
        source.extend(&basis[700..]);

        let ops = streaming_match_all(&source, &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(&basis, &ops);
        assert_eq!(reconstructed, source);
    }

    #[test]
    fn test_streaming_no_basis_large_file() {
        // Regression: streaming with no basis (no_sums=true) must read the
        // entire source, not just the first chunk.
        let c = ctx(0, ChecksumType::Md5);
        let source: Vec<u8> = (0..DEFAULT_STREAM_CHUNK * 3 + 1000)
            .map(|i| (i % 251) as u8)
            .collect();
        let sums = compute_signatures(b"", &c);
        let ops = streaming_match_all(&source, &sums, &c, DEFAULT_STREAM_CHUNK);
        let reconstructed = apply_owned_diffops(b"", &ops);
        assert_eq!(reconstructed.len(), source.len());
        assert_eq!(reconstructed, source);
    }
}
