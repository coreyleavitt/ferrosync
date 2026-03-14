//! Zlib/deflate compression for the rsync wire protocol.
//!
//! Rsync uses raw deflate (RFC 1951) for token-level compression. The
//! compressor maintains state across tokens within a file, using
//! `Z_SYNC_FLUSH` between tokens to allow the decompressor to produce
//! output for each token independently.
//!
//! Two modes are supported:
//! - **zlib**: standard deflate with per-token sync flush.
//! - **zlibx**: same algorithm, but uses a clean deflate context per file
//!   (rsync 3.1.1+).

use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::{Compression, FlushDecompress, Status};
use std::io::Write;

use crate::error::ProtocolError;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Compress a block of data using raw deflate.
pub fn compress_block(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    encoder
        .write_all(data)
        .map_err(ProtocolError::Io)?;
    encoder.finish().map_err(ProtocolError::Io)
}

/// Decompress a raw deflate block.
pub fn decompress_block(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(Vec::new());
    decoder
        .write_all(compressed)
        .map_err(ProtocolError::Io)?;
    decoder.finish().map_err(ProtocolError::Io)
}

/// Streaming compressor that maintains deflate state across multiple
/// `compress()` calls within a single file transfer. Uses `Z_SYNC_FLUSH`
/// between chunks so the decompressor can produce output incrementally.
pub struct Compressor {
    inner: flate2::Compress,
}

impl Compressor {
    pub fn new(level: u32) -> Self {
        Self {
            inner: flate2::Compress::new(Compression::new(level), false),
        }
    }

    /// Compress `data`, returning the compressed bytes. Uses `Z_SYNC_FLUSH`
    /// so the decompressor can decode without waiting for more input.
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let max_out = data.len() + data.len() / 100 + 100;
        let mut output = vec![0u8; max_out];

        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        loop {
            let in_consumed = (self.inner.total_in() - before_in) as usize;
            let out_produced = (self.inner.total_out() - before_out) as usize;

            if output.len() - out_produced < 64 {
                output.resize(output.len() * 2, 0);
            }

            let status = self
                .inner
                .compress(
                    &data[in_consumed..],
                    &mut output[out_produced..],
                    flate2::FlushCompress::Sync,
                )
                .map_err(|e| ProtocolError::Io(std::io::Error::other(e)))?;

            match status {
                Status::Ok | Status::BufError => {
                    if in_consumed >= data.len() {
                        break;
                    }
                }
                Status::StreamEnd => break,
            }
        }

        let total_out = (self.inner.total_out() - before_out) as usize;
        output.truncate(total_out);
        Ok(output)
    }

    /// Reset the compressor for a new file (zlibx mode).
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

/// Streaming decompressor paired with [`Compressor`].
pub struct Decompressor {
    inner: flate2::Decompress,
}

impl Decompressor {
    pub fn new() -> Self {
        Self {
            inner: flate2::Decompress::new(false),
        }
    }

    /// Decompress data produced by [`Compressor::compress`].
    pub fn decompress(&mut self, compressed: &[u8], expected_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; expected_len + expected_len / 10 + 64];

        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        loop {
            let in_consumed = (self.inner.total_in() - before_in) as usize;
            let out_produced = (self.inner.total_out() - before_out) as usize;

            if output.len() - out_produced < 64 {
                output.resize(output.len() * 2, 0);
            }

            let status = self
                .inner
                .decompress(
                    &compressed[in_consumed..],
                    &mut output[out_produced..],
                    FlushDecompress::Sync,
                )
                .map_err(|e| ProtocolError::Io(std::io::Error::other(e)))?;

            let total_out = (self.inner.total_out() - before_out) as usize;

            match status {
                Status::Ok | Status::BufError => {
                    if in_consumed >= compressed.len() || total_out >= expected_len {
                        break;
                    }
                }
                Status::StreamEnd => break,
            }
        }

        let total_out = (self.inner.total_out() - before_out) as usize;
        output.truncate(total_out);
        Ok(output)
    }

    /// Reset the decompressor for a new file (zlibx mode).
    pub fn reset(&mut self) {
        self.inner.reset(false);
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_roundtrip() {
        let data = b"Hello, world! This is test data for compression.";
        let compressed = compress_block(data, 6).unwrap();
        assert!(compressed.len() < data.len() + 20); // compressed shouldn't be massively larger
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_block_empty() {
        let compressed = compress_block(b"", 6).unwrap();
        let decompressed = decompress_block(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_block_large_data() {
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_block(&data, 6).unwrap();
        // Patterned data should compress well.
        assert!(compressed.len() < data.len());
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let chunks = [
            b"first chunk of data".as_slice(),
            b"second chunk with different content".as_slice(),
            b"third and final chunk".as_slice(),
        ];

        for chunk in &chunks {
            let compressed = compressor.compress(chunk).unwrap();
            let decompressed = decompressor.decompress(&compressed, chunk.len()).unwrap();
            assert_eq!(decompressed, *chunk);
        }
    }

    #[test]
    fn test_streaming_reset() {
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let data = b"some data to compress";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);

        // Reset for a new file (zlibx mode).
        compressor.reset();
        decompressor.reset();

        let data2 = b"different file data";
        let compressed2 = compressor.compress(data2).unwrap();
        let decompressed2 = decompressor.decompress(&compressed2, data2.len()).unwrap();
        assert_eq!(decompressed2, data2);
    }

    #[test]
    fn test_compression_levels() {
        let data: Vec<u8> = vec![0xAA; 10_000];
        for level in 1..=9 {
            let compressed = compress_block(&data, level).unwrap();
            let decompressed = decompress_block(&compressed).unwrap();
            assert_eq!(decompressed, data, "failed at level {level}");
        }
    }

    #[test]
    fn test_highly_compressible() {
        let data = vec![0u8; 50_000];
        let compressed = compress_block(&data, 6).unwrap();
        // All zeros should compress extremely well.
        assert!(compressed.len() < 100, "compressed {} bytes to {} bytes", data.len(), compressed.len());
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_incompressible_data() {
        // Random-looking data shouldn't crash, even if it doesn't compress well.
        let data: Vec<u8> = (0..5000).map(|i| {
            ((i * 7919 + 104729) % 256) as u8
        }).collect();
        let compressed = compress_block(&data, 6).unwrap();
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
