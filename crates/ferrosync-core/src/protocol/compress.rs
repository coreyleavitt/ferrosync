//! Compression for the rsync wire protocol.
//!
//! Supports three backends:
//! - **zlib/zlibx**: raw deflate (RFC 1951) via `flate2`.
//! - **zstd**: Zstandard streaming compression via the `zstd` crate.
//! - **lz4**: LZ4 block compression via `lz4_flex`.
//!
//! The `Compressor` and `Decompressor` types use enum dispatch to select the
//! backend at runtime, keeping a single API surface for the rest of the crate.

use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::{Compression, FlushDecompress, Status};
use std::io::Write;
use zstd::stream::raw::Operation;

use crate::error::ProtocolError;
use crate::protocol::handshake::CompressType;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// One-shot block compression (zlib only, kept for backward compat)
// ---------------------------------------------------------------------------

/// Compress a block of data using raw deflate.
pub fn compress_block(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).map_err(ProtocolError::from)?;
    encoder.finish().map_err(ProtocolError::from)
}

/// Decompress a raw deflate block.
pub fn decompress_block(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(Vec::new());
    decoder.write_all(compressed).map_err(ProtocolError::from)?;
    decoder.finish().map_err(ProtocolError::from)
}

// ---------------------------------------------------------------------------
// Zlib (deflate) streaming backend
// ---------------------------------------------------------------------------

struct ZlibCompressor {
    inner: flate2::Compress,
}

impl ZlibCompressor {
    fn new(level: u32) -> Self {
        Self {
            inner: flate2::Compress::new(Compression::new(level), false),
        }
    }

    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
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
                .map_err(|e| ProtocolError::Io(std::sync::Arc::new(std::io::Error::other(e))))?;

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

    fn reset(&mut self) {
        self.inner.reset();
    }
}

struct ZlibDecompressor {
    inner: flate2::Decompress,
}

impl ZlibDecompressor {
    fn new() -> Self {
        Self {
            inner: flate2::Decompress::new(false),
        }
    }

    fn decompress(&mut self, compressed: &[u8], expected_len: usize) -> Result<Vec<u8>> {
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
                .map_err(|e| ProtocolError::Io(std::sync::Arc::new(std::io::Error::other(e))))?;

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

    fn reset(&mut self) {
        self.inner.reset(false);
    }
}

// ---------------------------------------------------------------------------
// Zstd streaming backend
// ---------------------------------------------------------------------------

struct ZstdCompressor {
    cctx: zstd::stream::raw::Encoder<'static>,
}

impl ZstdCompressor {
    fn new(level: i32) -> Result<Self> {
        let cctx = zstd::stream::raw::Encoder::new(level).map_err(ProtocolError::from)?;
        Ok(Self { cctx })
    }

    fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(data.len() + 128);
        let mut in_buffer = zstd::stream::raw::InBuffer::around(data);

        // Feed all input data.
        loop {
            let mut out_buf = vec![0u8; data.len() + 256];
            let mut out_buffer = zstd::stream::raw::OutBuffer::around(&mut out_buf);

            self.cctx
                .run(&mut in_buffer, &mut out_buffer)
                .map_err(ProtocolError::from)?;

            let pos = out_buffer.pos();
            output.extend_from_slice(&out_buf[..pos]);

            if in_buffer.pos() >= data.len() {
                break;
            }
        }

        // Flush to ensure decompressor can decode without more input.
        loop {
            let mut out_buf = vec![0u8; 256];
            let mut out_buffer = zstd::stream::raw::OutBuffer::around(&mut out_buf);

            let remaining = self
                .cctx
                .flush(&mut out_buffer)
                .map_err(ProtocolError::from)?;

            let pos = out_buffer.pos();
            output.extend_from_slice(&out_buf[..pos]);

            if remaining == 0 {
                break;
            }
        }

        Ok(output)
    }

    fn reset(&mut self) -> Result<()> {
        self.cctx.reinit().map_err(ProtocolError::from)?;
        Ok(())
    }
}

struct ZstdDecompressor {
    dctx: zstd::stream::raw::Decoder<'static>,
}

impl ZstdDecompressor {
    fn new() -> Result<Self> {
        let dctx = zstd::stream::raw::Decoder::new().map_err(ProtocolError::from)?;
        Ok(Self { dctx })
    }

    fn decompress(&mut self, compressed: &[u8], expected_len: usize) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(expected_len);
        let mut in_buffer = zstd::stream::raw::InBuffer::around(compressed);

        loop {
            let mut out_buf = vec![0u8; expected_len + 256];
            let mut out_buffer = zstd::stream::raw::OutBuffer::around(&mut out_buf);

            self.dctx
                .run(&mut in_buffer, &mut out_buffer)
                .map_err(ProtocolError::from)?;

            let pos = out_buffer.pos();
            output.extend_from_slice(&out_buf[..pos]);

            if in_buffer.pos() >= compressed.len() || pos == 0 {
                break;
            }
        }

        Ok(output)
    }

    fn reset(&mut self) -> Result<()> {
        self.dctx.reinit().map_err(ProtocolError::from)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LZ4 block backend
// ---------------------------------------------------------------------------

struct Lz4Compressor;

impl Lz4Compressor {
    fn new() -> Self {
        Self
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(lz4_flex::compress_prepend_size(data))
    }
}

struct Lz4Decompressor;

impl Lz4Decompressor {
    fn new() -> Self {
        Self
    }

    fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::decompress_size_prepended(compressed).map_err(|e| {
            ProtocolError::Io(std::sync::Arc::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("lz4 decompress error: {e}"),
            )))
        })
    }
}

// ---------------------------------------------------------------------------
// Polymorphic Compressor
// ---------------------------------------------------------------------------

/// Streaming compressor dispatching to zlib, zstd, or lz4.
///
/// The public API matches the original zlib-only `Compressor` so callers
/// (sender, token encoder) do not need to change.
pub struct Compressor {
    inner: CompressorKind,
}

enum CompressorKind {
    Zlib(ZlibCompressor),
    Zstd(ZstdCompressor),
    Lz4(Lz4Compressor),
}

/// Indicates whether this compressor uses the Z_SYNC_FLUSH trailer that
/// needs to be stripped on the wire (only zlib does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressorType {
    Zlib,
    Zstd,
    Lz4,
}

impl Compressor {
    /// Create a compressor for the negotiated compression type.
    pub fn from_type(compress_type: CompressType, level: u32) -> Result<Self> {
        match compress_type {
            CompressType::Zlib | CompressType::Zlibx => Ok(Self::new(level)),
            CompressType::Zstd => Self::new_zstd(level as i32),
            CompressType::Lz4 => Ok(Self::new_lz4()),
            CompressType::None => Ok(Self::new(level)), // fallback, shouldn't happen
        }
    }

    /// Create a new zlib compressor (backward-compatible constructor).
    pub fn new(level: u32) -> Self {
        Self {
            inner: CompressorKind::Zlib(ZlibCompressor::new(level)),
        }
    }

    /// Create a new zstd compressor with the given level (default: 3).
    pub fn new_zstd(level: i32) -> Result<Self> {
        Ok(Self {
            inner: CompressorKind::Zstd(ZstdCompressor::new(level)?),
        })
    }

    /// Create a new lz4 compressor.
    pub fn new_lz4() -> Self {
        Self {
            inner: CompressorKind::Lz4(Lz4Compressor::new()),
        }
    }

    /// What type of compressor this is.
    pub fn compressor_type(&self) -> CompressorType {
        match &self.inner {
            CompressorKind::Zlib(_) => CompressorType::Zlib,
            CompressorKind::Zstd(_) => CompressorType::Zstd,
            CompressorKind::Lz4(_) => CompressorType::Lz4,
        }
    }

    /// Compress `data`, returning the compressed bytes.
    ///
    /// For zlib, uses `Z_SYNC_FLUSH` so the decompressor can decode
    /// without waiting for more input.
    /// For zstd, uses `ZSTD_e_flush`.
    /// For lz4, uses block compression with prepended size.
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match &mut self.inner {
            CompressorKind::Zlib(c) => c.compress(data),
            CompressorKind::Zstd(c) => c.compress(data),
            CompressorKind::Lz4(c) => c.compress(data),
        }
    }

    /// Reset the compressor for a new file (zlibx mode, or zstd reset).
    pub fn reset(&mut self) -> Result<()> {
        match &mut self.inner {
            CompressorKind::Zlib(c) => {
                c.reset();
                Ok(())
            }
            CompressorKind::Zstd(c) => c.reset(),
            CompressorKind::Lz4(_) => Ok(()), // lz4 is stateless per block
        }
    }
}

// ---------------------------------------------------------------------------
// Polymorphic Decompressor
// ---------------------------------------------------------------------------

/// Streaming decompressor dispatching to zlib, zstd, or lz4.
pub struct Decompressor {
    inner: DecompressorKind,
}

enum DecompressorKind {
    Zlib(ZlibDecompressor),
    Zstd(ZstdDecompressor),
    Lz4(Lz4Decompressor),
}

impl Decompressor {
    /// Create a decompressor for the negotiated compression type.
    pub fn from_type(compress_type: CompressType) -> Result<Self> {
        match compress_type {
            CompressType::Zlib | CompressType::Zlibx => Ok(Self::new()),
            CompressType::Zstd => Self::new_zstd(),
            CompressType::Lz4 => Ok(Self::new_lz4()),
            CompressType::None => Ok(Self::new()), // fallback
        }
    }

    /// Create a new zlib decompressor (backward-compatible constructor).
    pub fn new() -> Self {
        Self {
            inner: DecompressorKind::Zlib(ZlibDecompressor::new()),
        }
    }

    /// Create a new zstd decompressor.
    pub fn new_zstd() -> Result<Self> {
        Ok(Self {
            inner: DecompressorKind::Zstd(ZstdDecompressor::new()?),
        })
    }

    /// Create a new lz4 decompressor.
    pub fn new_lz4() -> Self {
        Self {
            inner: DecompressorKind::Lz4(Lz4Decompressor::new()),
        }
    }

    /// What type of decompressor this is.
    pub fn decompressor_type(&self) -> CompressorType {
        match &self.inner {
            DecompressorKind::Zlib(_) => CompressorType::Zlib,
            DecompressorKind::Zstd(_) => CompressorType::Zstd,
            DecompressorKind::Lz4(_) => CompressorType::Lz4,
        }
    }

    /// Decompress data produced by the corresponding compressor.
    ///
    /// `expected_len` is a hint for output buffer sizing (used by zlib/zstd).
    /// For lz4, the output size is encoded in the compressed data.
    pub fn decompress(&mut self, compressed: &[u8], expected_len: usize) -> Result<Vec<u8>> {
        match &mut self.inner {
            DecompressorKind::Zlib(d) => d.decompress(compressed, expected_len),
            DecompressorKind::Zstd(d) => d.decompress(compressed, expected_len),
            DecompressorKind::Lz4(d) => d.decompress(compressed),
        }
    }

    /// Reset the decompressor for a new file (zlibx mode, or zstd reset).
    pub fn reset(&mut self) -> Result<()> {
        match &mut self.inner {
            DecompressorKind::Zlib(d) => {
                d.reset();
                Ok(())
            }
            DecompressorKind::Zstd(d) => d.reset(),
            DecompressorKind::Lz4(_) => Ok(()), // lz4 is stateless per block
        }
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

    // -----------------------------------------------------------------------
    // Zlib tests (unchanged from original)
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_roundtrip() {
        let data = b"Hello, world! This is test data for compression.";
        let compressed = compress_block(data, 6).unwrap();
        assert!(compressed.len() < data.len() + 20);
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

        compressor.reset().unwrap();
        decompressor.reset().unwrap();

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
        assert!(
            compressed.len() < 100,
            "compressed {} bytes to {} bytes",
            data.len(),
            compressed.len()
        );
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_incompressible_data() {
        let data: Vec<u8> = (0..5000)
            .map(|i| ((i * 7919 + 104729) % 256) as u8)
            .collect();
        let compressed = compress_block(&data, 6).unwrap();
        let decompressed = decompress_block(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    // -----------------------------------------------------------------------
    // Zstd tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_zstd_roundtrip() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let data = b"Hello, zstd compression test data!";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data.as_slice());
    }

    #[test]
    fn test_zstd_streaming_multiple_chunks() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let chunks = [
            b"first zstd chunk".as_slice(),
            b"second zstd chunk with more data".as_slice(),
            b"third and final zstd chunk".as_slice(),
        ];

        for chunk in &chunks {
            let compressed = compressor.compress(chunk).unwrap();
            let decompressed = decompressor.decompress(&compressed, chunk.len()).unwrap();
            assert_eq!(decompressed, *chunk);
        }
    }

    #[test]
    fn test_zstd_large_data() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compressor.compress(&data).unwrap();
        // Patterned data should compress well.
        assert!(compressed.len() < data.len());
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_zstd_empty() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let data = b"";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, 0).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_zstd_reset() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let data = b"data before reset";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data.as_slice());

        compressor.reset().unwrap();
        decompressor.reset().unwrap();

        let data2 = b"data after reset";
        let compressed2 = compressor.compress(data2).unwrap();
        let decompressed2 = decompressor.decompress(&compressed2, data2.len()).unwrap();
        assert_eq!(decompressed2, data2.as_slice());
    }

    #[test]
    fn test_zstd_compressor_type() {
        let c = Compressor::new_zstd(3).unwrap();
        assert_eq!(c.compressor_type(), CompressorType::Zstd);
        let d = Decompressor::new_zstd().unwrap();
        assert_eq!(d.decompressor_type(), CompressorType::Zstd);
    }

    // -----------------------------------------------------------------------
    // LZ4 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lz4_roundtrip() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let data = b"Hello, lz4 compression test data!";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data.as_slice());
    }

    #[test]
    fn test_lz4_streaming_multiple_chunks() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let chunks = [
            b"first lz4 chunk".as_slice(),
            b"second lz4 chunk with more data".as_slice(),
            b"third and final lz4 chunk".as_slice(),
        ];

        for chunk in &chunks {
            let compressed = compressor.compress(chunk).unwrap();
            let decompressed = decompressor.decompress(&compressed, chunk.len()).unwrap();
            assert_eq!(decompressed, *chunk);
        }
    }

    #[test]
    fn test_lz4_large_data() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compressor.compress(&data).unwrap();
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lz4_empty() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let data = b"";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = decompressor.decompress(&compressed, 0).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_lz4_highly_compressible() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let data = vec![0u8; 50_000];
        let compressed = compressor.compress(&data).unwrap();
        // All zeros should compress very well.
        assert!(
            compressed.len() < 1000,
            "compressed {} bytes to {} bytes",
            data.len(),
            compressed.len()
        );
        let decompressed = decompressor.decompress(&compressed, data.len()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lz4_compressor_type() {
        let c = Compressor::new_lz4();
        assert_eq!(c.compressor_type(), CompressorType::Lz4);
        let d = Decompressor::new_lz4();
        assert_eq!(d.decompressor_type(), CompressorType::Lz4);
    }

    // -----------------------------------------------------------------------
    // Cross-algorithm type checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_zlib_compressor_type() {
        let c = Compressor::new(6);
        assert_eq!(c.compressor_type(), CompressorType::Zlib);
        let d = Decompressor::new();
        assert_eq!(d.decompressor_type(), CompressorType::Zlib);
    }
}
