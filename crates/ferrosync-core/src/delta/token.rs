//! Wire-format token encoding/decoding for delta transfer.
//!
//! During delta transfer, the sender emits a stream of tokens:
//! - **Literal data**: a positive `i32` length followed by raw bytes.
//! - **Block match**: a negative `i32` encoding the matched block index as
//!   `-(index + 1)`.
//! - **End of file**: a zero token.
//!
//! When compression is enabled, rsync uses a flag-byte scheme:
//! - `END_FLAG (0x00)` -- end of file
//! - `DEFLATED_DATA (0x40) | (len >> 8)` + `(len & 0xFF)` -- compressed data
//! - `TOKEN_REL (0x80) + offset` -- relative block match (offset 0-63)
//! - `TOKEN_LONG (0x20) + write_int(index)` -- absolute block match
//! - Run-length variants for consecutive block matches
//!
//! The DEFLATED_DATA flag-byte wire format is shared across all compression
//! algorithms (zlib, zstd, lz4). Only the compressed payload encoding differs.
//!
//! ```text
//! read_int -> token
//! if token == 0:  end of file data
//! if token > 0:   `token` bytes of literal data follow
//! if token < 0:   matched block at index -(token+1)
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ops::{DiffOp, OwnedDiffOp};
use crate::error::ProtocolError;
use crate::protocol::compress::{Compressor, CompressorType, Decompressor};
use crate::protocol::varint;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Maximum size of a literal data chunk in a single token.
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Maximum size for a single wire allocation (256 MiB).
/// Prevents OOM from malicious or corrupted wire values.
const MAX_WIRE_ALLOC: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Compressed token flag bytes (matches rsync's token.c)
// ---------------------------------------------------------------------------

/// End of compressed token stream.
const END_FLAG: u8 = 0x00;
/// Absolute block match token (followed by 4-byte index).
const TOKEN_LONG: u8 = 0x20;
/// Absolute block match with run count (followed by 4-byte index + 2-byte count).
const TOKENRUN_LONG: u8 = 0x21;
/// Compressed data follows: high 6 bits of length in flag, low 8 bits in next byte.
const DEFLATED_DATA: u8 = 0x40;
/// Relative block match token: low 6 bits = offset from last token.
const TOKEN_REL: u8 = 0x80;
/// Relative block match with run count.
const TOKENRUN_REL: u8 = 0xC0;

/// Maximum compressed data count per frame (14-bit length field).
const MAX_DATA_COUNT: usize = 16383;

/// The Z_SYNC_FLUSH trailer bytes that rsync strips from zlib compressed output.
/// Only used for zlib -- zstd and lz4 do not use this trailer.
const SYNC_FLUSH_TRAILER: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

/// A decoded transfer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// Literal data that doesn't match any basis block.
    Data(Vec<u8>),
    /// A matched block from the basis file, identified by index.
    BlockMatch(i32),
    /// End of file data -- all tokens for this file have been sent.
    EndOfFile,
}

// ---------------------------------------------------------------------------
// Helpers for trailer stripping (zlib only)
// ---------------------------------------------------------------------------

/// Strip the Z_SYNC_FLUSH trailer from compressed output if the compressor
/// is zlib. Zstd and lz4 do not use this trailer.
fn maybe_strip_trailer(compressed: &[u8], ctype: CompressorType) -> &[u8] {
    if ctype == CompressorType::Zlib
        && compressed.len() >= 4
        && compressed[compressed.len() - 4..] == SYNC_FLUSH_TRAILER
    {
        &compressed[..compressed.len() - 4]
    } else {
        compressed
    }
}

/// Append the Z_SYNC_FLUSH trailer for decompression if the decompressor
/// is zlib. Zstd and lz4 do not need it.
fn maybe_append_trailer(compressed: &mut Vec<u8>, dtype: CompressorType) {
    if dtype == CompressorType::Zlib {
        compressed.extend_from_slice(&SYNC_FLUSH_TRAILER);
    }
}

// ---------------------------------------------------------------------------
// Uncompressed token encoding/decoding (simple_send_token / simple_recv_token)
// ---------------------------------------------------------------------------

/// Write literal data tokens to the wire.
///
/// Large data is automatically split into CHUNK_SIZE pieces.
pub async fn send_data<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(CHUNK_SIZE) {
        varint::write_int(w, chunk.len() as i32).await?;
        w.write_all(chunk).await.map_err(ProtocolError::from)?;
    }
    Ok(())
}

/// Write a block match token to the wire.
pub async fn send_block_match<W: AsyncWrite + Unpin>(w: &mut W, block_index: i32) -> Result<()> {
    let token = block_index
        .checked_add(1)
        .and_then(|b| b.checked_neg())
        .ok_or(ProtocolError::WireValueOutOfRange {
            field: "block_index",
            value: block_index as i64,
            max: i32::MAX as i64,
        })?;
    varint::write_int(w, token).await
}

/// Write the end-of-file token.
pub async fn send_eof<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    varint::write_int(w, 0).await
}

/// Read the next token from the wire.
pub async fn recv_token<R: AsyncRead + Unpin>(r: &mut R) -> Result<Token> {
    let token = varint::read_int(r).await?;

    use std::cmp::Ordering;
    match token.cmp(&0) {
        Ordering::Equal => Ok(Token::EndOfFile),
        Ordering::Greater => {
            let len = token as usize;
            if len > MAX_WIRE_ALLOC {
                return Err(ProtocolError::WireValueOutOfRange {
                    field: "token_data_len",
                    value: token as i64,
                    max: MAX_WIRE_ALLOC as i64,
                });
            }
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).await.map_err(ProtocolError::from)?;
            Ok(Token::Data(buf))
        }
        Ordering::Less => {
            let block_index = -(token + 1);
            Ok(Token::BlockMatch(block_index))
        }
    }
}

// ---------------------------------------------------------------------------
// Compressed token encoding (matches rsync's send_deflated_token)
// ---------------------------------------------------------------------------

/// State for the compressed token sender, tracking block match runs.
pub struct CompressedTokenWriter {
    last_token: i32,
    run_start: i32,
    last_run_end: i32,
    flush_pending: bool,
    compressor: Compressor,
}

impl CompressedTokenWriter {
    pub fn new(compressor: Compressor) -> Self {
        Self {
            last_token: -1,
            run_start: 0,
            last_run_end: 0,
            flush_pending: false,
            compressor,
        }
    }

    /// Send a token with optional literal data preceding it.
    ///
    /// This mirrors rsync's `send_deflated_token(f, token, buf, offset, nb, toklen)`.
    /// - `data`: literal data bytes to compress and send (may be empty).
    /// - `token`: the block match index, or -1 for EOF, or -2 for data-only.
    pub async fn send_token<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        data: &[u8],
        token: i32,
    ) -> Result<()> {
        if self.last_token == -1 {
            // Initialization for new file.
            self.compressor.reset()?;
            self.last_run_end = 0;
            self.run_start = token;
            self.flush_pending = false;
        } else if self.last_token == -2 {
            self.run_start = token;
        } else if !data.is_empty()
            || token != self.last_token + 1
            || token >= self.run_start + 65536
        {
            // Output previous run.
            self.flush_run(w).await?;
            self.run_start = token;
        }

        self.last_token = token;

        if !data.is_empty() || self.flush_pending {
            self.compress_and_send(w, data, token != -2).await?;
            self.flush_pending = token == -2;
        }

        if token == -1 {
            // End of file.
            w.write_all(&[END_FLAG])
                .await
                .map_err(ProtocolError::from)?;
        }

        Ok(())
    }

    /// Flush a pending block match run to the wire.
    async fn flush_run<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> Result<()> {
        let r = self.run_start - self.last_run_end;
        let n = self.last_token - self.run_start;

        if (0..=63).contains(&r) {
            let flag = if n == 0 {
                TOKEN_REL + r as u8
            } else {
                TOKENRUN_REL + r as u8
            };
            w.write_all(&[flag]).await.map_err(ProtocolError::from)?;
        } else {
            let flag = if n == 0 { TOKEN_LONG } else { TOKENRUN_LONG };
            w.write_all(&[flag]).await.map_err(ProtocolError::from)?;
            varint::write_int(w, self.run_start).await?;
        }
        if n != 0 {
            w.write_all(&[n as u8, (n >> 8) as u8])
                .await
                .map_err(ProtocolError::from)?;
        }
        self.last_run_end = self.last_token;
        Ok(())
    }

    /// Compress data and write DEFLATED_DATA frames.
    async fn compress_and_send<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        data: &[u8],
        do_flush: bool,
    ) -> Result<()> {
        let ctype = self.compressor.compressor_type();

        // Compress data in chunks, writing DEFLATED_DATA frames.
        let mut offset = 0;
        while offset < data.len() || (offset == 0 && data.is_empty() && self.flush_pending) {
            let chunk_end = (offset + CHUNK_SIZE).min(data.len());
            let chunk = &data[offset..chunk_end];
            let is_last = chunk_end >= data.len();

            let compressed = self.compressor.compress(chunk)?;

            // Strip the Z_SYNC_FLUSH trailer only for zlib.
            let output = if is_last && do_flush {
                maybe_strip_trailer(&compressed, ctype)
            } else {
                &compressed[..]
            };

            if !output.is_empty() {
                let n = output.len();
                if n > MAX_DATA_COUNT {
                    // Split into multiple frames.
                    let mut pos = 0;
                    while pos < n {
                        let frame_len = (n - pos).min(MAX_DATA_COUNT);
                        let hdr = [
                            DEFLATED_DATA + (frame_len >> 8) as u8,
                            (frame_len & 0xFF) as u8,
                        ];
                        w.write_all(&hdr).await.map_err(ProtocolError::from)?;
                        w.write_all(&output[pos..pos + frame_len])
                            .await
                            .map_err(ProtocolError::from)?;
                        pos += frame_len;
                    }
                } else {
                    let hdr = [DEFLATED_DATA + (n >> 8) as u8, (n & 0xFF) as u8];
                    w.write_all(&hdr).await.map_err(ProtocolError::from)?;
                    w.write_all(output).await.map_err(ProtocolError::from)?;
                }
            }

            offset = chunk_end;
            if data.is_empty() {
                break;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Compressed token decoding (matches rsync's recv_deflated_token)
// ---------------------------------------------------------------------------

/// State for the compressed token receiver.
pub struct CompressedTokenReader {
    decompressor: Decompressor,
    rx_token: i32,
    rx_run: i32,
    state: CompressRecvState,
    _pending_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressRecvState {
    Init,
    Idle,
    Running,
}

impl CompressedTokenReader {
    pub fn new(decompressor: Decompressor) -> Self {
        Self {
            decompressor,
            rx_token: 0,
            rx_run: 0,
            state: CompressRecvState::Init,
            _pending_data: Vec::new(),
        }
    }

    /// Read the next token from the compressed stream.
    ///
    /// This mirrors rsync's `recv_deflated_token`. The wire format uses
    /// flag bytes to distinguish data, block matches, and EOF.
    pub async fn recv_token<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Result<Token> {
        let dtype = self.decompressor.decompressor_type();

        loop {
            match self.state {
                CompressRecvState::Init => {
                    self.decompressor.reset()?;
                    self.state = CompressRecvState::Idle;
                    self.rx_token = 0;
                }
                CompressRecvState::Running => {
                    self.rx_token += 1;
                    self.rx_run -= 1;
                    if self.rx_run == 0 {
                        self.state = CompressRecvState::Idle;
                    }
                    return Ok(Token::BlockMatch(self.rx_token));
                }
                CompressRecvState::Idle => {
                    let flag = varint::read_byte(r).await?;

                    if (flag & 0xC0) == DEFLATED_DATA {
                        // Compressed data frame.
                        let n =
                            ((flag as usize & 0x3F) << 8) + varint::read_byte(r).await? as usize;
                        if n == 0 {
                            continue;
                        }
                        if n > MAX_DATA_COUNT {
                            return Err(ProtocolError::WireValueOutOfRange {
                                field: "compressed_data_len",
                                value: n as i64,
                                max: MAX_DATA_COUNT as i64,
                            });
                        }
                        let mut compressed = vec![0u8; n];
                        r.read_exact(&mut compressed)
                            .await
                            .map_err(ProtocolError::from)?;

                        // Append the Z_SYNC_FLUSH trailer only for zlib.
                        maybe_append_trailer(&mut compressed, dtype);

                        let decompressed = self.decompressor.decompress(&compressed, CHUNK_SIZE)?;
                        if !decompressed.is_empty() {
                            return Ok(Token::Data(decompressed));
                        }
                        continue;
                    }

                    if flag == END_FLAG {
                        self.state = CompressRecvState::Init;
                        return Ok(Token::EndOfFile);
                    }

                    // Block match token.
                    if flag & TOKEN_REL != 0 {
                        self.rx_token += (flag & 0x3F) as i32;
                        let shifted = flag >> 6;
                        if shifted & 1 != 0 {
                            // Run count follows.
                            let lo = varint::read_byte(r).await? as i32;
                            let hi = varint::read_byte(r).await? as i32;
                            self.rx_run = lo + (hi << 8);
                            self.state = CompressRecvState::Running;
                        }
                    } else {
                        self.rx_token = varint::read_int(r).await?;
                        if self.rx_token < 0 {
                            return Err(ProtocolError::Handshake {
                                message: "invalid token number in compressed stream".to_string(),
                            });
                        }
                        if flag & 1 != 0 {
                            // Run count follows (TOKEN_LONG variant).
                            let lo = varint::read_byte(r).await? as i32;
                            let hi = varint::read_byte(r).await? as i32;
                            self.rx_run = lo + (hi << 8);
                            self.state = CompressRecvState::Running;
                        }
                    }
                    return Ok(Token::BlockMatch(self.rx_token));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers (backward-compatible API)
// ---------------------------------------------------------------------------

/// Write literal data tokens with compression.
///
/// Uses rsync's compressed wire format: DEFLATED_DATA flag bytes with
/// compressed payload. The compressor state is maintained across calls.
/// Works with all compression backends (zlib, zstd, lz4).
pub async fn send_data_compressed<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
    compressor: &mut Compressor,
) -> Result<()> {
    let ctype = compressor.compressor_type();

    for chunk in data.chunks(CHUNK_SIZE) {
        let compressed = compressor.compress(chunk)?;

        // Strip Z_SYNC_FLUSH trailer only for zlib.
        let output = maybe_strip_trailer(&compressed, ctype);

        if !output.is_empty() {
            let n = output.len();
            if n > MAX_DATA_COUNT {
                // Split into multiple frames.
                let mut pos = 0;
                while pos < n {
                    let frame_len = (n - pos).min(MAX_DATA_COUNT);
                    let hdr = [
                        DEFLATED_DATA + (frame_len >> 8) as u8,
                        (frame_len & 0xFF) as u8,
                    ];
                    w.write_all(&hdr).await.map_err(ProtocolError::from)?;
                    w.write_all(&output[pos..pos + frame_len])
                        .await
                        .map_err(ProtocolError::from)?;
                    pos += frame_len;
                }
            } else {
                let hdr = [DEFLATED_DATA + (n >> 8) as u8, (n & 0xFF) as u8];
                w.write_all(&hdr).await.map_err(ProtocolError::from)?;
                w.write_all(output).await.map_err(ProtocolError::from)?;
            }
        }
    }
    Ok(())
}

/// Write a block match token in compressed stream format.
///
/// Uses rsync's TOKEN_LONG encoding (flag byte + 4-byte index).
pub async fn send_block_match_compressed<W: AsyncWrite + Unpin>(
    w: &mut W,
    block_index: i32,
) -> Result<()> {
    w.write_all(&[TOKEN_LONG])
        .await
        .map_err(ProtocolError::from)?;
    varint::write_int(w, block_index).await
}

/// Write the end-of-file marker in compressed stream format.
pub async fn send_eof_compressed<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    w.write_all(&[END_FLAG]).await.map_err(ProtocolError::from)
}

/// Read the next token from a compressed stream.
///
/// Uses rsync's compressed wire format with flag bytes.
/// Works with all decompression backends (zlib, zstd, lz4).
///
/// **Note:** This simple API cannot correctly decode `TOKEN_REL` or
/// `TOKENRUN_REL`/`TOKENRUN_LONG` tokens because they require stateful
/// tracking of the last block index. If a relative or run token is
/// encountered, this function returns an error. Use
/// [`CompressedTokenReader`] for full support of all compressed token types.
pub async fn recv_token_compressed<R: AsyncRead + Unpin>(
    r: &mut R,
    decompressor: &mut Decompressor,
) -> Result<Token> {
    let dtype = decompressor.decompressor_type();
    let flag = varint::read_byte(r).await?;

    if flag == END_FLAG {
        return Ok(Token::EndOfFile);
    }

    if (flag & 0xC0) == DEFLATED_DATA {
        // Compressed data frame.
        let n = ((flag as usize & 0x3F) << 8) + varint::read_byte(r).await? as usize;
        if n == 0 {
            return Ok(Token::Data(Vec::new()));
        }
        if n > MAX_DATA_COUNT {
            return Err(ProtocolError::WireValueOutOfRange {
                field: "compressed_data_len",
                value: n as i64,
                max: MAX_DATA_COUNT as i64,
            });
        }
        let mut compressed = vec![0u8; n];
        r.read_exact(&mut compressed)
            .await
            .map_err(ProtocolError::from)?;

        // Append Z_SYNC_FLUSH trailer only for zlib.
        maybe_append_trailer(&mut compressed, dtype);

        let decompressed = decompressor.decompress(&compressed, CHUNK_SIZE)?;
        return Ok(Token::Data(decompressed));
    }

    // Block match token.
    if flag & TOKEN_REL != 0 {
        // TOKEN_REL and TOKENRUN_REL encode a relative offset from the
        // last block index. The simple stateless API cannot resolve these;
        // callers must use CompressedTokenReader instead.
        return Err(ProtocolError::Handshake {
            message: "recv_token_compressed: TOKEN_REL requires stateful decoding; \
                      use CompressedTokenReader instead"
                .to_string(),
        });
    }

    if flag == TOKENRUN_LONG {
        // TOKENRUN_LONG encodes a run of consecutive block matches.
        // The simple stateless API cannot track run state.
        return Err(ProtocolError::Handshake {
            message: "recv_token_compressed: TOKENRUN_LONG requires stateful decoding; \
                      use CompressedTokenReader instead"
                .to_string(),
        });
    }

    // TOKEN_LONG: read absolute index.
    let block_index = varint::read_int(r).await?;
    Ok(Token::BlockMatch(block_index))
}

// ---------------------------------------------------------------------------
// DiffOp -> wire token helpers
// ---------------------------------------------------------------------------

/// Write a sequence of borrowed diff operations as rsync wire tokens.
///
/// Translates `DiffOp::Copy` back to block indices using `blength`, then
/// writes uncompressed data/block-match tokens followed by EOF.
pub async fn write_diffops_as_tokens<W: AsyncWrite + Unpin>(
    w: &mut W,
    ops: &[DiffOp<'_>],
    blength: u32,
) -> Result<()> {
    for op in ops {
        match op {
            DiffOp::Literal(data) => send_data(w, data).await?,
            DiffOp::Copy(bref) => send_block_match(w, bref.block_index(blength)).await?,
        }
    }
    send_eof(w).await
}

/// Write a sequence of owned diff operations as rsync wire tokens.
///
/// Same as [`write_diffops_as_tokens`] but for owned operations from
/// streaming matchers.
pub async fn write_owned_diffops_as_tokens<W: AsyncWrite + Unpin>(
    w: &mut W,
    ops: &[OwnedDiffOp],
    blength: u32,
) -> Result<()> {
    for op in ops {
        match op {
            OwnedDiffOp::Literal(data) => send_data(w, data).await?,
            OwnedDiffOp::Copy(bref) => send_block_match(w, bref.block_index(blength)).await?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_eof_roundtrip() {
        let mut buf = Vec::new();
        send_eof(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(recv_token(&mut cursor).await.unwrap(), Token::EndOfFile);
    }

    #[tokio::test]
    async fn test_data_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        send_data(&mut buf, data).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        match recv_token(&mut cursor).await.unwrap() {
            Token::Data(d) => assert_eq!(d, data),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_block_match_roundtrip() {
        for idx in [0, 1, 5, 100] {
            let mut buf = Vec::new();
            send_block_match(&mut buf, idx).await.unwrap();

            let mut cursor = Cursor::new(&buf);
            assert_eq!(
                recv_token(&mut cursor).await.unwrap(),
                Token::BlockMatch(idx),
            );
        }
    }

    #[tokio::test]
    async fn test_mixed_token_stream() {
        let mut buf = Vec::new();
        send_data(&mut buf, b"literal").await.unwrap();
        send_block_match(&mut buf, 0).await.unwrap();
        send_data(&mut buf, b"more").await.unwrap();
        send_block_match(&mut buf, 3).await.unwrap();
        send_eof(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::Data(b"literal".to_vec()),
        );
        assert_eq!(recv_token(&mut cursor).await.unwrap(), Token::BlockMatch(0),);
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::Data(b"more".to_vec()),
        );
        assert_eq!(recv_token(&mut cursor).await.unwrap(), Token::BlockMatch(3),);
        assert_eq!(recv_token(&mut cursor).await.unwrap(), Token::EndOfFile,);
    }

    // -----------------------------------------------------------------------
    // Zlib compressed token tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_compressed_data_roundtrip() {
        let data = b"hello world, this is data that should compress well well well";
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, data, &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        match recv_token_compressed(&mut cursor, &mut decompressor)
            .await
            .unwrap()
        {
            Token::Data(d) => assert_eq!(d, data.as_slice()),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_compressed_block_match_roundtrip() {
        let mut buf = Vec::new();
        send_block_match_compressed(&mut buf, 42).await.unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut decompressor = Decompressor::new();
        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::BlockMatch(42),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_compressed_mixed_stream() {
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, b"literal data", &mut compressor)
            .await
            .unwrap();
        send_block_match_compressed(&mut buf, 0).await.unwrap();
        send_data_compressed(&mut buf, b"more data", &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"literal data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::BlockMatch(0),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"more data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_compressed_wire_format_flag_bytes() {
        // Verify the wire format uses correct flag bytes.
        let mut buf = Vec::new();
        send_eof_compressed(&mut buf).await.unwrap();
        assert_eq!(buf, &[END_FLAG]);

        let mut buf2 = Vec::new();
        send_block_match_compressed(&mut buf2, 5).await.unwrap();
        assert_eq!(buf2[0], TOKEN_LONG);
        // Next 4 bytes are the LE i32 block index.
        assert_eq!(i32::from_le_bytes(buf2[1..5].try_into().unwrap()), 5);
    }

    #[tokio::test]
    async fn test_stateful_compressed_reader() {
        // Test the CompressedTokenReader with run encoding.
        let compressor = Compressor::new(6);

        // Build a compressed stream with the stateful writer.
        let mut buf = Vec::new();
        let mut writer = CompressedTokenWriter::new(compressor);

        // Send data + block 0 + block 1 (consecutive = run) + EOF
        writer.send_token(&mut buf, b"hello", 0).await.unwrap();
        writer.send_token(&mut buf, b"", 1).await.unwrap();
        writer.send_token(&mut buf, b"", -1).await.unwrap();

        // Read back with stateful reader.
        let decompressor = Decompressor::new();
        let mut reader = CompressedTokenReader::new(decompressor);
        let mut cursor = Cursor::new(&buf);

        match reader.recv_token(&mut cursor).await.unwrap() {
            Token::Data(d) => assert_eq!(d, b"hello"),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(0),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(1),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_recv_token_compressed_rejects_token_rel() {
        // Issue #60: the simple recv_token_compressed API must not silently
        // return wrong indices for TOKEN_REL. It should return an error.
        let mut buf = vec![TOKEN_REL + 5]; // TOKEN_REL with offset=5
        buf.push(END_FLAG); // followed by EOF

        let mut decompressor = Decompressor::new();
        let mut cursor = Cursor::new(&buf);
        let result = recv_token_compressed(&mut cursor, &mut decompressor).await;
        assert!(
            result.is_err(),
            "TOKEN_REL should error in simple API, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_large_data_chunking() {
        let data = vec![0xABu8; CHUNK_SIZE * 2 + 100];
        let mut buf = Vec::new();
        send_data(&mut buf, &data).await.unwrap();

        // Should produce 3 tokens: CHUNK_SIZE, CHUNK_SIZE, 100
        let mut cursor = Cursor::new(&buf);
        let mut reassembled = Vec::new();
        for _ in 0..3 {
            match recv_token(&mut cursor).await.unwrap() {
                Token::Data(d) => reassembled.extend_from_slice(&d),
                other => panic!("expected Data, got {other:?}"),
            }
        }
        assert_eq!(reassembled, data);
    }

    // -----------------------------------------------------------------------
    // Zstd compressed token tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_zstd_compressed_data_roundtrip() {
        let data = b"hello world, this is zstd data that should compress well well well";
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, data, &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        match recv_token_compressed(&mut cursor, &mut decompressor)
            .await
            .unwrap()
        {
            Token::Data(d) => assert_eq!(d, data.as_slice()),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_zstd_compressed_mixed_stream() {
        let mut compressor = Compressor::new_zstd(3).unwrap();
        let mut decompressor = Decompressor::new_zstd().unwrap();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, b"zstd literal data", &mut compressor)
            .await
            .unwrap();
        send_block_match_compressed(&mut buf, 7).await.unwrap();
        send_data_compressed(&mut buf, b"more zstd data", &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"zstd literal data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::BlockMatch(7),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"more zstd data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_zstd_stateful_writer_reader() {
        let compressor = Compressor::new_zstd(3).unwrap();

        let mut buf = Vec::new();
        let mut writer = CompressedTokenWriter::new(compressor);

        writer.send_token(&mut buf, b"zstd hello", 0).await.unwrap();
        writer.send_token(&mut buf, b"", 1).await.unwrap();
        writer.send_token(&mut buf, b"", -1).await.unwrap();

        let decompressor = Decompressor::new_zstd().unwrap();
        let mut reader = CompressedTokenReader::new(decompressor);
        let mut cursor = Cursor::new(&buf);

        match reader.recv_token(&mut cursor).await.unwrap() {
            Token::Data(d) => assert_eq!(d, b"zstd hello"),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(0),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(1),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::EndOfFile,
        );
    }

    // -----------------------------------------------------------------------
    // LZ4 compressed token tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_lz4_compressed_data_roundtrip() {
        let data = b"hello world, this is lz4 data that should compress well well well";
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, data, &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        match recv_token_compressed(&mut cursor, &mut decompressor)
            .await
            .unwrap()
        {
            Token::Data(d) => assert_eq!(d, data.as_slice()),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_lz4_compressed_mixed_stream() {
        let mut compressor = Compressor::new_lz4();
        let mut decompressor = Decompressor::new_lz4();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, b"lz4 literal data", &mut compressor)
            .await
            .unwrap();
        send_block_match_compressed(&mut buf, 3).await.unwrap();
        send_data_compressed(&mut buf, b"more lz4 data", &mut compressor)
            .await
            .unwrap();
        send_eof_compressed(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"lz4 literal data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::BlockMatch(3),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::Data(b"more lz4 data".to_vec()),
        );
        assert_eq!(
            recv_token_compressed(&mut cursor, &mut decompressor)
                .await
                .unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_lz4_stateful_writer_reader() {
        let compressor = Compressor::new_lz4();

        let mut buf = Vec::new();
        let mut writer = CompressedTokenWriter::new(compressor);

        writer.send_token(&mut buf, b"lz4 hello", 0).await.unwrap();
        writer.send_token(&mut buf, b"", 1).await.unwrap();
        writer.send_token(&mut buf, b"", -1).await.unwrap();

        let decompressor = Decompressor::new_lz4();
        let mut reader = CompressedTokenReader::new(decompressor);
        let mut cursor = Cursor::new(&buf);

        match reader.recv_token(&mut cursor).await.unwrap() {
            Token::Data(d) => assert_eq!(d, b"lz4 hello"),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(0),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(1),
        );
        assert_eq!(
            reader.recv_token(&mut cursor).await.unwrap(),
            Token::EndOfFile,
        );
    }

    // -----------------------------------------------------------------------
    // Negotiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_negotiate_zstd_selected() {
        use crate::protocol::handshake::CompressType;
        // ferrosync-to-ferrosync: both support zstd, should be first pick
        let our_list = "zstd lz4 zlibx zlib none";
        let their_list = "zstd lz4 zlibx zlib none";
        // Manually check first common entry
        let mut selected = None;
        for name in our_list.split_whitespace() {
            if their_list.split_whitespace().any(|r| r == name) {
                selected = CompressType::from_name(name);
                break;
            }
        }
        assert_eq!(selected, Some(CompressType::Zstd));
    }

    #[test]
    fn test_negotiate_lz4_fallback() {
        use crate::protocol::handshake::CompressType;
        // Remote only supports lz4 and zlib
        let our_list = "zstd lz4 zlibx zlib none";
        let their_list = "lz4 zlib none";
        let mut selected = None;
        for name in our_list.split_whitespace() {
            if their_list.split_whitespace().any(|r| r == name) {
                selected = CompressType::from_name(name);
                break;
            }
        }
        assert_eq!(selected, Some(CompressType::Lz4));
    }

    #[test]
    fn test_negotiate_zlib_fallback_with_rsync() {
        use crate::protocol::handshake::CompressType;
        // Standard rsync 3.1.x only supports zlib/zlibx
        let our_list = "zstd lz4 zlibx zlib none";
        let their_list = "zlibx zlib none";
        let mut selected = None;
        for name in our_list.split_whitespace() {
            if their_list.split_whitespace().any(|r| r == name) {
                selected = CompressType::from_name(name);
                break;
            }
        }
        assert_eq!(selected, Some(CompressType::Zlibx));
    }
}
