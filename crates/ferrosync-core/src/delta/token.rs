//! Wire-format token encoding/decoding for delta transfer.
//!
//! During delta transfer, the sender emits a stream of tokens:
//! - **Literal data**: a positive `i32` length followed by raw bytes.
//! - **Block match**: a negative `i32` encoding the matched block index as
//!   `-(index + 1)`.
//! - **End of file**: a zero token.
//!
//! ```text
//! read_int -> token
//! if token == 0:  end of file data
//! if token > 0:   `token` bytes of literal data follow
//! if token < 0:   matched block at index -(token+1)
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::protocol::compress::{Compressor, Decompressor};
use crate::protocol::varint;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Maximum size of a literal data chunk in a single token.
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Maximum size for a single wire allocation (256 MiB).
/// Prevents OOM from malicious or corrupted wire values.
const MAX_WIRE_ALLOC: usize = 256 * 1024 * 1024;

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

/// Write literal data tokens to the wire.
///
/// Large data is automatically split into CHUNK_SIZE pieces.
pub async fn send_data<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(CHUNK_SIZE) {
        varint::write_int(w, chunk.len() as i32).await?;
        w.write_all(chunk).await.map_err(ProtocolError::Io)?;
    }
    Ok(())
}

/// Write a block match token to the wire.
pub async fn send_block_match<W: AsyncWrite + Unpin>(
    w: &mut W,
    block_index: i32,
) -> Result<()> {
    let token = -(block_index + 1);
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
            r.read_exact(&mut buf).await.map_err(ProtocolError::Io)?;
            Ok(Token::Data(buf))
        }
        Ordering::Less => {
            let block_index = -(token + 1);
            Ok(Token::BlockMatch(block_index))
        }
    }
}

/// Write literal data tokens with compression.
///
/// Each chunk is deflated before writing. The wire format is:
/// `uncompressed_length (i32) | compressed_length (i32) | compressed_bytes`.
pub async fn send_data_compressed<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
    compressor: &mut Compressor,
) -> Result<()> {
    for chunk in data.chunks(CHUNK_SIZE) {
        let compressed = compressor.compress(chunk)?;
        // Write uncompressed length (positive = data token).
        varint::write_int(w, chunk.len() as i32).await?;
        // Write compressed length.
        varint::write_int(w, compressed.len() as i32).await?;
        // Write compressed data.
        w.write_all(&compressed).await.map_err(ProtocolError::Io)?;
    }
    Ok(())
}

/// Read the next token from a compressed stream.
///
/// Compressed data tokens have the format:
/// `uncompressed_length (i32) | compressed_length (i32) | compressed_bytes`.
/// Block match and EOF tokens are unchanged.
pub async fn recv_token_compressed<R: AsyncRead + Unpin>(
    r: &mut R,
    decompressor: &mut Decompressor,
) -> Result<Token> {
    let token = varint::read_int(r).await?;

    use std::cmp::Ordering;
    match token.cmp(&0) {
        Ordering::Equal => Ok(Token::EndOfFile),
        Ordering::Greater => {
            let uncompressed_len = token as usize;
            if uncompressed_len > MAX_WIRE_ALLOC {
                return Err(ProtocolError::WireValueOutOfRange {
                    field: "token_uncompressed_len",
                    value: token as i64,
                    max: MAX_WIRE_ALLOC as i64,
                });
            }
            let compressed_int = varint::read_int(r).await?;
            if compressed_int < 0 || compressed_int as usize > MAX_WIRE_ALLOC {
                return Err(ProtocolError::WireValueOutOfRange {
                    field: "token_compressed_len",
                    value: compressed_int as i64,
                    max: MAX_WIRE_ALLOC as i64,
                });
            }
            let compressed_len = compressed_int as usize;
            let mut compressed = vec![0u8; compressed_len];
            r.read_exact(&mut compressed)
                .await
                .map_err(ProtocolError::Io)?;
            let data = decompressor.decompress(&compressed, uncompressed_len)?;
            Ok(Token::Data(data))
        }
        Ordering::Less => {
            let block_index = -(token + 1);
            Ok(Token::BlockMatch(block_index))
        }
    }
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
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(0),
        );
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::Data(b"more".to_vec()),
        );
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::BlockMatch(3),
        );
        assert_eq!(
            recv_token(&mut cursor).await.unwrap(),
            Token::EndOfFile,
        );
    }

    #[tokio::test]
    async fn test_compressed_data_roundtrip() {
        let data = b"hello world, this is data that should compress well well well";
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, data, &mut compressor)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        match recv_token_compressed(&mut cursor, &mut decompressor)
            .await
            .unwrap()
        {
            Token::Data(d) => assert_eq!(d, data),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_compressed_mixed_stream() {
        let mut compressor = Compressor::new(6);
        let mut decompressor = Decompressor::new();

        let mut buf = Vec::new();
        send_data_compressed(&mut buf, b"literal data", &mut compressor)
            .await
            .unwrap();
        send_block_match(&mut buf, 0).await.unwrap();
        send_data_compressed(&mut buf, b"more data", &mut compressor)
            .await
            .unwrap();
        send_eof(&mut buf).await.unwrap();

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
}
