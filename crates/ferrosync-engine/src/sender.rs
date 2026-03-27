//! Sender role: matches blocks and sends delta tokens.
//!
//! The sender receives block signatures from the generator, matches them
//! against the source file using a rolling checksum, and sends delta tokens
//! (literal data + block match references) to the receiver.

use std::io::Read;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use ferrosync_delta::checksum;
use ferrosync_delta::matcher::{self, StreamingMatcher};
use ferrosync_delta::ops::DiffOp;
use ferrosync_delta::sum::{self, SumStruct};
use ferrosync_delta::token::{self, PlainTokenWriter, TokenWriter};
use ferrosync_delta::ProtocolContext;
use ferrosync_protocol::compress::Compressor;
use ferrosync_protocol::varint;
use ferrosync_types::error::ProtocolError;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Process a single file: read signatures, match against source, send tokens.
///
/// Wire format sent to receiver:
/// - file_index (NDX-encoded)
/// - sum_head (4x i32: count, blength, s2length, remainder)
/// - tokens (data/block_match/eof)
/// - file-level checksum (checksum_len bytes)
pub async fn send_file_delta<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    sig_reader: &mut R,
    token_writer: &mut W,
    file_index: i32,
    source_data: &[u8],
    ctx: &ProtocolContext,
) -> Result<()> {
    // Read block signatures from the generator.
    let sums = sum::read_sums(sig_reader).await?;

    // Match blocks.
    let ops = matcher::match_blocks(source_data, &sums, ctx);

    // Write file index.
    varint::write_int(token_writer, file_index).await?;

    // Write tokens + checksum.
    let mut writer = PlainTokenWriter::new();
    write_tokens_and_checksum(&mut writer, token_writer, &ops, source_data, &sums, ctx).await
}

/// Signal end of sender output (no more files).
pub async fn send_sender_done<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    varint::write_int(w, -1).await
}

/// Convenience: process a single file given the signatures already in hand.
pub async fn send_file_delta_with_sums<W: AsyncWrite + Unpin>(
    token_writer: &mut W,
    file_index: i32,
    source_data: &[u8],
    sums: &SumStruct,
    ctx: &ProtocolContext,
) -> Result<()> {
    let ops = matcher::match_blocks(source_data, sums, ctx);

    varint::write_int(token_writer, file_index).await?;

    let mut writer = PlainTokenWriter::new();
    write_tokens_and_checksum(&mut writer, token_writer, &ops, source_data, sums, ctx).await
}

/// Process a single file with compressed token output.
pub async fn send_file_delta_compressed<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    sig_reader: &mut R,
    token_writer: &mut W,
    file_index: i32,
    source_data: &[u8],
    ctx: &ProtocolContext,
    compressor: Compressor,
) -> Result<()> {
    let sums = sum::read_sums(sig_reader).await?;
    let ops = matcher::match_blocks(source_data, &sums, ctx);

    varint::write_int(token_writer, file_index).await?;

    let mut writer = token::CompressedTokenWriter::new(compressor);
    write_tokens_and_checksum(&mut writer, token_writer, &ops, source_data, &sums, ctx).await
}

/// Process a single file using streaming I/O: reads from a `Read` source in
/// chunks instead of requiring the entire file in memory.
///
/// Wire format is identical to [`send_file_delta_with_sums`] -- the receiver
/// cannot distinguish streaming from batch output.
pub async fn send_file_delta_streaming<W: AsyncWrite + Unpin>(
    token_writer: &mut W,
    file_index: i32,
    reader: &mut dyn Read,
    sums: &SumStruct,
    ctx: &ProtocolContext,
    chunk_size: usize,
) -> Result<()> {
    let blength = sums.head.blength as u32;
    varint::write_int(token_writer, file_index).await?;

    let mut smatcher = StreamingMatcher::new(sums, ctx, chunk_size);
    let mut file_hash = checksum::IncrementalChecksum::new(ctx.checksum_type);
    let mut writer = PlainTokenWriter::new();

    loop {
        let (ops, done) = smatcher
            .process_chunk(reader, &mut file_hash)
            .map_err(ProtocolError::from)?;
        token::write_diffops(&mut writer, token_writer, &ops, blength).await?;
        if done {
            break;
        }
    }
    writer.write_eof(token_writer).await?;

    let file_sum = file_hash.finalize();
    token_writer
        .write_all(&file_sum)
        .await
        .map_err(ProtocolError::from)?;

    Ok(())
}

/// Write tokens and file-level checksum.
async fn write_tokens_and_checksum<T: TokenWriter, W: AsyncWrite + Unpin>(
    writer: &mut T,
    w: &mut W,
    ops: &[DiffOp<'_>],
    source_data: &[u8],
    sums: &SumStruct,
    ctx: &ProtocolContext,
) -> Result<()> {
    let blength = sums.head.blength as u32;
    token::write_diffops(writer, w, ops, blength).await?;
    writer.write_eof(w).await?;

    let file_sum = checksum::file_checksum(source_data, ctx);
    w.write_all(&file_sum).await.map_err(ProtocolError::from)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrosync_delta::sum;
    use ferrosync_delta::ProtocolContext;
    use ferrosync_protocol::handshake::ChecksumType;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_send_file_delta_new_file() {
        let source = b"brand new file contents";
        let ctx = ProtocolContext::test_default(0, ChecksumType::Md5);
        let sums = sum::compute_signatures(b"", &ctx);
        let seed = 42;
        let ctx = ProtocolContext::test_default(seed, ChecksumType::Md5);

        let mut buf = Vec::new();
        send_file_delta_with_sums(&mut buf, 0, source, &sums, &ctx)
            .await
            .unwrap();

        // Verify we can read back: file_index + tokens + checksum.
        let mut cursor = Cursor::new(&buf);
        let idx = varint::read_int(&mut cursor).await.unwrap();
        assert_eq!(idx, 0);

        // Read tokens until EOF.
        let mut reconstructed = Vec::new();
        loop {
            match token::recv_token(&mut cursor).await.unwrap() {
                token::Token::Data(d) => reconstructed.extend_from_slice(&d),
                token::Token::EndOfFile => break,
                token::Token::BlockMatch(_) => panic!("no basis, shouldn't match"),
            }
        }
        assert_eq!(reconstructed, source);

        // Read checksum.
        let mut csum = vec![0u8; ChecksumType::Md5.digest_len()];
        tokio::io::AsyncReadExt::read_exact(&mut cursor, &mut csum)
            .await
            .unwrap();
        let expected = checksum::file_checksum(source, &ctx);
        assert_eq!(csum, expected);
    }

    #[tokio::test]
    async fn test_send_file_delta_from_stream() {
        let basis = vec![0xABu8; 3000];
        let source = basis.clone();
        let seed = 99;
        let ctx = ProtocolContext::test_default(seed, ChecksumType::Md5);

        let sums = sum::compute_signatures(&basis, &ctx);
        let mut sig_buf = Vec::new();
        sum::write_sums(&mut sig_buf, &sums).await.unwrap();

        let mut sig_cursor = Cursor::new(&sig_buf);
        let mut token_buf = Vec::new();
        send_file_delta(&mut sig_cursor, &mut token_buf, 0, &source, &ctx)
            .await
            .unwrap();

        assert!(!token_buf.is_empty());
    }

    #[tokio::test]
    async fn test_send_file_delta_streaming_matches_batch() {
        // Streaming and batch paths should produce identical wire output
        // for the same source data and signatures.
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let seed = 42;
        let ctx = ProtocolContext::test_default(seed, ChecksumType::Md5);
        let sums = sum::compute_signatures(&basis, &ctx);

        // Batch path.
        let mut batch_buf = Vec::new();
        send_file_delta_with_sums(&mut batch_buf, 0, &source, &sums, &ctx)
            .await
            .unwrap();

        // Streaming path.
        let mut stream_buf = Vec::new();
        let mut reader = Cursor::new(&source);
        send_file_delta_streaming(
            &mut stream_buf,
            0,
            &mut reader,
            &sums,
            &ctx,
            matcher::DEFAULT_STREAM_CHUNK,
        )
        .await
        .unwrap();

        // Both should decode to the same reconstructed content.
        let batch_data = decode_tokens(&batch_buf).await;
        let stream_data = decode_tokens(&stream_buf).await;
        assert_eq!(batch_data, stream_data);
    }

    #[tokio::test]
    async fn test_send_file_delta_streaming_new_file() {
        let source = b"brand new file contents";
        let ctx_zero = ProtocolContext::test_default(0, ChecksumType::Md5);
        let sums = sum::compute_signatures(b"", &ctx_zero);
        let seed = 42;
        let ctx = ProtocolContext::test_default(seed, ChecksumType::Md5);

        let mut buf = Vec::new();
        let mut reader = Cursor::new(source.as_slice());
        send_file_delta_streaming(
            &mut buf,
            0,
            &mut reader,
            &sums,
            &ctx,
            matcher::DEFAULT_STREAM_CHUNK,
        )
        .await
        .unwrap();

        let data = decode_tokens(&buf).await;
        assert_eq!(data, source);
    }

    #[tokio::test]
    async fn test_send_file_delta_streaming_small_chunks() {
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let source = basis.clone();
        let seed = 55;
        let ctx = ProtocolContext::test_default(seed, ChecksumType::Md5);
        let sums = sum::compute_signatures(&basis, &ctx);

        // Batch path for reference.
        let mut batch_buf = Vec::new();
        send_file_delta_with_sums(&mut batch_buf, 0, &source, &sums, &ctx)
            .await
            .unwrap();

        // Streaming path with a very small chunk size.
        let mut stream_buf = Vec::new();
        let mut reader = Cursor::new(&source);
        send_file_delta_streaming(&mut stream_buf, 0, &mut reader, &sums, &ctx, 1024)
            .await
            .unwrap();

        // Both should decode to the same token sequence.
        let batch_data = decode_tokens(&batch_buf).await;
        let stream_data = decode_tokens(&stream_buf).await;
        assert_eq!(batch_data, stream_data);
    }

    /// Decode file_index + tokens + checksum from a sender output buffer,
    /// returning the reconstructed file content.
    async fn decode_tokens(buf: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(buf);
        let _idx = varint::read_int(&mut cursor).await.unwrap();
        let mut reconstructed = Vec::new();
        loop {
            match token::recv_token(&mut cursor).await.unwrap() {
                token::Token::Data(d) => reconstructed.extend_from_slice(&d),
                token::Token::EndOfFile => break,
                token::Token::BlockMatch(_) => {
                    // For comparison purposes we just note that a match occurred;
                    // the actual block data comes from the basis which both paths
                    // reference identically.
                    reconstructed.extend_from_slice(b"<MATCH>");
                }
            }
        }
        reconstructed
    }
}
