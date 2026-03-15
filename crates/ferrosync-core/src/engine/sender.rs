//! Sender role: matches blocks and sends delta tokens.
//!
//! The sender receives block signatures from the generator, matches them
//! against the source file using a rolling checksum, and sends delta tokens
//! (literal data + block match references) to the receiver.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::delta::checksum;
use crate::delta::matcher::{self, MatchOp};
use crate::delta::sum::{self, SumStruct};
use crate::delta::token;
use crate::error::ProtocolError;
use crate::protocol::compress::Compressor;
use crate::protocol::handshake::ChecksumType;
use crate::protocol::varint;

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
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<()> {
    // Read block signatures from the generator.
    let sums = sum::read_sums(sig_reader).await?;

    // Match blocks.
    let ops = matcher::match_blocks(
        source_data,
        &sums,
        seed,
        checksum_type,
        checksum::CHAR_OFFSET_V30,
        true,
    );

    // Write file index.
    varint::write_int(token_writer, file_index).await?;

    // Write tokens + checksum.
    write_tokens_and_checksum(token_writer, &ops, source_data, seed, checksum_type).await
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
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<()> {
    let ops = matcher::match_blocks(
        source_data,
        sums,
        seed,
        checksum_type,
        checksum::CHAR_OFFSET_V30,
        true,
    );

    varint::write_int(token_writer, file_index).await?;

    write_tokens_and_checksum(token_writer, &ops, source_data, seed, checksum_type).await
}

/// Process a single file with compressed token output.
pub async fn send_file_delta_compressed<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    sig_reader: &mut R,
    token_writer: &mut W,
    file_index: i32,
    source_data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
    compressor: &mut Compressor,
) -> Result<()> {
    let sums = sum::read_sums(sig_reader).await?;
    let ops = matcher::match_blocks(
        source_data,
        &sums,
        seed,
        checksum_type,
        checksum::CHAR_OFFSET_V30,
        true,
    );

    varint::write_int(token_writer, file_index).await?;

    for op in &ops {
        match op {
            MatchOp::Data(data) => {
                token::send_data_compressed(token_writer, data, compressor).await?;
            }
            MatchOp::BlockMatch(idx) => {
                token::send_block_match_compressed(token_writer, *idx).await?;
            }
        }
    }
    token::send_eof_compressed(token_writer).await?;

    let file_sum = checksum::file_checksum(source_data, seed, checksum_type);
    token_writer
        .write_all(&file_sum)
        .await
        .map_err(ProtocolError::from)?;

    Ok(())
}

/// Write tokens and file-level checksum.
async fn write_tokens_and_checksum<W: AsyncWrite + Unpin>(
    w: &mut W,
    ops: &[MatchOp],
    source_data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<()> {
    for op in ops {
        match op {
            MatchOp::Data(data) => token::send_data(w, data).await?,
            MatchOp::BlockMatch(idx) => token::send_block_match(w, *idx).await?,
        }
    }
    token::send_eof(w).await?;

    let file_sum = checksum::file_checksum(source_data, seed, checksum_type);
    w.write_all(&file_sum).await.map_err(ProtocolError::from)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::sum;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_send_file_delta_new_file() {
        let source = b"brand new file contents";
        let sums =
            sum::compute_signatures(b"", 0, ChecksumType::Md5, checksum::CHAR_OFFSET_V30, true);
        let seed = 42;

        let mut buf = Vec::new();
        send_file_delta_with_sums(&mut buf, 0, source, &sums, seed, ChecksumType::Md5)
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
        let expected = checksum::file_checksum(source, seed, ChecksumType::Md5);
        assert_eq!(csum, expected);
    }

    #[tokio::test]
    async fn test_send_file_delta_from_stream() {
        let basis = vec![0xABu8; 3000];
        let source = basis.clone();
        let seed = 99;

        let sums = sum::compute_signatures(
            &basis,
            seed,
            ChecksumType::Md5,
            checksum::CHAR_OFFSET_V30,
            true,
        );
        let mut sig_buf = Vec::new();
        sum::write_sums(&mut sig_buf, &sums).await.unwrap();

        let mut sig_cursor = Cursor::new(&sig_buf);
        let mut token_buf = Vec::new();
        send_file_delta(
            &mut sig_cursor,
            &mut token_buf,
            0,
            &source,
            seed,
            ChecksumType::Md5,
        )
        .await
        .unwrap();

        assert!(!token_buf.is_empty());
    }
}
