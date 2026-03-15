//! Receiver role: receives delta tokens and reconstructs files.
//!
//! The receiver reads delta tokens from the sender, combines them with
//! the local basis file to reconstruct the updated file, and verifies
//! the file-level checksum.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::delta::checksum;
use crate::delta::token::{self, Token};
use crate::error::ProtocolError;
use crate::protocol::compress::Decompressor;
use crate::protocol::handshake::ChecksumType;
use crate::protocol::varint;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Result of receiving and applying a single file's delta.
#[derive(Debug)]
pub struct ReceivedFile {
    /// The file index from the sender.
    pub file_index: i32,
    /// The reconstructed file data.
    pub data: Vec<u8>,
}

/// Read a file index from the sender stream.
///
/// Returns `None` if the sender is done (file_index == -1).
pub async fn recv_file_index<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<i32>> {
    let idx = varint::read_int(r).await?;
    if idx == -1 {
        Ok(None)
    } else {
        Ok(Some(idx))
    }
}

/// Receive tokens and reconstruct a file from the basis data.
///
/// Reads tokens until `EndOfFile`, then reads and verifies the file-level
/// checksum. Returns the reconstructed file data.
pub async fn recv_file_delta<R: AsyncRead + Unpin>(
    r: &mut R,
    basis_data: &[u8],
    blength: usize,
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let block_count = if blength > 0 && !basis_data.is_empty() {
        basis_data.len().div_ceil(blength)
    } else {
        0
    };
    #[allow(clippy::manual_is_multiple_of)]
    let remainder = if blength > 0 && !basis_data.is_empty() && basis_data.len() % blength != 0 {
        basis_data.len() % blength
    } else {
        blength
    };

    // Read tokens.
    loop {
        match token::recv_token(r).await? {
            Token::Data(data) => {
                output.extend_from_slice(&data);
            }
            Token::BlockMatch(idx) => {
                let idx = idx as usize;
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
                let end = (offset + len).min(basis_data.len());
                if offset < basis_data.len() {
                    output.extend_from_slice(&basis_data[offset..end]);
                }
            }
            Token::EndOfFile => break,
        }
    }

    // Read and verify file-level checksum.
    let digest_len = checksum_type.digest_len();
    let mut received_checksum = vec![0u8; digest_len];
    r.read_exact(&mut received_checksum)
        .await
        .map_err(ProtocolError::from)?;

    let computed_checksum = checksum::file_checksum(&output, seed, checksum_type);
    if received_checksum != computed_checksum {
        return Err(ProtocolError::ChecksumMismatch {
            expected: hex_encode(&received_checksum),
            actual: hex_encode(&computed_checksum),
        });
    }

    Ok(output)
}

/// Receive tokens with decompression and reconstruct a file.
///
/// Same as [`recv_file_delta`] but decompresses data tokens using the
/// provided decompressor.
pub async fn recv_file_delta_compressed<R: AsyncRead + Unpin>(
    r: &mut R,
    basis_data: &[u8],
    blength: usize,
    seed: i32,
    checksum_type: ChecksumType,
    decompressor: &mut Decompressor,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let block_count = if blength > 0 && !basis_data.is_empty() {
        basis_data.len().div_ceil(blength)
    } else {
        0
    };
    #[allow(clippy::manual_is_multiple_of)]
    let remainder = if blength > 0 && !basis_data.is_empty() && basis_data.len() % blength != 0 {
        basis_data.len() % blength
    } else {
        blength
    };

    loop {
        match token::recv_token_compressed(r, decompressor).await? {
            Token::Data(data) => {
                output.extend_from_slice(&data);
            }
            Token::BlockMatch(idx) => {
                let idx = idx as usize;
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
                let end = (offset + len).min(basis_data.len());
                if offset < basis_data.len() {
                    output.extend_from_slice(&basis_data[offset..end]);
                }
            }
            Token::EndOfFile => break,
        }
    }

    let digest_len = checksum_type.digest_len();
    let mut received_checksum = vec![0u8; digest_len];
    r.read_exact(&mut received_checksum)
        .await
        .map_err(ProtocolError::from)?;

    let computed_checksum = checksum::file_checksum(&output, seed, checksum_type);
    if received_checksum != computed_checksum {
        return Err(ProtocolError::ChecksumMismatch {
            expected: hex_encode(&received_checksum),
            actual: hex_encode(&computed_checksum),
        });
    }

    Ok(output)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::{sum, token};
    use crate::engine::sender;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_recv_new_file() {
        let source = b"hello world, this is new data!";
        let seed = 42;
        let sums = sum::compute_signatures(
            b"",
            seed,
            ChecksumType::Md5,
            checksum::CHAR_OFFSET_V30,
            true,
        );

        // Sender writes: file_index + tokens + checksum.
        let mut buf = Vec::new();
        sender::send_file_delta_with_sums(&mut buf, 0, source, &sums, seed, ChecksumType::Md5)
            .await
            .unwrap();

        // Receiver reads.
        let mut cursor = Cursor::new(&buf);
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, Some(0));

        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };
        let result = recv_file_delta(&mut cursor, b"", blength, seed, ChecksumType::Md5)
            .await
            .unwrap();

        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_recv_identical_file() {
        let data = vec![0xABu8; 3000];
        let seed = 99;
        let sums = sum::compute_signatures(
            &data,
            seed,
            ChecksumType::Md5,
            checksum::CHAR_OFFSET_V30,
            true,
        );

        let mut buf = Vec::new();
        sender::send_file_delta_with_sums(&mut buf, 0, &data, &sums, seed, ChecksumType::Md5)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, Some(0));

        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };
        let result = recv_file_delta(&mut cursor, &data, blength, seed, ChecksumType::Md5)
            .await
            .unwrap();

        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_recv_modified_file() {
        let mut basis = vec![0u8; 5000];
        for (i, b) in basis.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let mut source = basis.clone();
        source[2500] = 0xFF;
        source[2501] = 0xFF;

        let seed = 7;
        let sums = sum::compute_signatures(
            &basis,
            seed,
            ChecksumType::Md5,
            checksum::CHAR_OFFSET_V30,
            true,
        );

        let mut buf = Vec::new();
        sender::send_file_delta_with_sums(&mut buf, 3, &source, &sums, seed, ChecksumType::Md5)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, Some(3));

        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };
        let result = recv_file_delta(&mut cursor, &basis, blength, seed, ChecksumType::Md5)
            .await
            .unwrap();

        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_checksum_verification_failure() {
        let source = b"test data";
        let seed = 42;

        // Build valid tokens but corrupt the checksum (no sum head in manual construction).
        let mut buf = Vec::new();
        crate::protocol::varint::write_int(&mut buf, 0)
            .await
            .unwrap();
        token::send_data(&mut buf, source).await.unwrap();
        token::send_eof(&mut buf).await.unwrap();
        let digest_len = ChecksumType::Md5.digest_len();
        buf.extend_from_slice(&vec![0xFF; digest_len]);

        let mut cursor = Cursor::new(&buf);
        let _ = recv_file_index(&mut cursor).await.unwrap();

        let result = recv_file_delta(&mut cursor, b"", 700, seed, ChecksumType::Md5).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProtocolError::ChecksumMismatch { .. }),
            "expected ChecksumMismatch, got {err:?}",
        );
    }

    #[tokio::test]
    async fn test_recv_done_signal() {
        let mut buf = Vec::new();
        crate::protocol::varint::write_int(&mut buf, -1)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, None);
    }
}
