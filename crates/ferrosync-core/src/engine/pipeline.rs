//! Transfer pipeline orchestration.
//!
//! Connects the generator, sender, and receiver roles into a complete
//! file transfer pipeline using tokio tasks and in-memory byte pipes.

use tokio::io::AsyncWriteExt;

use crate::delta::sum;
use crate::delta::ProtocolContext;
use crate::error::ProtocolError;
use crate::protocol::compress::{Compressor, Decompressor};

use super::generator;
use super::receiver;
use super::sender;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Transfer a single file through the complete generator -> sender -> receiver
/// pipeline.
///
/// - `source_data`: The file data on the sender side.
/// - `basis_data`: The existing file data on the receiver side (empty if new).
/// - `ctx`: Protocol context with seed, checksum type, and other parameters.
///
/// Returns the reconstructed file data on the receiver side.
pub async fn transfer_file(
    source_data: &[u8],
    basis_data: &[u8],
    ctx: &ProtocolContext,
) -> Result<Vec<u8>> {
    // Generator -> Sender pipe (carries block signatures).
    let (gen_write, gen_read) = tokio::io::duplex(64 * 1024);
    // Sender -> Receiver pipe (carries delta tokens).
    let (send_write, send_read) = tokio::io::duplex(64 * 1024);

    let ctx = *ctx;
    let basis_owned = basis_data.to_vec();
    let source_owned = source_data.to_vec();

    // Generator task: compute signatures from basis, write to gen_write.
    let gen_handle = tokio::spawn(async move {
        let mut w = gen_write;
        let result = generator::send_file_signatures(&mut w, 0, &basis_owned, &ctx).await;
        if let Err(e) = &result {
            tracing::error!("generator error: {e}");
        }
        generator::send_generator_done(&mut w).await.ok();
        w.shutdown().await.ok();
        result
    });

    // Sender task: read signatures from gen_read, match against source,
    // write tokens to send_write.
    let send_handle = tokio::spawn(async move {
        let mut r = gen_read;
        let mut w = send_write;

        let result = async {
            let idx = generator::recv_file_index(&mut r).await?;
            if idx.is_none() {
                sender::send_sender_done(&mut w).await?;
                return Ok(());
            }

            sender::send_file_delta(&mut r, &mut w, 0, &source_owned, &ctx).await?;

            sender::send_sender_done(&mut w).await?;
            Ok::<(), ProtocolError>(())
        }
        .await;

        if let Err(e) = &result {
            tracing::error!("sender error: {e}");
        }
        w.shutdown().await.ok();
        result
    });

    // Receiver: read tokens from send_read, reconstruct file.
    let recv_basis = basis_data.to_vec();
    let recv_handle = tokio::spawn(async move {
        let mut r = send_read;

        let idx = receiver::recv_file_index(&mut r).await?;
        if idx.is_none() {
            return Ok(Vec::new());
        }

        // Compute block length from basis (receiver already knows the params).
        let sums = sum::compute_signatures(&recv_basis, &ctx);
        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };

        receiver::recv_file_delta(&mut r, &recv_basis, blength, &ctx).await
    });

    // Wait for all tasks.
    let (gen_result, send_result, recv_result) =
        tokio::try_join!(gen_handle, send_handle, recv_handle)
            .map_err(|e| ProtocolError::Io(std::sync::Arc::new(std::io::Error::other(e))))?;

    gen_result?;
    send_result?;
    recv_result
}

/// Transfer a single file with compression on the sender->receiver channel.
///
/// Same as [`transfer_file`] but compresses delta tokens with the given
/// compression level (1-9).
pub async fn transfer_file_compressed(
    source_data: &[u8],
    basis_data: &[u8],
    ctx: &ProtocolContext,
    compress_level: u32,
) -> Result<Vec<u8>> {
    let (gen_write, gen_read) = tokio::io::duplex(64 * 1024);
    let (send_write, send_read) = tokio::io::duplex(64 * 1024);

    let ctx = *ctx;
    let basis_owned = basis_data.to_vec();
    let source_owned = source_data.to_vec();

    let gen_handle = tokio::spawn(async move {
        let mut w = gen_write;
        let result = generator::send_file_signatures(&mut w, 0, &basis_owned, &ctx).await;
        if let Err(e) = &result {
            tracing::error!("generator error: {e}");
        }
        generator::send_generator_done(&mut w).await.ok();
        w.shutdown().await.ok();
        result
    });

    let send_handle = tokio::spawn(async move {
        let mut r = gen_read;
        let mut w = send_write;
        let mut compressor = Compressor::new(compress_level);

        let result = async {
            let idx = generator::recv_file_index(&mut r).await?;
            if idx.is_none() {
                sender::send_sender_done(&mut w).await?;
                return Ok(());
            }

            sender::send_file_delta_compressed(
                &mut r,
                &mut w,
                0,
                &source_owned,
                &ctx,
                &mut compressor,
            )
            .await?;

            sender::send_sender_done(&mut w).await?;
            Ok::<(), ProtocolError>(())
        }
        .await;

        if let Err(e) = &result {
            tracing::error!("sender error: {e}");
        }
        w.shutdown().await.ok();
        result
    });

    let recv_basis = basis_data.to_vec();
    let recv_handle = tokio::spawn(async move {
        let mut r = send_read;
        let mut decompressor = Decompressor::new();

        let idx = receiver::recv_file_index(&mut r).await?;
        if idx.is_none() {
            return Ok(Vec::new());
        }

        // Compute block length from basis (receiver already knows the params).
        let sums = sum::compute_signatures(&recv_basis, &ctx);
        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };

        receiver::recv_file_delta_compressed(&mut r, &recv_basis, blength, &ctx, &mut decompressor)
            .await
    });

    let (gen_result, send_result, recv_result) =
        tokio::try_join!(gen_handle, send_handle, recv_handle)
            .map_err(|e| ProtocolError::Io(std::sync::Arc::new(std::io::Error::other(e))))?;

    gen_result?;
    send_result?;
    recv_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake::ChecksumType;

    #[tokio::test]
    async fn test_transfer_new_file() {
        let source = b"Hello, world! This is a brand new file.";
        let result = transfer_file(
            source,
            b"",
            &ProtocolContext::test_default(42, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_identical_file() {
        let data = vec![0xABu8; 5000];
        let result = transfer_file(
            &data,
            &data,
            &ProtocolContext::test_default(99, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_transfer_modified_file() {
        let mut basis = Vec::new();
        for i in 0..10000 {
            basis.push((i % 256) as u8);
        }
        let mut source = basis.clone();
        source[5000] = 0xFF;
        source[5001] = 0xFE;
        source[5002] = 0xFD;

        let result = transfer_file(
            &source,
            &basis,
            &ProtocolContext::test_default(7, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_completely_different() {
        let basis = vec![0u8; 5000];
        let source = vec![0xFFu8; 5000];
        let result = transfer_file(
            &source,
            &basis,
            &ProtocolContext::test_default(0, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_with_md4() {
        let source = b"Testing MD4 checksum path";
        let result = transfer_file(
            source,
            b"",
            &ProtocolContext::test_default(123, ChecksumType::Md4),
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_large_file() {
        let mut data = Vec::with_capacity(100_000);
        for i in 0..100_000 {
            data.push((i * 37 % 256) as u8);
        }
        let result = transfer_file(
            &data,
            b"",
            &ProtocolContext::test_default(55, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_transfer_appended_data() {
        let basis = vec![42u8; 5000];
        let mut source = basis.clone();
        source.extend_from_slice(&[0xBB; 1000]);

        let result = transfer_file(
            &source,
            &basis,
            &ProtocolContext::test_default(10, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_compressed_new_file() {
        let source = b"Hello, world! This is a brand new file with some data.";
        let result = transfer_file_compressed(
            source,
            b"",
            &ProtocolContext::test_default(42, ChecksumType::Md5),
            6,
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_compressed_modified_file() {
        let mut basis = Vec::new();
        for i in 0..10000 {
            basis.push((i % 256) as u8);
        }
        let mut source = basis.clone();
        source[5000] = 0xFF;
        source[5001] = 0xFE;

        let result = transfer_file_compressed(
            &source,
            &basis,
            &ProtocolContext::test_default(7, ChecksumType::Md5),
            6,
        )
        .await
        .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_compressed_identical() {
        let data = vec![0xABu8; 5000];
        let result = transfer_file_compressed(
            &data,
            &data,
            &ProtocolContext::test_default(99, ChecksumType::Md5),
            6,
        )
        .await
        .unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_transfer_empty_to_empty() {
        let result = transfer_file(
            b"",
            b"",
            &ProtocolContext::test_default(0, ChecksumType::Md5),
        )
        .await
        .unwrap();
        assert!(result.is_empty());
    }
}
