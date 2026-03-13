//! Transfer pipeline orchestration.
//!
//! Connects the generator, sender, and receiver roles into a complete
//! file transfer pipeline using tokio tasks and in-memory byte pipes.

use tokio::io::AsyncWriteExt;

use crate::delta::sum;
use crate::error::ProtocolError;
use crate::protocol::handshake::ChecksumType;

use super::generator;
use super::receiver;
use super::sender;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Transfer a single file through the complete generator -> sender -> receiver
/// pipeline.
///
/// - `source_data`: The file data on the sender side.
/// - `basis_data`: The existing file data on the receiver side (empty if new).
/// - `seed`: Checksum seed from protocol negotiation.
/// - `checksum_type`: MD4 or MD5.
///
/// Returns the reconstructed file data on the receiver side.
pub async fn transfer_file(
    source_data: &[u8],
    basis_data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<Vec<u8>> {
    // Generator -> Sender pipe (carries block signatures).
    let (gen_write, gen_read) = tokio::io::duplex(64 * 1024);
    // Sender -> Receiver pipe (carries delta tokens).
    let (send_write, send_read) = tokio::io::duplex(64 * 1024);

    let gen_seed = seed;
    let gen_ct = checksum_type;
    let basis_owned = basis_data.to_vec();
    let source_owned = source_data.to_vec();

    // Generator task: compute signatures from basis, write to gen_write.
    let gen_handle = tokio::spawn(async move {
        let mut w = gen_write;
        let result = generator::send_file_signatures(
            &mut w, 0, &basis_owned, gen_seed, gen_ct,
        )
        .await;
        if let Err(e) = &result {
            tracing::error!("generator error: {e}");
        }
        generator::send_generator_done(&mut w).await.ok();
        w.shutdown().await.ok();
        result
    });

    // Sender task: read signatures from gen_read, match against source,
    // write tokens to send_write.
    let send_seed = seed;
    let send_ct = checksum_type;
    let send_handle = tokio::spawn(async move {
        let mut r = gen_read;
        let mut w = send_write;

        let result = async {
            let idx = generator::recv_file_index(&mut r).await?;
            if idx.is_none() {
                sender::send_sender_done(&mut w).await?;
                return Ok(());
            }

            sender::send_file_delta(
                &mut r,
                &mut w,
                0,
                &source_owned,
                send_seed,
                send_ct,
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

    // Receiver: read tokens from send_read, reconstruct file.
    let recv_basis = basis_data.to_vec();
    let recv_seed = seed;
    let recv_ct = checksum_type;
    let recv_handle = tokio::spawn(async move {
        let mut r = send_read;

        let idx = receiver::recv_file_index(&mut r).await?;
        if idx.is_none() {
            return Ok(Vec::new());
        }

        // Compute block length from basis to know how to interpret block refs.
        let sums = sum::compute_signatures(&recv_basis, recv_seed, recv_ct);
        let blength = if sums.head.blength > 0 {
            sums.head.blength as usize
        } else {
            700
        };

        receiver::recv_file_delta(&mut r, &recv_basis, blength, recv_seed, recv_ct).await
    });

    // Wait for all tasks.
    let (gen_result, send_result, recv_result) =
        tokio::try_join!(gen_handle, send_handle, recv_handle)
            .map_err(|e| ProtocolError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    gen_result?;
    send_result?;
    recv_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transfer_new_file() {
        let source = b"Hello, world! This is a brand new file.";
        let result = transfer_file(source, b"", 42, ChecksumType::Md5)
            .await
            .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_identical_file() {
        let data = vec![0xABu8; 5000];
        let result = transfer_file(&data, &data, 99, ChecksumType::Md5)
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
        // Modify a few bytes.
        source[5000] = 0xFF;
        source[5001] = 0xFE;
        source[5002] = 0xFD;

        let result = transfer_file(&source, &basis, 7, ChecksumType::Md5)
            .await
            .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_completely_different() {
        let basis = vec![0u8; 5000];
        let source = vec![0xFFu8; 5000];
        let result = transfer_file(&source, &basis, 0, ChecksumType::Md5)
            .await
            .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_with_md4() {
        let source = b"Testing MD4 checksum path";
        let result = transfer_file(source, b"", 123, ChecksumType::Md4)
            .await
            .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_large_file() {
        // ~100KB file to test chunking.
        let mut data = Vec::with_capacity(100_000);
        for i in 0..100_000 {
            data.push((i * 37 % 256) as u8);
        }
        let result = transfer_file(&data, b"", 55, ChecksumType::Md5)
            .await
            .unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_transfer_appended_data() {
        let basis = vec![42u8; 5000];
        let mut source = basis.clone();
        source.extend_from_slice(&[0xBB; 1000]); // append data

        let result = transfer_file(&source, &basis, 10, ChecksumType::Md5)
            .await
            .unwrap();
        assert_eq!(result, source);
    }

    #[tokio::test]
    async fn test_transfer_empty_to_empty() {
        let result = transfer_file(b"", b"", 0, ChecksumType::Md5)
            .await
            .unwrap();
        assert!(result.is_empty());
    }
}
