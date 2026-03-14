//! Generator role: computes block signatures for basis files.
//!
//! The generator examines the receiver's existing files and computes block
//! checksums that the sender can use to identify matching regions.

use tokio::io::AsyncWrite;

use crate::delta::sum::{self, SumStruct};
use crate::error::ProtocolError;
use crate::protocol::handshake::ChecksumType;
use crate::protocol::varint;

type Result<T> = std::result::Result<T, ProtocolError>;

/// Compute block signatures for a basis file and send them over the wire.
///
/// Wire format: file_index (i32) + sum_head + block signatures.
/// Sends file_index = -1 to signal no more files.
pub async fn send_file_signatures<W: AsyncWrite + Unpin>(
    w: &mut W,
    file_index: i32,
    basis_data: &[u8],
    seed: i32,
    checksum_type: ChecksumType,
) -> Result<()> {
    // Write file index.
    varint::write_int(w, file_index).await?;

    // Compute and send signatures.
    let sums = sum::compute_signatures(basis_data, seed, checksum_type);
    sum::write_sums(w, &sums).await?;

    Ok(())
}

/// Signal end of generator output (no more files to transfer).
pub async fn send_generator_done<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    varint::write_int(w, -1).await
}

/// Read a file index from the generator stream.
///
/// Returns `None` if the generator is done (file_index == -1).
pub async fn recv_file_index<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Option<i32>> {
    let idx = varint::read_int(r).await?;
    if idx == -1 {
        Ok(None)
    } else {
        Ok(Some(idx))
    }
}

/// Read block signatures from the generator stream.
pub async fn recv_file_signatures<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<SumStruct> {
    sum::read_sums(r).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_send_recv_signatures() {
        let basis = vec![0xABu8; 3000];
        let seed = 42;
        let checksum_type = ChecksumType::Md5;

        let mut buf = Vec::new();
        send_file_signatures(&mut buf, 0, &basis, seed, checksum_type)
            .await
            .unwrap();
        send_generator_done(&mut buf).await.unwrap();

        let mut cursor = Cursor::new(&buf);

        // Read file index.
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, Some(0));

        // Read signatures.
        let sums = recv_file_signatures(&mut cursor).await.unwrap();
        assert!(sums.head.count > 0);

        // Read done marker.
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, None);
    }

    #[tokio::test]
    async fn test_empty_basis() {
        let mut buf = Vec::new();
        send_file_signatures(&mut buf, 5, b"", 0, ChecksumType::Md5)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let idx = recv_file_index(&mut cursor).await.unwrap();
        assert_eq!(idx, Some(5));

        let sums = recv_file_signatures(&mut cursor).await.unwrap();
        assert_eq!(sums.head.count, 0);
    }
}
