//! Algorithm-agnostic diff operations.
//!
//! These types decouple delta computation from the rsync wire protocol.
//! Instead of block indices (which assume fixed-size blocks), operations
//! reference basis data by byte offset and length, supporting fixed-block,
//! CDC, and arbitrary byte-range delta algorithms.

use std::borrow::Cow;

/// A reference to a contiguous region of the basis file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasisRef {
    /// Byte offset in the basis file.
    pub offset: u64,
    /// Length of this region in bytes.
    pub length: u32,
}

impl BasisRef {
    /// Recover the rsync block index for wire encoding.
    ///
    /// Only valid for fixed-block-size signatures where every block
    /// (except possibly the last) has the same length.
    pub fn block_index(&self, blength: u32) -> i32 {
        debug_assert!(blength > 0);
        debug_assert!(
            self.offset.is_multiple_of(blength as u64),
            "BasisRef offset {} is not aligned to blength {}",
            self.offset,
            blength
        );
        (self.offset / blength as u64) as i32
    }
}

/// Algorithm-agnostic diff operation.
///
/// Uses `Cow<[u8]>` for literal data so the same type works for both
/// borrowing (batch path) and owning (streaming path). Streaming sites
/// use `DiffOp<'static>` with `Cow::Owned`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp<'a> {
    /// Literal data from the source not present in the basis.
    Literal(Cow<'a, [u8]>),
    /// Copy a region from the basis file.
    Copy(BasisRef),
}

impl<'a> DiffOp<'a> {
    /// Create a literal op borrowing a slice (zero-copy batch path).
    pub fn literal(data: &'a [u8]) -> Self {
        Self::Literal(Cow::Borrowed(data))
    }

    /// Create a literal op owning data (streaming path).
    pub fn literal_owned(data: Vec<u8>) -> Self {
        Self::Literal(Cow::Owned(data))
    }

    /// Create a copy op referencing a basis region.
    pub fn copy(bref: BasisRef) -> Self {
        Self::Copy(bref)
    }
}

/// Reconstruct a file by applying diff operations against a basis.
pub fn apply_diffops(basis: &[u8], ops: &[DiffOp<'_>]) -> Vec<u8> {
    let mut output = Vec::new();
    for op in ops {
        match op {
            DiffOp::Literal(data) => {
                output.extend_from_slice(data);
            }
            DiffOp::Copy(bref) => {
                let offset = bref.offset as usize;
                let end = (offset + bref.length as usize).min(basis.len());
                if offset < basis.len() {
                    output.extend_from_slice(&basis[offset..end]);
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basis_ref_block_index() {
        let bref = BasisRef {
            offset: 2100,
            length: 700,
        };
        assert_eq!(bref.block_index(700), 3);
    }

    #[test]
    fn test_apply_diffops_literal_only() {
        let ops = vec![DiffOp::literal(b"hello world")];
        assert_eq!(apply_diffops(b"", &ops), b"hello world");
    }

    #[test]
    fn test_apply_diffops_copy_only() {
        let basis = b"abcdefghij";
        let ops = vec![DiffOp::Copy(BasisRef {
            offset: 3,
            length: 4,
        })];
        assert_eq!(apply_diffops(basis, &ops), b"defg");
    }

    #[test]
    fn test_apply_diffops_mixed() {
        let basis = b"ABCDEF";
        let ops = vec![
            DiffOp::literal(b">>"),
            DiffOp::Copy(BasisRef {
                offset: 2,
                length: 3,
            }),
            DiffOp::literal(b"<<"),
        ];
        assert_eq!(apply_diffops(basis, &ops), b">>CDE<<");
    }

    #[test]
    fn test_apply_diffops_owned() {
        let basis = b"ABCDEF";
        let ops: Vec<DiffOp<'static>> = vec![
            DiffOp::literal_owned(b">>".to_vec()),
            DiffOp::Copy(BasisRef {
                offset: 0,
                length: 2,
            }),
        ];
        assert_eq!(apply_diffops(basis, &ops), b">>AB");
    }

    #[test]
    fn test_apply_diffops_copy_beyond_basis() {
        let basis = b"AB";
        let ops = vec![DiffOp::Copy(BasisRef {
            offset: 10,
            length: 5,
        })];
        // Offset beyond basis -- no data copied.
        assert_eq!(apply_diffops(basis, &ops), b"");
    }

    #[test]
    fn test_apply_diffops_copy_partial() {
        let basis = b"ABCD";
        let ops = vec![DiffOp::Copy(BasisRef {
            offset: 2,
            length: 10,
        })];
        // Length extends beyond basis -- clamped.
        assert_eq!(apply_diffops(basis, &ops), b"CD");
    }
}
