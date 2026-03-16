//! Variable-length integer encoding for the rsync wire protocol.
//!
//! Rsync uses multiple integer encoding schemes depending on protocol version
//! and context:
//!
//! - **Fixed-width:** `read_int`/`write_int` (4 bytes LE), `read_shortint`/
//!   `write_shortint` (2 bytes LE), `read_longint`/`write_longint` (4 or 12 bytes).
//! - **Compact varint (proto >= 30):** `read_varint`/`write_varint` (1-5 bytes),
//!   `read_varlong`/`write_varlong` (variable, 64-bit).
//! - **NDX index (proto >= 30):** Delta-encoded file list indices.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::protocol::wire_format::IntCodec;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// Lookup table for prefix-coded varint
// ---------------------------------------------------------------------------

/// Maps `first_byte / 4` to the number of extra bytes that follow.
const INT_BYTE_EXTRA: [u8; 64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00-0x3F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x40-0x7F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x80-0xBF
    2, 2, 2, 2, 2, 2, 2, 2, // 0xC0-0xDF
    3, 3, 3, 3, // 0xE0-0xEF
    4, 4, // 0xF0-0xF7
    5, // 0xF8-0xFB
    6, // 0xFC-0xFF
];

// ---------------------------------------------------------------------------
// Fixed-width: 2-byte little-endian (shortint)
// ---------------------------------------------------------------------------

/// Read a 2-byte little-endian unsigned integer.
pub async fn read_shortint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).await?;
    Ok(u16::from_le_bytes(buf))
}

/// Write a 2-byte little-endian unsigned integer.
pub async fn write_shortint<W: AsyncWrite + Unpin>(w: &mut W, val: u16) -> Result<()> {
    w.write_all(&val.to_le_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed-width: 4-byte little-endian (int)
// ---------------------------------------------------------------------------

/// Read a 4-byte little-endian signed integer.
pub(crate) async fn read_int<R: AsyncRead + Unpin>(r: &mut R) -> Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await?;
    Ok(i32::from_le_bytes(buf))
}

/// Write a 4-byte little-endian signed integer.
pub(crate) async fn write_int<W: AsyncWrite + Unpin>(w: &mut W, val: i32) -> Result<()> {
    w.write_all(&val.to_le_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed-width with sentinel: longint (4 or 12 bytes)
// ---------------------------------------------------------------------------

/// Read a 64-bit integer: 4 bytes if it fits in i32, otherwise a 0xFFFFFFFF
/// sentinel followed by 8 bytes little-endian.
pub(crate) async fn read_longint<R: AsyncRead + Unpin>(r: &mut R) -> Result<i64> {
    let val = read_int(r).await?;
    if val != -1 {
        // Not the sentinel -- value fits in 32 bits.
        return Ok(val as i64);
    }
    // Sentinel: read the full 64-bit value.
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf).await?;
    Ok(i64::from_le_bytes(buf))
}

/// Write a 64-bit integer: 4 bytes if it fits in 0..=0x7FFFFFFF, otherwise
/// the 0xFFFFFFFF sentinel + 8 bytes.
pub(crate) async fn write_longint<W: AsyncWrite + Unpin>(w: &mut W, val: i64) -> Result<()> {
    if (0..=0x7FFF_FFFF_i64).contains(&val) {
        write_int(w, val as i32).await
    } else {
        write_int(w, -1).await?;
        w.write_all(&val.to_le_bytes()).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Compact varint (protocol >= 30): 1-4 bytes for values up to 0x0FFFFFFF
// ---------------------------------------------------------------------------

/// Read a compact variable-length 32-bit integer (protocol >= 30).
///
/// The first byte's high bits encode the number of extra bytes via the
/// `INT_BYTE_EXTRA` lookup table. Supports the full u32 range (1-5 bytes).
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32> {
    let mut ch = [0u8; 1];
    r.read_exact(&mut ch).await?;
    let ch = ch[0];

    let extra = INT_BYTE_EXTRA[(ch / 4) as usize] as usize;
    if extra == 0 {
        return Ok(ch as u32);
    }

    // rsync's varint encoding supports extra=4 (total 5 wire bytes). When
    // extra=4, the first byte is always 0xF0 and the masked data bits are 0,
    // so the 4 extra bytes contain the complete 32-bit value. Only reject
    // extra > 4 (values 0xF8+ which would need > 32 data bits).
    if extra > 4 {
        return Err(ProtocolError::InvalidVarint);
    }

    let mut b = [0u8; 4];
    r.read_exact(&mut b[..extra]).await?;

    if extra < 4 {
        // The data bits from the first byte go into the highest position.
        let bit = 1u8 << (7 - extra + 1);
        b[extra] = ch & (bit - 1);
    }
    // When extra=4, all 4 bytes already contain the full u32 value.
    // The first byte (0xF0-0xF7) carries no additional data bits for
    // valid varints (max 28-bit values), so we skip the assignment.

    Ok(u32::from_le_bytes(b))
}

/// Write a compact variable-length 32-bit integer (protocol >= 30).
///
/// Encodes any u32 value in 1-5 bytes using prefix-coded variable length.
pub(crate) async fn write_varint<W: AsyncWrite + Unpin>(w: &mut W, x: u32) -> Result<()> {
    let mut b = [0u8; 5]; // b[0] = prefix byte, b[1..4] = LE value bytes
    let le = x.to_le_bytes();
    b[1] = le[0];
    b[2] = le[1];
    b[3] = le[2];
    b[4] = le[3];

    // Find the highest non-zero byte (counting from b[4] down to b[1]).
    let mut cnt: usize = 4;
    while cnt > 1 && b[cnt] == 0 {
        cnt -= 1;
    }
    // cnt is now the index (in b[]) of the highest non-zero byte, minimum 1.

    // Determine the prefix bit threshold.
    let bit = 1u8 << (7 - cnt + 1);

    if b[cnt] >= bit {
        // The high data byte doesn't fit under the prefix -- need one more byte.
        cnt += 1;
        b[0] = !(bit - 1); // prefix mask: all bits above threshold set
    } else if cnt > 1 {
        // Merge the high data byte into the prefix.
        b[0] = b[cnt] | !(bit * 2 - 1);
    } else {
        // Single byte: value < 128.
        b[0] = b[1];
        w.write_all(&b[..1]).await?;
        return Ok(());
    }

    // Write b[0] (prefix) followed by b[1..cnt-1] (lower data bytes).
    w.write_all(&b[..cnt]).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Compact varlong (protocol >= 30): variable bytes for i64
// ---------------------------------------------------------------------------

/// Read a compact variable-length 64-bit integer (protocol >= 30).
///
/// `min_bytes` specifies the minimum number of bytes on the wire (typically 3
/// for file sizes).
pub(crate) async fn read_varlong<R: AsyncRead + Unpin>(r: &mut R, min_bytes: usize) -> Result<i64> {
    debug_assert!((1..=8).contains(&min_bytes));

    let mut b = [0u8; 8];
    r.read_exact(&mut b[..min_bytes]).await?;

    let first = b[0];
    let extra = INT_BYTE_EXTRA[(first / 4) as usize] as usize;

    // Shift the raw data bytes down: b[0..min_bytes-2] contain the lower bytes.
    // b[0] is the prefix byte -- the data starts at b[1] in the wire stream,
    // but we already read into b[0..min_bytes-1].
    // Re-arrange: move b[1..min_bytes-1] to b[0..min_bytes-2], leaving room
    // for the extra bytes and the masked first byte.
    let mut result = [0u8; 8];
    result[..min_bytes - 1].copy_from_slice(&b[1..min_bytes]);

    if extra > 0 {
        let extra_start = min_bytes - 1;
        if extra_start + extra >= 8 {
            return Err(ProtocolError::InvalidVarint);
        }
        r.read_exact(&mut result[extra_start..extra_start + extra])
            .await?;

        let bit = 1u8 << (7 - extra + 1);
        result[extra_start + extra] = first & (bit - 1);
    } else {
        result[min_bytes - 1] = first;
    }

    Ok(i64::from_le_bytes(result))
}

/// Write a compact variable-length 64-bit integer (protocol >= 30).
///
/// `min_bytes` specifies the minimum number of bytes on the wire.
pub(crate) async fn write_varlong<W: AsyncWrite + Unpin>(
    w: &mut W,
    x: i64,
    min_bytes: usize,
) -> Result<()> {
    debug_assert!((1..=8).contains(&min_bytes));

    let le = x.to_le_bytes();
    // b[0] will be the prefix byte; b[1..9] hold the LE value.
    let mut b = [0u8; 9];
    b[1..9].copy_from_slice(&le);

    // Find the highest non-zero byte, minimum at position min_bytes.
    let mut cnt = 8;
    while cnt > min_bytes && b[cnt] == 0 {
        cnt -= 1;
    }

    let bit = 1u8 << (7 - (cnt - min_bytes));

    if b[cnt] >= bit {
        cnt += 1;
        b[0] = !(bit - 1);
    } else if cnt > min_bytes {
        b[0] = b[cnt] | !(bit * 2 - 1);
        b[cnt] = 0;
    } else {
        b[0] = b[min_bytes];
        b[min_bytes] = 0;
    }

    // Wire: prefix byte, then the lower (cnt-1) data bytes.
    // Repack into contiguous buffer: [b[0], b[1], ..., b[cnt-1]]
    w.write_all(&b[..cnt]).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Version-switching wrappers
// ---------------------------------------------------------------------------

/// Read a 32-bit integer using compact varint for `Compact` codec, fixed 4
/// bytes for `Fixed`.
pub(crate) async fn read_varint30<R: AsyncRead + Unpin>(r: &mut R, codec: IntCodec) -> Result<u32> {
    match codec {
        IntCodec::Fixed => Ok(read_int(r).await? as u32),
        IntCodec::Compact => read_varint(r).await,
    }
}

/// Write a 32-bit integer using compact varint for `Compact` codec, fixed 4
/// bytes for `Fixed`.
pub(crate) async fn write_varint30<W: AsyncWrite + Unpin>(
    w: &mut W,
    val: u32,
    codec: IntCodec,
) -> Result<()> {
    match codec {
        IntCodec::Fixed => write_int(w, val as i32).await,
        IntCodec::Compact => write_varint(w, val).await,
    }
}

/// Read a 64-bit integer using compact varlong for `Compact` codec,
/// sentinel-based longint for `Fixed`.
pub(crate) async fn read_varlong30<R: AsyncRead + Unpin>(
    r: &mut R,
    min_bytes: usize,
    codec: IntCodec,
) -> Result<i64> {
    match codec {
        IntCodec::Fixed => read_longint(r).await,
        IntCodec::Compact => read_varlong(r, min_bytes).await,
    }
}

/// Write a 64-bit integer using compact varlong for `Compact` codec,
/// sentinel-based longint for `Fixed`.
pub(crate) async fn write_varlong30<W: AsyncWrite + Unpin>(
    w: &mut W,
    val: i64,
    min_bytes: usize,
    codec: IntCodec,
) -> Result<()> {
    match codec {
        IntCodec::Fixed => write_longint(w, val).await,
        IntCodec::Compact => write_varlong(w, val, min_bytes).await,
    }
}

// ---------------------------------------------------------------------------
// NDX (file list index) encoding (protocol >= 30)
// ---------------------------------------------------------------------------

/// Mutable state for delta-encoded file list index reading.
#[derive(Debug, Clone)]
pub struct NdxState {
    pub prev_positive: i32,
    pub prev_negative: i32,
}

impl Default for NdxState {
    fn default() -> Self {
        Self {
            prev_positive: -1,
            prev_negative: 1,
        }
    }
}

/// Sentinel value indicating end of file list index stream.
pub const NDX_DONE: i32 = -1;

/// Read a delta-encoded file list index (protocol >= 30).
///
/// For `Fixed` codec, falls back to `read_int`.
pub async fn read_ndx<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &mut NdxState,
    codec: IntCodec,
) -> Result<i32> {
    if codec == IntCodec::Fixed {
        return read_int(r).await;
    }

    let mut b = [0u8; 1];
    r.read_exact(&mut b).await?;
    let mut val = b[0];

    if val == 0 {
        return Ok(NDX_DONE);
    }

    let is_negative = val == 0xFF;
    if is_negative {
        r.read_exact(&mut b).await?;
        val = b[0];
    }

    let prev = if is_negative {
        &mut state.prev_negative
    } else {
        &mut state.prev_positive
    };

    let ndx = if val == 0xFE {
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).await?;
        if buf[0] & 0x80 != 0 {
            // 4-byte absolute encoding.
            let mut buf2 = [0u8; 2];
            r.read_exact(&mut buf2).await?;
            ((buf[0] as i32 & 0x7F) << 24)
                | ((buf2[1] as i32) << 16)
                | ((buf2[0] as i32) << 8)
                | (buf[1] as i32)
        } else {
            // 2-byte big-endian delta.
            let diff = ((buf[0] as i32) << 8) | (buf[1] as i32);
            *prev + diff
        }
    } else {
        // 1-byte delta.
        *prev + val as i32
    };

    *prev = ndx;
    if is_negative {
        Ok(-ndx)
    } else {
        Ok(ndx)
    }
}

/// Write a delta-encoded file list index (protocol >= 30).
///
/// For `Fixed` codec, falls back to `write_int`.
pub async fn write_ndx<W: AsyncWrite + Unpin>(
    w: &mut W,
    ndx: i32,
    state: &mut NdxState,
    codec: IntCodec,
) -> Result<()> {
    if codec == IntCodec::Fixed {
        return write_int(w, ndx).await;
    }

    if ndx == NDX_DONE {
        w.write_all(&[0x00]).await?;
        return Ok(());
    }

    let (is_negative, abs_ndx) = if ndx < 0 { (true, -ndx) } else { (false, ndx) };

    if is_negative {
        w.write_all(&[0xFF]).await?;
    }

    let prev = if is_negative {
        &mut state.prev_negative
    } else {
        &mut state.prev_positive
    };

    let diff = abs_ndx - *prev;
    *prev = abs_ndx;

    if diff > 0 && diff < 0xFE {
        // 1-byte delta.
        w.write_all(&[diff as u8]).await?;
    } else if (0..=0x7FFF).contains(&diff) {
        // 3-byte: 0xFE + 2-byte big-endian delta.
        let buf = [0xFE, (diff >> 8) as u8, (diff & 0xFF) as u8];
        w.write_all(&buf).await?;
    } else {
        // 5-byte: 0xFE + 4-byte absolute with high bit set.
        let buf = [
            0xFE,
            ((abs_ndx >> 24) as u8) | 0x80,
            (abs_ndx & 0xFF) as u8,
            ((abs_ndx >> 8) & 0xFF) as u8,
            ((abs_ndx >> 16) & 0xFF) as u8,
        ];
        w.write_all(&buf).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Read a single byte
// ---------------------------------------------------------------------------

/// Read a single byte from the stream.
pub(crate) async fn read_byte<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).await?;
    Ok(buf[0])
}

/// Write a single byte to the stream.
pub(crate) async fn write_byte<W: AsyncWrite + Unpin>(w: &mut W, val: u8) -> Result<()> {
    w.write_all(&[val]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Helper: encode then decode, verify round-trip.
    macro_rules! roundtrip_test {
        ($write_fn:ident, $read_fn:ident, $val:expr) => {{
            let mut buf = Vec::new();
            $write_fn(&mut buf, $val).await.unwrap();
            let mut cursor = Cursor::new(&buf);
            let result = $read_fn(&mut cursor).await.unwrap();
            assert_eq!(result, $val, "roundtrip failed for value {:?}", $val);
            buf.len()
        }};
    }

    #[tokio::test]
    async fn test_shortint_roundtrip() {
        for val in [0u16, 1, 127, 128, 255, 256, 0x7FFF, 0xFFFF] {
            roundtrip_test!(write_shortint, read_shortint, val);
        }
    }

    #[tokio::test]
    async fn test_shortint_wire_format() {
        let mut buf = Vec::new();
        write_shortint(&mut buf, 0x0102).await.unwrap();
        assert_eq!(buf, &[0x02, 0x01]); // little-endian
    }

    #[tokio::test]
    async fn test_int_roundtrip() {
        for val in [0i32, 1, -1, 127, 128, 0x7FFF_FFFF, -0x7FFF_FFFF] {
            roundtrip_test!(write_int, read_int, val);
        }
    }

    #[tokio::test]
    async fn test_int_wire_format() {
        let mut buf = Vec::new();
        write_int(&mut buf, 0x12345678).await.unwrap();
        assert_eq!(buf, &[0x78, 0x56, 0x34, 0x12]); // little-endian
    }

    #[tokio::test]
    async fn test_longint_short_form() {
        // Values that fit in 31 bits use 4 bytes.
        let mut buf = Vec::new();
        write_longint(&mut buf, 42).await.unwrap();
        assert_eq!(buf.len(), 4);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_longint(&mut cursor).await.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_longint_long_form() {
        // Values > 0x7FFFFFFF use 12 bytes (sentinel + 8 bytes).
        let val = 0x1_0000_0000_i64;
        let mut buf = Vec::new();
        write_longint(&mut buf, val).await.unwrap();
        assert_eq!(buf.len(), 12);
        assert_eq!(&buf[..4], &[0xFF, 0xFF, 0xFF, 0xFF]); // sentinel

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_longint(&mut cursor).await.unwrap(), val);
    }

    #[tokio::test]
    async fn test_longint_negative() {
        let val = -100_i64;
        let mut buf = Vec::new();
        write_longint(&mut buf, val).await.unwrap();
        // Negative values don't fit in 0..=0x7FFFFFFF, so they use long form.
        assert_eq!(buf.len(), 12);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_longint(&mut cursor).await.unwrap(), val);
    }

    #[tokio::test]
    async fn test_varint_single_byte() {
        // Values 0-127 use a single byte.
        for val in [0u32, 1, 63, 64, 127] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).await.unwrap();
            assert_eq!(buf.len(), 1, "value {val} should be 1 byte");
            assert_eq!(buf[0], val as u8);

            let mut cursor = Cursor::new(&buf);
            assert_eq!(read_varint(&mut cursor).await.unwrap(), val);
        }
    }

    #[tokio::test]
    async fn test_varint_roundtrip() {
        // Varint supports values up to 0x0FFFFFFF (28 bits).
        let test_values = [
            0u32,
            1,
            127,
            128,
            255,
            256,
            1000,
            16383,
            16384,
            0xFFFF,
            0x1_0000,
            0xFF_FFFF,
            0xFFF_FFFF,
            0x0FFF_FFFF,
        ];
        for val in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).await.unwrap();
            let mut cursor = Cursor::new(&buf);
            let decoded = read_varint(&mut cursor).await.unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
        }
    }

    #[tokio::test]
    async fn test_varint_full_range() {
        // All u32 values should encode and decode correctly.
        let cases: &[u32] = &[0x1000_0000, 0x354b_43ea, 0xFFFF_FFFF];
        for &val in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).await.unwrap();
            assert_eq!(buf.len(), 5, "value {val:#x} should use 5 bytes");
            let mut cursor = Cursor::new(&buf);
            assert_eq!(read_varint(&mut cursor).await.unwrap(), val);
        }
    }

    #[tokio::test]
    async fn test_varint_encoding_size() {
        // Verify expected sizes for different ranges.
        let cases: &[(u32, usize)] = &[(0, 1), (127, 1), (128, 2), (16383, 2), (0x0FFF_FFFF, 4)];
        for &(val, expected_size) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, val).await.unwrap();
            assert_eq!(
                buf.len(),
                expected_size,
                "value {val:#x} expected {expected_size} bytes, got {}",
                buf.len()
            );
        }
    }

    #[tokio::test]
    async fn test_varint30_fixed_codec() {
        // Fixed codec: always 4 bytes.
        let mut buf = Vec::new();
        write_varint30(&mut buf, 42, IntCodec::Fixed).await.unwrap();
        assert_eq!(buf.len(), 4);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_varint30(&mut cursor, IntCodec::Fixed).await.unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn test_varint30_compact_codec() {
        // Compact codec: compact encoding.
        let mut buf = Vec::new();
        write_varint30(&mut buf, 42, IntCodec::Compact)
            .await
            .unwrap();
        assert_eq!(buf.len(), 1);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_varint30(&mut cursor, IntCodec::Compact).await.unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn test_ndx_done() {
        let mut state_w = NdxState::default();
        let mut state_r = NdxState::default();

        let mut buf = Vec::new();
        write_ndx(&mut buf, NDX_DONE, &mut state_w, IntCodec::Compact)
            .await
            .unwrap();
        assert_eq!(buf, &[0x00]);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_ndx(&mut cursor, &mut state_r, IntCodec::Compact)
                .await
                .unwrap(),
            NDX_DONE
        );
    }

    #[tokio::test]
    async fn test_ndx_sequential_positive() {
        // Ascending indices should use 1-byte deltas.
        let mut state_w = NdxState::default();
        let mut state_r = NdxState::default();

        let indices = [0, 1, 2, 3, 100, 200];
        let mut buf = Vec::new();
        for &ndx in &indices {
            write_ndx(&mut buf, ndx, &mut state_w, IntCodec::Compact)
                .await
                .unwrap();
        }

        let mut cursor = Cursor::new(&buf);
        for &expected in &indices {
            let got = read_ndx(&mut cursor, &mut state_r, IntCodec::Compact)
                .await
                .unwrap();
            assert_eq!(got, expected, "ndx mismatch");
        }
    }

    #[tokio::test]
    async fn test_ndx_negative() {
        let mut state_w = NdxState::default();
        let mut state_r = NdxState::default();

        let mut buf = Vec::new();
        write_ndx(&mut buf, -5, &mut state_w, IntCodec::Compact)
            .await
            .unwrap();
        assert_eq!(buf[0], 0xFF); // negative prefix

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_ndx(&mut cursor, &mut state_r, IntCodec::Compact)
                .await
                .unwrap(),
            -5
        );
    }

    #[tokio::test]
    async fn test_ndx_large_jump() {
        let mut state_w = NdxState::default();
        let mut state_r = NdxState::default();

        // First write index 0, then jump to a large value.
        let mut buf = Vec::new();
        write_ndx(&mut buf, 0, &mut state_w, IntCodec::Compact)
            .await
            .unwrap();
        write_ndx(&mut buf, 100_000, &mut state_w, IntCodec::Compact)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_ndx(&mut cursor, &mut state_r, IntCodec::Compact)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            read_ndx(&mut cursor, &mut state_r, IntCodec::Compact)
                .await
                .unwrap(),
            100_000
        );
    }

    #[tokio::test]
    async fn test_ndx_fixed_codec() {
        // Fixed codec: falls back to read_int/write_int.
        let mut state_w = NdxState::default();
        let mut state_r = NdxState::default();

        let mut buf = Vec::new();
        write_ndx(&mut buf, 42, &mut state_w, IntCodec::Fixed)
            .await
            .unwrap();
        assert_eq!(buf.len(), 4); // fixed 4-byte encoding

        let mut cursor = Cursor::new(&buf);
        assert_eq!(
            read_ndx(&mut cursor, &mut state_r, IntCodec::Fixed)
                .await
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn test_byte_roundtrip() {
        let mut buf = Vec::new();
        write_byte(&mut buf, 0xAB).await.unwrap();
        assert_eq!(buf, &[0xAB]);

        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_byte(&mut cursor).await.unwrap(), 0xAB);
    }

    // -----------------------------------------------------------------------
    // Truncated / malformed input tests (#54)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_read_shortint_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_shortint(&mut cursor).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_shortint_truncated_one_byte() {
        let mut cursor = Cursor::new(&[0x42]);
        let result = read_shortint(&mut cursor).await;
        assert!(result.is_err(), "1 byte for shortint should return error");
    }

    #[tokio::test]
    async fn test_read_int_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_int(&mut cursor).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_int_truncated_partial() {
        let mut cursor = Cursor::new(&[0x01, 0x02]);
        let result = read_int(&mut cursor).await;
        assert!(result.is_err(), "2 bytes for int should return error");
    }

    #[tokio::test]
    async fn test_read_longint_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_longint(&mut cursor).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_longint_truncated_sentinel_no_payload() {
        // Sentinel bytes (0xFFFFFFFF) with no 8-byte payload following.
        let mut cursor = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let result = read_longint(&mut cursor).await;
        assert!(
            result.is_err(),
            "sentinel with no payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_longint_truncated_sentinel_partial_payload() {
        // Sentinel followed by only 4 bytes instead of 8.
        let mut cursor = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04]);
        let result = read_longint(&mut cursor).await;
        assert!(
            result.is_err(),
            "sentinel with partial payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_varint_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_varint(&mut cursor).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_varint_truncated_multibyte() {
        // 0x80 prefix means 1 extra byte needed, but none provided.
        let mut cursor = Cursor::new(&[0x80]);
        let result = read_varint(&mut cursor).await;
        assert!(result.is_err(), "truncated varint should return error");
    }

    #[tokio::test]
    async fn test_read_varint_malformed_too_many_extra_bytes() {
        // 0xF8 prefix byte => INT_BYTE_EXTRA[(0xF8/4)] = INT_BYTE_EXTRA[62] = 5
        // extra=5 > 4, should return InvalidVarint.
        let mut cursor = Cursor::new(&[0xF8, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let result = read_varint(&mut cursor).await;
        assert!(result.is_err(), "varint with extra > 4 should return error");
    }

    #[tokio::test]
    async fn test_read_varint_malformed_0xfc() {
        // 0xFC prefix byte => INT_BYTE_EXTRA[(0xFC/4)] = INT_BYTE_EXTRA[63] = 6
        // extra=6 > 4, should return InvalidVarint.
        let mut cursor = Cursor::new(&[0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let result = read_varint(&mut cursor).await;
        assert!(
            result.is_err(),
            "varint with 0xFC prefix should return error"
        );
    }

    #[tokio::test]
    async fn test_read_varlong_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_varlong(&mut cursor, 3).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_varlong_truncated_partial_min_bytes() {
        // min_bytes=3 but only 2 bytes provided.
        let mut cursor = Cursor::new(&[0x00, 0x00]);
        let result = read_varlong(&mut cursor, 3).await;
        assert!(result.is_err(), "partial min_bytes should return error");
    }

    #[tokio::test]
    async fn test_read_varlong_truncated_extra_bytes_missing() {
        // min_bytes=3, first byte 0x80 => extra=1, but no extra byte provided.
        let mut cursor = Cursor::new(&[0x80, 0x00, 0x00]);
        let result = read_varlong(&mut cursor, 3).await;
        assert!(
            result.is_err(),
            "varlong with missing extra bytes should return error"
        );
    }

    #[tokio::test]
    async fn test_read_byte_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let result = read_byte(&mut cursor).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_ndx_truncated_empty() {
        let mut cursor = Cursor::new(&[] as &[u8]);
        let mut state = NdxState::default();
        let result = read_ndx(&mut cursor, &mut state, IntCodec::Compact).await;
        assert!(result.is_err(), "empty input should return error");
    }

    #[tokio::test]
    async fn test_read_ndx_truncated_negative_prefix_no_value() {
        // 0xFF prefix (negative marker) with no following byte.
        let mut cursor = Cursor::new(&[0xFF]);
        let mut state = NdxState::default();
        let result = read_ndx(&mut cursor, &mut state, IntCodec::Compact).await;
        assert!(
            result.is_err(),
            "negative prefix with no value should return error"
        );
    }

    #[tokio::test]
    async fn test_read_ndx_truncated_fe_prefix_no_payload() {
        // 0xFE prefix means 2-byte or 4-byte absolute/delta encoding follows.
        let mut cursor = Cursor::new(&[0xFE]);
        let mut state = NdxState::default();
        let result = read_ndx(&mut cursor, &mut state, IntCodec::Compact).await;
        assert!(
            result.is_err(),
            "0xFE prefix with no payload should return error"
        );
    }

    #[tokio::test]
    async fn test_read_ndx_truncated_fe_4byte_incomplete() {
        // 0xFE, then 2 bytes with high bit set (4-byte encoding), but missing last 2 bytes.
        let mut cursor = Cursor::new(&[0xFE, 0x80, 0x00]);
        let mut state = NdxState::default();
        let result = read_ndx(&mut cursor, &mut state, IntCodec::Compact).await;
        assert!(
            result.is_err(),
            "4-byte ndx with missing bytes should return error"
        );
    }
}
