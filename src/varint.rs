//! LEB128-style variable-length integer encoding.
//!
//! This module provides functions for reading and writing varints in the
//! notepack binary format. Values are encoded using 7 bits per byte, with
//! the high bit indicating continuation.

use crate::Error;
use std::io::Write;

/// Encode a `u64` as an LEB128 varint, appending bytes to `buf`.
///
/// Returns the number of bytes written (1–10 depending on magnitude).
#[inline]
pub fn write_varint(buf: &mut Vec<u8>, mut n: u64) -> usize {
    let mut len = 0;
    loop {
        let mut b = (n & 0x7F) as u8; // low 7 bits
        n >>= 7;
        if n != 0 {
            b |= 0x80; // continuation
        }
        buf.push(b);
        len += 1;
        if n == 0 {
            break;
        }
    }
    len
}

/// Decode an LEB128 varint from `input`, advancing the slice past the consumed bytes.
///
/// # Errors
///
/// - [`Error::VarintOverflow`] if the varint exceeds 64 bits.
/// - [`Error::VarintUnterminated`] if the input ends mid-varint.
#[inline]
pub fn read_varint(input: &mut &[u8]) -> Result<u64, Error> {
    let mut n = 0u64;
    let mut shift = 0u32;

    for i in 0..input.len() {
        let b = input[i];
        let chunk = (b & 0x7F) as u64;
        n |= chunk << shift;

        if b & 0x80 == 0 {
            *input = &input[i + 1..]; // advance the slice handle
            return Ok(n);
        }

        shift += 7;
        if shift >= 64 {
            return Err(Error::VarintOverflow);
        }
    }
    Err(Error::VarintUnterminated)
}

/// Decode a tagged varint: the low bit indicates type, upper bits hold the value.
///
/// Returns `(value, is_bytes)` where `is_bytes` is `true` if the tag bit was set.
/// Used for tag element strings to distinguish UTF-8 text from raw bytes.
#[inline]
pub fn read_tagged_varint(input: &mut &[u8]) -> Result<(u64, bool), Error> {
    let raw = read_varint(input)?;
    Ok((raw >> 1, (raw & 1) != 0))
}

/// Encode a tagged varint: shifts `value` left by 1 and sets the low bit if `tagged`.
///
/// Returns the number of bytes written, or an error if the value is too large.
///
/// # Errors
///
/// Returns [`Error::TaggedVarintOverflow`] if `value >= 2^63` (cannot be shifted left).
#[inline]
pub fn write_tagged_varint(buf: &mut Vec<u8>, value: u64, tagged: bool) -> Result<usize, Error> {
    let shifted = value
        .checked_shl(1)
        .ok_or(Error::TaggedVarintOverflow)?;
    // Also check that the high bit wasn't set (which would wrap to 0)
    if value >= (1u64 << 63) {
        return Err(Error::TaggedVarintOverflow);
    }
    let tagged_value = shifted | (tagged as u64);
    Ok(write_varint(buf, tagged_value))
}

/// Write a varint to any [`Write`] implementor.
///
/// Returns the number of bytes written.
#[inline]
pub fn write_varint_to<W: Write>(w: &mut W, mut n: u64) -> std::io::Result<usize> {
    let mut len = 0;
    loop {
        let mut b = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        w.write_all(&[b])?;
        len += 1;
        if n == 0 {
            break;
        }
    }
    Ok(len)
}

/// Write a tagged varint to any [`Write`] implementor.
///
/// Returns the number of bytes written, or an error if the value is too large or I/O fails.
///
/// # Errors
///
/// Returns [`Error::TaggedVarintOverflow`] if `value >= 2^63`.
/// Returns [`Error::Io`] if writing fails.
#[inline]
pub fn write_tagged_varint_to<W: Write>(
    w: &mut W,
    value: u64,
    tagged: bool,
) -> Result<usize, Error> {
    let shifted = value
        .checked_shl(1)
        .ok_or(Error::TaggedVarintOverflow)?;
    // Also check that the high bit wasn't set (which would wrap to 0)
    if value >= (1u64 << 63) {
        return Err(Error::TaggedVarintOverflow);
    }
    let tagged_value = shifted | (tagged as u64);
    Ok(write_varint_to(w, tagged_value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // ─────────────────────────────────────────────────────────────────────────────
    // write_varint / read_varint roundtrip tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn varint_roundtrip_zero() {
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 0);
        assert_eq!(written, 1);
        assert_eq!(buf, [0x00]);

        let mut slice = buf.as_slice();
        let val = read_varint(&mut slice).unwrap();
        assert_eq!(val, 0);
        assert!(slice.is_empty());
    }

    #[test]
    fn varint_roundtrip_one() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1);
        assert_eq!(buf, [0x01]);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 1);
    }

    #[test]
    fn varint_roundtrip_127() {
        // 127 = 0x7F, fits in one byte (no continuation)
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 127);
        assert_eq!(written, 1);
        assert_eq!(buf, [0x7F]);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 127);
    }

    #[test]
    fn varint_roundtrip_128() {
        // 128 = 0x80, requires 2 bytes: 0x80 0x01
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 128);
        assert_eq!(written, 2);
        assert_eq!(buf, [0x80, 0x01]);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 128);
    }

    #[test]
    fn varint_roundtrip_16383() {
        // 16383 = 0x3FFF, max 2-byte value
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 16383);
        assert_eq!(written, 2);
        assert_eq!(buf, [0xFF, 0x7F]);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 16383);
    }

    #[test]
    fn varint_roundtrip_16384() {
        // 16384 = 0x4000, requires 3 bytes
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 16384);
        assert_eq!(written, 3);
        assert_eq!(buf, [0x80, 0x80, 0x01]);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 16384);
    }

    #[test]
    fn varint_roundtrip_large_value() {
        // Test a large timestamp-like value: 1720000000
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, 1720000000);
        assert_eq!(written, 5);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 1720000000);
    }

    #[test]
    fn varint_roundtrip_u64_max() {
        let mut buf = Vec::new();
        let written = write_varint(&mut buf, u64::MAX);
        assert_eq!(written, 10); // u64::MAX requires 10 bytes

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), u64::MAX);
    }

    #[test]
    fn varint_roundtrip_powers_of_two() {
        for exp in 0..64 {
            let val = 1u64 << exp;
            let mut buf = Vec::new();
            write_varint(&mut buf, val);

            let mut slice = buf.as_slice();
            assert_eq!(read_varint(&mut slice).unwrap(), val, "failed for 2^{exp}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // read_varint error tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn varint_unterminated_empty_input() {
        let mut slice: &[u8] = &[];
        let err = read_varint(&mut slice).unwrap_err();
        assert!(matches!(err, Error::VarintUnterminated));
    }

    #[test]
    fn varint_unterminated_continuation_at_end() {
        // Continuation bit set but no more bytes
        let mut slice: &[u8] = &[0x80];
        let err = read_varint(&mut slice).unwrap_err();
        assert!(matches!(err, Error::VarintUnterminated));
    }

    #[test]
    fn varint_unterminated_multiple_continuations() {
        // All continuation bits, never terminates
        let mut slice: &[u8] = &[0x80, 0x80, 0x80];
        let err = read_varint(&mut slice).unwrap_err();
        assert!(matches!(err, Error::VarintUnterminated));
    }

    #[test]
    fn varint_overflow_too_many_bytes() {
        // 10 bytes with continuation bits would overflow u64
        // After 9 bytes we've consumed 63 bits, 10th byte would push shift to 70
        let mut slice: &[u8] = &[0x80; 11]; // 11 continuation bytes
        let err = read_varint(&mut slice).unwrap_err();
        assert!(matches!(err, Error::VarintOverflow));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Multiple varints in sequence
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn varint_read_multiple_sequential() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1);
        write_varint(&mut buf, 300);
        write_varint(&mut buf, 0);
        write_varint(&mut buf, u64::MAX);

        let mut slice = buf.as_slice();
        assert_eq!(read_varint(&mut slice).unwrap(), 1);
        assert_eq!(read_varint(&mut slice).unwrap(), 300);
        assert_eq!(read_varint(&mut slice).unwrap(), 0);
        assert_eq!(read_varint(&mut slice).unwrap(), u64::MAX);
        assert!(slice.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Tagged varint tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn tagged_varint_roundtrip_untagged() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 42, false).unwrap();

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, 42);
        assert!(!is_bytes);
    }

    #[test]
    fn tagged_varint_roundtrip_tagged() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 42, true).unwrap();

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, 42);
        assert!(is_bytes);
    }

    #[test]
    fn tagged_varint_zero_untagged() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 0, false).unwrap();
        assert_eq!(buf, [0x00]); // (0 << 1) | 0 = 0

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, 0);
        assert!(!is_bytes);
    }

    #[test]
    fn tagged_varint_zero_tagged() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 0, true).unwrap();
        assert_eq!(buf, [0x01]); // (0 << 1) | 1 = 1

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, 0);
        assert!(is_bytes);
    }

    #[test]
    fn tagged_varint_large_value() {
        // 32 is common (pubkey length), tagged
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 32, true).unwrap();
        // (32 << 1) | 1 = 65 = 0x41
        assert_eq!(buf, [0x41]);

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, 32);
        assert!(is_bytes);
    }

    #[test]
    fn tagged_varint_max_safe_value() {
        // Maximum value that can be shifted left by 1: (2^63 - 1)
        let max_safe = (1u64 << 63) - 1;
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, max_safe, true).unwrap();

        let mut slice = buf.as_slice();
        let (val, is_bytes) = read_tagged_varint(&mut slice).unwrap();
        assert_eq!(val, max_safe);
        assert!(is_bytes);
    }

    #[test]
    fn tagged_varint_overflow_returns_error() {
        // Values >= 2^63 should return an error, not panic or wrap
        let mut buf = Vec::new();
        let result = write_tagged_varint(&mut buf, 1u64 << 63, false);
        assert!(matches!(result, Err(Error::TaggedVarintOverflow)));

        // u64::MAX should also error
        let result = write_tagged_varint(&mut buf, u64::MAX, true);
        assert!(matches!(result, Err(Error::TaggedVarintOverflow)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Writer variant tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn write_varint_to_matches_buffer_version() {
        for val in [0, 1, 127, 128, 16383, 16384, 1720000000, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);

            let mut writer_buf = Vec::new();
            let written = write_varint_to(&mut writer_buf, val).unwrap();

            assert_eq!(buf, writer_buf, "mismatch for value {val}");
            assert_eq!(written, buf.len());
        }
    }

    #[test]
    fn write_tagged_varint_to_matches_buffer_version() {
        for val in [0, 1, 32, 64, 1000] {
            for tagged in [false, true] {
                let mut buf = Vec::new();
                write_tagged_varint(&mut buf, val, tagged).unwrap();

                let mut writer_buf = Vec::new();
                let written = write_tagged_varint_to(&mut writer_buf, val, tagged).unwrap();

                assert_eq!(buf, writer_buf, "mismatch for value {val}, tagged={tagged}");
                assert_eq!(written, buf.len());
            }
        }
    }

    #[test]
    fn write_tagged_varint_to_overflow_returns_error() {
        let mut buf = Vec::new();
        let result = write_tagged_varint_to(&mut buf, 1u64 << 63, false);
        assert!(matches!(result, Err(Error::TaggedVarintOverflow)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Byte-level encoding verification
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn varint_encoding_matches_spec() {
        // From SPEC.md: 1720000000 encodes as 80 bc 94 b4 06
        let mut buf = Vec::new();
        write_varint(&mut buf, 1720000000);
        assert_eq!(buf, [0x80, 0xbc, 0x94, 0xb4, 0x06]);
    }
}
