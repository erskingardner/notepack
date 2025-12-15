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
/// Returns the number of bytes written.
///
/// # Panics
///
/// Panics if `value` is too large to shift left (i.e., `value >= 2^63`).
#[inline]
pub fn write_tagged_varint(buf: &mut Vec<u8>, value: u64, tagged: bool) -> usize {
    let tagged = value
        .checked_shl(1)
        .expect("value too large for tagged varint")
        | (tagged as u64);
    write_varint(buf, tagged)
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
/// Returns the number of bytes written.
#[inline]
pub fn write_tagged_varint_to<W: Write>(w: &mut W, value: u64, tagged: bool) -> std::io::Result<usize> {
    let tagged = value
        .checked_shl(1)
        .expect("value too large for tagged varint")
        | (tagged as u64);
    write_varint_to(w, tagged)
}
