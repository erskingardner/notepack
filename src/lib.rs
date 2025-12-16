//! # notepack
//!
//! A Rust library for packing and parsing [nostr](https://github.com/nostr-protocol/nostr) notes
//! into a compact binary format called **notepack**.
//!
//! This crate provides two core capabilities:
//!
//! - **Encoding**: Turn a [`Note`] (a structured Nostr event) into a notepack binary, or a Base64
//!   string prefixed with `notepack_`.
//! - **Decoding / Streaming Parsing**: Efficiently stream through a binary notepack payload using
//!   [`NoteParser`], yielding fields as they are parsed (without needing to fully deserialize).
//!
//! ## Features
//!
//! - **Compact binary format** using varint encoding for integers.
//! - **Streaming parser**: no allocation-heavy parsing; fields are yielded one by one as they’re read.
//!
//! ## Example: Encoding a Note
//!
//! ```rust
//! use notepack::{NoteBuf, pack_note_to_string};
//!
//! let note = NoteBuf {
//!     id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
//!     pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
//!     created_at: 1753898766,
//!     kind: 1,
//!     tags: vec![vec!["tag".into(), "value".into()]],
//!     content: "Hello, world!".into(),
//!     sig: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
//! };
//!
//! let packed = pack_note_to_string(&note).unwrap();
//! println!("{packed}");
//! // prints something like `notepack_AAECA...`
//! ```
//!
//! ## Example: Streaming Parse
//!
//! ```rust
//! use notepack::{NoteParser, ParsedField};
//!
//! let b64 = "notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw";
//! let bytes = NoteParser::decode(b64).unwrap();
//! let parser = NoteParser::new(&bytes);
//!
//! for field in parser {
//!     match field.unwrap() {
//!         ParsedField::Id(id) => println!("id: {}", hex_simd::encode_to_string(id, hex_simd::AsciiCase::Lower)),
//!         ParsedField::Content(c) => println!("content: {}", c),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Binary Tool
//!
//! This crate also ships with a small CLI called `notepack` (see `main.rs`):
//!
//! - **Pipe in a JSON Nostr event** → outputs a `notepack_...` string.
//! - **Pipe in a `notepack_...` string** → outputs the JSON representation.
//!
//! ```bash
//! echo '{"id":"...","pubkey":"...","created_at":123,"kind":1,"tags":[],"content":"Hi","sig":"..."}' \
//!   | notepack
//! ```
//!
//! ## Modules
//!
//! - [`Note`] — main event struct used for encoding.
//! - [`NoteParser`] — streaming parser for notepack binaries.
//! - [`ParsedField`] — enum of parsed fields yielded by the parser.
//! - [`Error`] — unified error type.
//! - [`StringType`] — distinguishes between raw byte tags and UTF-8 tags.
//!
//! ## Spec
//!
//! The notepack format is loosely inspired by [MessagePack](https://msgpack.org/) but optimized for
//! Nostr notes. Strings that look like 32-byte hex are stored more compactly; integers are encoded
//! as LEB128-style varints; and the format starts with a `version` field for forward compatibility.

mod error;
mod note;
mod parser;
mod stringtype;
mod varint;

pub use error::Error;
pub use note::{Note, NoteBinary, NoteBuf, TagElems, Tags};
pub use parser::{MAX_ALLOCATION_SIZE, NoteParser, ParsedField, ParserState, SUPPORTED_VERSION};
pub use stringtype::StringType;

use std::io::Write;
use varint::{write_tagged_varint, write_tagged_varint_to, write_varint, write_varint_to};

// ─────────────────────────────────────────────────────────────────────────────
// Hex encoding/decoding lookup tables for performance
// ─────────────────────────────────────────────────────────────────────────────

/// Lookup table for decoding lowercase hex nibbles.
/// Invalid bytes (non-hex or uppercase) map to 0xFF.
const HEX_DECODE_LUT: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    t[b'0' as usize] = 0;
    t[b'1' as usize] = 1;
    t[b'2' as usize] = 2;
    t[b'3' as usize] = 3;
    t[b'4' as usize] = 4;
    t[b'5' as usize] = 5;
    t[b'6' as usize] = 6;
    t[b'7' as usize] = 7;
    t[b'8' as usize] = 8;
    t[b'9' as usize] = 9;
    t[b'a' as usize] = 10;
    t[b'b' as usize] = 11;
    t[b'c' as usize] = 12;
    t[b'd' as usize] = 13;
    t[b'e' as usize] = 14;
    t[b'f' as usize] = 15;
    // Note: A-F intentionally NOT mapped - we only accept lowercase for round-trip stability
    t
};

/// Packs a [`NoteBuf`] into an existing buffer, appending the binary payload.
///
/// This is the streaming/zero-alloc encoding API. It appends the notepack binary
/// directly to the provided buffer, allowing callers to reuse allocations.
///
/// Returns the number of bytes written, or an [`Error`] if encoding fails.
///
/// # Errors
///
/// - [`Error::FromHex`] if any hex string field fails to decode.
/// - [`Error::InvalidFieldLength`] if `id`, `pubkey`, or `sig` have wrong sizes.
/// - [`Error::TaggedVarintOverflow`] if a tag element is too large.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteBuf, pack_note_into};
///
/// let note = NoteBuf {
///     id: "00".repeat(32),
///     pubkey: "11".repeat(32),
///     sig: "22".repeat(64),
///     ..Default::default()
/// };
/// let mut buf = Vec::with_capacity(256);
/// let len = pack_note_into(&note, &mut buf).unwrap();
/// assert_eq!(len, buf.len());
/// ```
pub fn pack_note_into(note: &NoteBuf, buf: &mut Vec<u8>) -> Result<usize, Error> {
    let start_len = buf.len();

    // version
    write_varint(buf, 1);

    // id - must be exactly 32 bytes
    let id_bytes = hex_simd::decode_to_vec(&note.id)?;
    if id_bytes.len() != 32 {
        return Err(Error::InvalidFieldLength {
            field: "id",
            expected: 32,
            actual: id_bytes.len(),
        });
    }
    buf.extend_from_slice(&id_bytes);

    // pubkey - must be exactly 32 bytes
    let pk_bytes = hex_simd::decode_to_vec(&note.pubkey)?;
    if pk_bytes.len() != 32 {
        return Err(Error::InvalidFieldLength {
            field: "pubkey",
            expected: 32,
            actual: pk_bytes.len(),
        });
    }
    buf.extend_from_slice(&pk_bytes);

    // signature - must be exactly 64 bytes
    let sig_bytes = hex_simd::decode_to_vec(&note.sig)?;
    if sig_bytes.len() != 64 {
        return Err(Error::InvalidFieldLength {
            field: "sig",
            expected: 64,
            actual: sig_bytes.len(),
        });
    }
    buf.extend_from_slice(&sig_bytes);

    write_varint(buf, note.created_at);
    write_varint(buf, note.kind);
    write_varint(buf, note.content.len() as u64);
    buf.extend_from_slice(note.content.as_bytes());

    write_varint(buf, note.tags.len() as u64);

    for tag in &note.tags {
        write_varint(buf, tag.len() as u64);

        for elem in tag {
            write_string(buf, elem.as_str())?;
        }
    }

    Ok(buf.len() - start_len)
}

/// Packs a [`NoteBuf`] into its compact binary notepack representation.
///
/// This function serializes a [`NoteBuf`] into the raw notepack binary format:
/// - Adds version (currently `1`) as a varint.
/// - Encodes fixed-size fields (`id`, `pubkey`, `sig`) as raw bytes.
/// - Writes variable-length fields (`content`, `tags`) with varint length prefixes.
/// - Optimizes strings that look like 32-byte hex by storing them in a compressed form.
///
/// Returns a `Vec<u8>` containing the binary payload, or an [`Error`] if encoding fails.
///
/// For buffer reuse, see [`pack_note_into`] which appends to an existing buffer.
///
/// # Errors
///
/// - [`Error::FromHex`] if any hex string field fails to decode.
/// - [`Error::InvalidFieldLength`] if `id`, `pubkey`, or `sig` have wrong sizes.
/// - [`Error::TaggedVarintOverflow`] if a tag element is too large.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteBuf, pack_note};
///
/// let note = NoteBuf {
///     id: "00".repeat(32),
///     pubkey: "11".repeat(32),
///     sig: "22".repeat(64),
///     ..Default::default()
/// };
/// let binary = pack_note(&note).unwrap();
/// assert!(binary.len() > 0);
/// ```
pub fn pack_note(note: &NoteBuf) -> Result<Vec<u8>, Error> {
    // Pre-allocate: version(1) + id(32) + pubkey(32) + sig(64) + content + estimated tags
    let tags_estimate: usize = note
        .tags
        .iter()
        .map(|tag| {
            // 1 byte for num_elems varint + sum of element lengths + 1 byte per elem for tagged varint
            1 + tag.iter().map(|e| e.len() + 1).sum::<usize>()
        })
        .sum();
    let mut buf = Vec::with_capacity(150 + note.content.len() + tags_estimate);
    pack_note_into(note, &mut buf)?;
    Ok(buf)
}

/// Packs a [`NoteBuf`] to any [`Write`] implementor (files, sockets, compression streams, etc.).
///
/// This is the streaming encoding API for I/O. It writes the notepack binary directly
/// to the provided writer without intermediate buffering.
///
/// Returns the number of bytes written, or an [`Error`] if encoding or I/O fails.
///
/// # Errors
///
/// - [`Error::FromHex`] if any hex string field fails to decode.
/// - [`Error::InvalidFieldLength`] if `id`, `pubkey`, or `sig` have wrong sizes.
/// - [`Error::TaggedVarintOverflow`] if a tag element is too large.
/// - [`Error::Io`] if writing to the writer fails.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteBuf, pack_note_to_writer};
///
/// let note = NoteBuf {
///     id: "00".repeat(32),
///     pubkey: "11".repeat(32),
///     sig: "22".repeat(64),
///     ..Default::default()
/// };
/// let mut output = Vec::new();
/// let len = pack_note_to_writer(&note, &mut output).unwrap();
/// assert_eq!(len, output.len());
/// ```
///
/// Writing to a file:
///
/// ```no_run
/// use notepack::{NoteBuf, pack_note_to_writer};
/// use std::fs::File;
///
/// let note = NoteBuf {
///     id: "00".repeat(32),
///     pubkey: "11".repeat(32),
///     sig: "22".repeat(64),
///     ..Default::default()
/// };
/// let mut file = File::create("note.bin").unwrap();
/// pack_note_to_writer(&note, &mut file).unwrap();
/// ```
pub fn pack_note_to_writer<W: Write>(note: &NoteBuf, w: &mut W) -> Result<usize, Error> {
    let mut len = 0;

    // version
    len += write_varint_to(w, 1)?;

    // id - must be exactly 32 bytes
    let id_bytes = hex_simd::decode_to_vec(&note.id)?;
    if id_bytes.len() != 32 {
        return Err(Error::InvalidFieldLength {
            field: "id",
            expected: 32,
            actual: id_bytes.len(),
        });
    }
    w.write_all(&id_bytes)?;
    len += id_bytes.len();

    // pubkey - must be exactly 32 bytes
    let pk_bytes = hex_simd::decode_to_vec(&note.pubkey)?;
    if pk_bytes.len() != 32 {
        return Err(Error::InvalidFieldLength {
            field: "pubkey",
            expected: 32,
            actual: pk_bytes.len(),
        });
    }
    w.write_all(&pk_bytes)?;
    len += pk_bytes.len();

    // signature - must be exactly 64 bytes
    let sig_bytes = hex_simd::decode_to_vec(&note.sig)?;
    if sig_bytes.len() != 64 {
        return Err(Error::InvalidFieldLength {
            field: "sig",
            expected: 64,
            actual: sig_bytes.len(),
        });
    }
    w.write_all(&sig_bytes)?;
    len += sig_bytes.len();

    len += write_varint_to(w, note.created_at)?;
    len += write_varint_to(w, note.kind)?;
    len += write_varint_to(w, note.content.len() as u64)?;
    w.write_all(note.content.as_bytes())?;
    len += note.content.len();

    len += write_varint_to(w, note.tags.len() as u64)?;

    for tag in &note.tags {
        len += write_varint_to(w, tag.len() as u64)?;

        for elem in tag {
            len += write_string_to(w, elem.as_str())?;
        }
    }

    Ok(len)
}

/// Encodes a [`Note`] directly to a `notepack_...` Base64 string.
///
/// This is a convenience wrapper around [`pack_note`], taking the binary payload and
/// Base64-encoding it (without padding) and prefixing with `notepack_`.
///
/// This is the primary API for exporting notes for storage, transmission, or embedding in JSON.
///
/// # Errors
///
/// Returns the same [`Error`]s as [`pack_note`], e.g. hex decoding issues.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteBuf, pack_note_to_string};
///
/// let note = NoteBuf {
///     id: "00".repeat(32),
///     pubkey: "11".repeat(32),
///     sig: "22".repeat(64),
///     ..Default::default()
/// };
/// let s = pack_note_to_string(&note).unwrap();
/// assert!(s.starts_with("notepack_"));
/// ```
pub fn pack_note_to_string(note: &NoteBuf) -> Result<String, Error> {
    let bytes = pack_note(note)?;
    Ok(format!("notepack_{}", base64_encode(&bytes)))
}

/// Encode bytes as Base64 (RFC 4648, no padding).
fn base64_encode(bs: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

    STANDARD_NO_PAD.encode(bs)
}

/// Decode a lowercase hex string to bytes.
///
/// Only lowercase hex is accepted to ensure round-trip encoding works correctly.
/// Uppercase hex or odd-length strings return an error.
#[cfg(test)]
fn decode_lowercase_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = input.as_bytes();

    // Reject odd-length hex strings
    if !bytes.len().is_multiple_of(2) {
        return Err("odd length");
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = HEX_DECODE_LUT[bytes[i] as usize];
        let lo = HEX_DECODE_LUT[bytes[i + 1] as usize];

        // 0xFF indicates invalid hex character
        if (hi | lo) > 0x0F {
            return Err("invalid hex");
        }

        out.push((hi << 4) | lo);
    }

    Ok(out)
}

/// Write a tag element string to a buffer.
///
/// If the string is valid lowercase hex, it's compacted to raw bytes (tagged=true).
/// Otherwise, it's written as UTF-8 text (tagged=false).
fn write_string(buf: &mut Vec<u8>, string: &str) -> Result<(), Error> {
    if string.is_empty() {
        write_tagged_varint(buf, 0, false)?;
        return Ok(());
    }

    if !try_write_compacted_hex(buf, string)? {
        write_tagged_varint(buf, string.len() as u64, false)?;
        buf.extend_from_slice(string.as_bytes());
    }
    Ok(())
}

/// Attempt to compact a lowercase hex string directly into `buf`.
///
/// This avoids allocating an intermediate `Vec<u8>` for common tag payloads.
/// Returns `Ok(true)` if compacted, `Ok(false)` if not hex, `Err` if varint overflow.
#[inline]
fn try_write_compacted_hex(buf: &mut Vec<u8>, string: &str) -> Result<bool, Error> {
    let s = string.as_bytes();

    // Must be even length for hex
    if !s.len().is_multiple_of(2) {
        return Ok(false);
    }

    let nbytes = s.len() / 2;
    let start = buf.len();

    // Write tagged length prefix first; roll back on validation failure.
    write_tagged_varint(buf, nbytes as u64, true)?;
    buf.reserve(nbytes);

    // Decode using lookup table for faster hex decoding
    for i in 0..nbytes {
        let hi = HEX_DECODE_LUT[s[i * 2] as usize];
        let lo = HEX_DECODE_LUT[s[i * 2 + 1] as usize];

        // Valid nibbles are 0-15; 0xFF indicates invalid hex
        if (hi | lo) > 0x0F {
            buf.truncate(start);
            return Ok(false);
        }

        buf.push((hi << 4) | lo);
    }

    Ok(true)
}

/// Write a tag element string to a [`Write`] implementor.
///
/// Same compaction logic as [`write_string`]: hex strings become raw bytes.
/// Returns the total number of bytes written.
fn write_string_to<W: Write>(w: &mut W, string: &str) -> Result<usize, Error> {
    if string.is_empty() {
        return write_tagged_varint_to(w, 0, false);
    }

    let s = string.as_bytes();

    // Must be even length for hex
    if s.len().is_multiple_of(2) {
        let nbytes = s.len() / 2;

        // Fast paths for the most common sizes (32/64 bytes) without heap allocation.
        if nbytes == 32 {
            let mut out = [0u8; 32];
            if decode_lower_hex_into(s, &mut out) {
                let len = write_tagged_varint_to(w, 32, true)?;
                w.write_all(&out)?;
                return Ok(len + out.len());
            }
        } else if nbytes == 64 {
            let mut out = [0u8; 64];
            if decode_lower_hex_into(s, &mut out) {
                let len = write_tagged_varint_to(w, 64, true)?;
                w.write_all(&out)?;
                return Ok(len + out.len());
            }
        } else {
            let mut out = Vec::with_capacity(nbytes);
            if decode_lower_hex_into_vec(s, &mut out) {
                let len = write_tagged_varint_to(w, nbytes as u64, true)?;
                w.write_all(&out)?;
                return Ok(len + out.len());
            }
        }
    }

    let len = write_tagged_varint_to(w, string.len() as u64, false)?;
    w.write_all(string.as_bytes())?;
    Ok(len + string.len())
}

/// Decode lowercase hex bytes into a fixed-size array using the lookup table.
#[inline]
fn decode_lower_hex_into<const N: usize>(bytes: &[u8], out: &mut [u8; N]) -> bool {
    if bytes.len() != (N * 2) {
        return false;
    }
    for i in 0..N {
        let hi = HEX_DECODE_LUT[bytes[i * 2] as usize];
        let lo = HEX_DECODE_LUT[bytes[i * 2 + 1] as usize];

        // Valid nibbles are 0-15; 0xFF indicates invalid
        if (hi | lo) > 0x0F {
            return false;
        }

        out[i] = (hi << 4) | lo;
    }
    true
}

/// Decode lowercase hex bytes into a Vec using the lookup table.
#[inline]
fn decode_lower_hex_into_vec(bytes: &[u8], out: &mut Vec<u8>) -> bool {
    if !bytes.len().is_multiple_of(2) {
        return false;
    }
    let n = bytes.len() / 2;
    out.clear();
    out.reserve(n);
    for i in 0..n {
        let hi = HEX_DECODE_LUT[bytes[i * 2] as usize];
        let lo = HEX_DECODE_LUT[bytes[i * 2 + 1] as usize];

        // Valid nibbles are 0-15; 0xFF indicates invalid
        if (hi | lo) > 0x0F {
            return false;
        }

        out.push((hi << 4) | lo);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // decode_lowercase_hex tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_lowercase_hex_valid() {
        let result = decode_lowercase_hex("aabbccdd").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn decode_lowercase_hex_empty() {
        let result = decode_lowercase_hex("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_lowercase_hex_32_bytes() {
        let hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = decode_lowercase_hex(hex).unwrap();
        assert_eq!(result.len(), 32);
        assert!(result.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn decode_lowercase_hex_rejects_uppercase() {
        let err = decode_lowercase_hex("AABBCCDD");
        assert!(err.is_err());
    }

    #[test]
    fn decode_lowercase_hex_rejects_mixed_case() {
        let err = decode_lowercase_hex("aaBBccDD");
        assert!(err.is_err());
    }

    #[test]
    fn decode_lowercase_hex_rejects_odd_length() {
        let err = decode_lowercase_hex("aabbc");
        assert!(err.is_err());
    }

    #[test]
    fn decode_lowercase_hex_rejects_invalid_chars() {
        let err = decode_lowercase_hex("gghhiijj");
        assert!(err.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // base64_encode tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8");
    }

    #[test]
    fn base64_encode_no_padding() {
        // "a" normally encodes to "YQ==" with padding
        assert_eq!(base64_encode(b"a"), "YQ");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // pack_note / pack_note_into tests
    // ─────────────────────────────────────────────────────────────────────────────

    fn minimal_note() -> NoteBuf {
        NoteBuf {
            id: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            pubkey: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            sig: "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222".into(),
            created_at: 0,
            kind: 0,
            content: "".into(),
            tags: vec![],
        }
    }

    #[test]
    fn pack_note_minimal() {
        let note = minimal_note();
        let bytes = pack_note(&note).unwrap();

        // version(1) + id(32) + pubkey(32) + sig(64) + created_at(1) + kind(1) + content_len(1) + num_tags(1)
        // = 1 + 32 + 32 + 64 + 1 + 1 + 1 + 1 = 133
        assert_eq!(bytes.len(), 133);

        // Verify version byte
        assert_eq!(bytes[0], 1);
    }

    #[test]
    fn pack_note_into_appends_to_existing() {
        let note = minimal_note();
        let mut buf = vec![0xFF, 0xFF]; // pre-existing data
        let written = pack_note_into(&note, &mut buf).unwrap();

        assert_eq!(written, 133);
        assert_eq!(buf.len(), 135); // 2 + 133
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0xFF);
        assert_eq!(buf[2], 1); // version
    }

    #[test]
    fn pack_note_with_content() {
        let mut note = minimal_note();
        note.content = "hello".into();

        let bytes = pack_note(&note).unwrap();
        // Base 133 + 5 bytes content = 138
        // But content_len varint is still 1 byte for 5
        assert_eq!(bytes.len(), 138);
    }

    #[test]
    fn pack_note_with_tags() {
        let mut note = minimal_note();
        note.tags = vec![
            vec![
                "e".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ],
            vec![
                "p".into(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ],
        ];

        let bytes = pack_note(&note).unwrap();
        assert!(bytes.len() > 133);

        // Decode and verify roundtrip
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        assert_eq!(parsed.tags.len(), 2);
    }

    #[test]
    fn pack_note_invalid_hex_id() {
        let mut note = minimal_note();
        note.id = "not valid hex".into();

        let err = pack_note(&note);
        assert!(err.is_err());
    }

    #[test]
    fn pack_note_invalid_hex_pubkey() {
        let mut note = minimal_note();
        note.pubkey = "UPPERCASE".into();

        let err = pack_note(&note);
        assert!(err.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // pack_note_to_writer tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn pack_note_to_writer_matches_pack_note() {
        let note = minimal_note();

        let bytes = pack_note(&note).unwrap();

        let mut writer_buf = Vec::new();
        let written = pack_note_to_writer(&note, &mut writer_buf).unwrap();

        assert_eq!(bytes, writer_buf);
        assert_eq!(written, bytes.len());
    }

    #[test]
    fn pack_note_to_writer_with_content_and_tags() {
        let mut note = minimal_note();
        note.content = "test content".into();
        note.tags = vec![vec!["t".into(), "tag".into()]];

        let bytes = pack_note(&note).unwrap();

        let mut writer_buf = Vec::new();
        pack_note_to_writer(&note, &mut writer_buf).unwrap();

        assert_eq!(bytes, writer_buf);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // pack_note_to_string tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn pack_note_to_string_has_prefix() {
        let note = minimal_note();
        let s = pack_note_to_string(&note).unwrap();
        assert!(s.starts_with("notepack_"));
    }

    #[test]
    fn pack_note_to_string_valid_base64() {
        let note = minimal_note();
        let s = pack_note_to_string(&note).unwrap();

        // Should decode back successfully
        let decoded = NoteParser::decode(&s).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn pack_note_to_string_no_padding() {
        let note = minimal_note();
        let s = pack_note_to_string(&note).unwrap();

        // Base64 should not have padding characters
        assert!(!s.contains('='));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // write_string tests (hex detection)
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn write_string_empty() {
        let mut buf = Vec::new();
        write_string(&mut buf, "").unwrap();
        // Empty string: tagged_varint(0, false) = 0
        assert_eq!(buf, [0x00]);
    }

    #[test]
    fn write_string_regular_text() {
        let mut buf = Vec::new();
        write_string(&mut buf, "hello").unwrap();
        // tagged_varint(5, false) = 10 = 0x0a, then "hello"
        assert_eq!(&buf[0..1], &[0x0a]);
        assert_eq!(&buf[1..], b"hello");
    }

    #[test]
    fn write_string_lowercase_hex_compacted() {
        let mut buf = Vec::new();
        write_string(&mut buf, "aabb").unwrap();
        // tagged_varint(2, true) = (2 << 1) | 1 = 5 = 0x05
        // Then raw bytes 0xaa 0xbb
        assert_eq!(buf, [0x05, 0xaa, 0xbb]);
    }

    #[test]
    fn write_string_uppercase_hex_not_compacted() {
        let mut buf = Vec::new();
        write_string(&mut buf, "AABB").unwrap();
        // Should be treated as text, not compacted
        // tagged_varint(4, false) = 8 = 0x08
        assert_eq!(&buf[0..1], &[0x08]);
        assert_eq!(&buf[1..], b"AABB");
    }

    #[test]
    fn write_string_mixed_case_hex_not_compacted() {
        let mut buf = Vec::new();
        write_string(&mut buf, "aAbB").unwrap();
        // Mixed case should be treated as text
        assert_eq!(&buf[0..1], &[0x08]);
        assert_eq!(&buf[1..], b"aAbB");
    }

    #[test]
    fn write_string_odd_length_hex_not_compacted() {
        let mut buf = Vec::new();
        write_string(&mut buf, "aab").unwrap();
        // Odd length is not valid hex
        assert_eq!(&buf[0..1], &[0x06]); // tagged_varint(3, false) = 6
        assert_eq!(&buf[1..], b"aab");
    }

    #[test]
    fn write_string_32byte_pubkey_compacted() {
        let pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut buf = Vec::new();
        write_string(&mut buf, pubkey).unwrap();

        // tagged_varint(32, true) = (32 << 1) | 1 = 65 = 0x41
        assert_eq!(buf[0], 0x41);
        assert_eq!(buf.len(), 1 + 32);
        assert!(buf[1..].iter().all(|&b| b == 0xbb));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // write_string_to tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn write_string_to_matches_buffer_version() {
        let test_cases = ["", "hello", "aabb", "AABB", "test123"];

        for s in test_cases {
            let mut buf = Vec::new();
            write_string(&mut buf, s).unwrap();

            let mut writer_buf = Vec::new();
            let written = write_string_to(&mut writer_buf, s).unwrap();

            assert_eq!(buf, writer_buf, "mismatch for string '{s}'");
            assert_eq!(written, buf.len());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Field length validation tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn pack_note_rejects_short_id() {
        let mut note = minimal_note();
        note.id = "aabb".into(); // Only 2 bytes, need 32
        let err = pack_note(&note).unwrap_err();
        match err {
            Error::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "id");
                assert_eq!(expected, 32);
                assert_eq!(actual, 2);
            }
            _ => panic!("expected InvalidFieldLength error"),
        }
    }

    #[test]
    fn pack_note_rejects_long_id() {
        let mut note = minimal_note();
        note.id = "aa".repeat(33); // 33 bytes, need 32
        let err = pack_note(&note).unwrap_err();
        match err {
            Error::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "id");
                assert_eq!(expected, 32);
                assert_eq!(actual, 33);
            }
            _ => panic!("expected InvalidFieldLength error"),
        }
    }

    #[test]
    fn pack_note_rejects_short_pubkey() {
        let mut note = minimal_note();
        note.pubkey = "bb".repeat(16); // 16 bytes, need 32
        let err = pack_note(&note).unwrap_err();
        match err {
            Error::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "pubkey");
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("expected InvalidFieldLength error"),
        }
    }

    #[test]
    fn pack_note_rejects_short_sig() {
        let mut note = minimal_note();
        note.sig = "cc".repeat(32); // 32 bytes, need 64
        let err = pack_note(&note).unwrap_err();
        match err {
            Error::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "sig");
                assert_eq!(expected, 64);
                assert_eq!(actual, 32);
            }
            _ => panic!("expected InvalidFieldLength error"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Roundtrip tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_minimal_note() {
        let note = minimal_note();
        let bytes = pack_note(&note).unwrap();
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        let recovered = parsed.to_owned().unwrap();

        assert_eq!(note.id, recovered.id);
        assert_eq!(note.pubkey, recovered.pubkey);
        assert_eq!(note.sig, recovered.sig);
        assert_eq!(note.created_at, recovered.created_at);
        assert_eq!(note.kind, recovered.kind);
        assert_eq!(note.content, recovered.content);
        assert_eq!(note.tags, recovered.tags);
    }

    #[test]
    fn roundtrip_with_content() {
        let mut note = minimal_note();
        note.content = "Hello, Nostr! 🎉".into();

        let bytes = pack_note(&note).unwrap();
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        let recovered = parsed.to_owned().unwrap();

        assert_eq!(note.content, recovered.content);
    }

    #[test]
    fn roundtrip_with_tags() {
        let mut note = minimal_note();
        note.tags = vec![
            vec![
                "e".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                "wss://relay.example.com".into(),
            ],
            vec![
                "p".into(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ],
            vec!["t".into(), "nostr".into()],
        ];

        let bytes = pack_note(&note).unwrap();
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        let recovered = parsed.to_owned().unwrap();

        assert_eq!(note.tags, recovered.tags);
    }

    #[test]
    fn roundtrip_via_base64_string() {
        let mut note = minimal_note();
        note.content = "test".into();
        note.kind = 1;
        note.created_at = 1720000000;

        let encoded = pack_note_to_string(&note).unwrap();
        let decoded_bytes = NoteParser::decode(&encoded).unwrap();
        let parsed = NoteParser::new(&decoded_bytes).into_note().unwrap();
        let recovered = parsed.to_owned().unwrap();

        assert_eq!(note.id, recovered.id);
        assert_eq!(note.pubkey, recovered.pubkey);
        assert_eq!(note.sig, recovered.sig);
        assert_eq!(note.created_at, recovered.created_at);
        assert_eq!(note.kind, recovered.kind);
        assert_eq!(note.content, recovered.content);
    }

    #[test]
    fn roundtrip_large_timestamp() {
        let mut note = minimal_note();
        note.created_at = u64::MAX;

        let bytes = pack_note(&note).unwrap();
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        assert_eq!(parsed.created_at, u64::MAX);
    }

    #[test]
    fn roundtrip_large_kind() {
        let mut note = minimal_note();
        note.kind = u64::MAX;

        let bytes = pack_note(&note).unwrap();
        let parsed = NoteParser::new(&bytes).into_note().unwrap();
        assert_eq!(parsed.kind, u64::MAX);
    }
}
