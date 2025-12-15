//! Spec conformance tests based on SPEC.md Section 9.1 test vectors.
//!
//! These tests verify that the implementation correctly encodes and decodes
//! the example note defined in the specification.

use notepack::{NoteBuf, NoteParser, pack_note, pack_note_to_string};

/// The expected binary encoding from SPEC.md §9.1 (hex)
const SPEC_BINARY_HEX: &str = "01000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222280bc94b406000568656c6c6f0203026541aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2e7773733a2f2f72656c61792e6578616d706c652e636f6d02027041bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The expected base64 string form from SPEC.md §9.1
const SPEC_B64: &str = "notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw";

/// Build the test note from SPEC.md §9.1
fn spec_note() -> NoteBuf {
    NoteBuf {
        id: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        pubkey: "1111111111111111111111111111111111111111111111111111111111111111".into(),
        // 64 bytes = 128 hex chars
        sig: "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222".into(),
        created_at: 1720000000,
        kind: 0,
        content: "hello".into(),
        tags: vec![
            vec![
                "e".into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                "wss://relay.example.com".into(),
            ],
            vec![
                "p".into(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ],
        ],
    }
}

#[test]
fn spec_encoding_matches_binary_vector() {
    let note = spec_note();
    let encoded = pack_note(&note).expect("encoding should succeed");
    let expected = hex_simd::decode_to_vec(SPEC_BINARY_HEX).expect("valid hex in spec");

    assert_eq!(
        encoded, expected,
        "Encoded binary does not match SPEC.md §9.1 test vector"
    );
}

#[test]
fn spec_encoding_matches_base64_vector() {
    let note = spec_note();
    let encoded = pack_note_to_string(&note).expect("encoding should succeed");

    assert_eq!(
        encoded, SPEC_B64,
        "Encoded base64 does not match SPEC.md §9.1 test vector"
    );
}

#[test]
fn spec_decoding_binary_vector() {
    let bytes = hex_simd::decode_to_vec(SPEC_BINARY_HEX).expect("valid hex");
    let note = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");

    // Verify fixed fields
    assert_eq!(note.id, &[0x00; 32]);
    assert_eq!(note.pubkey, &[0x11; 32]);
    assert_eq!(note.sig, &[0x22; 64]);
    assert_eq!(note.created_at, 1720000000);
    assert_eq!(note.kind, 0);
    assert_eq!(note.content, "hello");

    // Verify tag count
    assert_eq!(note.tags.len(), 2);
}

#[test]
fn spec_decoding_base64_vector() {
    let bytes = NoteParser::decode(SPEC_B64).expect("decoding should succeed");
    let note = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");

    assert_eq!(note.content, "hello");
    assert_eq!(note.kind, 0);
    assert_eq!(note.created_at, 1720000000);
}

#[test]
fn spec_roundtrip_preserves_all_fields() {
    let original = spec_note();

    // Encode
    let bytes = pack_note(&original).expect("encoding should succeed");

    // Decode
    let parsed = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");
    let recovered = parsed.to_owned().expect("to_owned should succeed");

    assert_eq!(original.id, recovered.id);
    assert_eq!(original.pubkey, recovered.pubkey);
    assert_eq!(original.sig, recovered.sig);
    assert_eq!(original.created_at, recovered.created_at);
    assert_eq!(original.kind, recovered.kind);
    assert_eq!(original.content, recovered.content);
    assert_eq!(original.tags, recovered.tags);
}

#[test]
fn spec_tag_iteration_yields_correct_values() {
    let bytes = hex_simd::decode_to_vec(SPEC_BINARY_HEX).expect("valid hex");
    let note = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");

    let mut tags = note.tags.clone();

    // Tag 0: ["e", <32 bytes 0xaa>, "wss://relay.example.com"]
    {
        let mut tag0 = tags.next_tag().expect("ok").expect("tag0");

        // Element 0: "e"
        let elem0 = tag0.next().expect("e0").expect("ok");
        match elem0 {
            notepack::StringType::Str(s) => assert_eq!(s, "e"),
            _ => panic!("expected Str"),
        }

        // Element 1: 32 bytes of 0xaa
        let elem1 = tag0.next().expect("e1").expect("ok");
        match elem1 {
            notepack::StringType::Bytes(bs) => {
                assert_eq!(bs.len(), 32);
                assert!(bs.iter().all(|&b| b == 0xaa));
            }
            _ => panic!("expected Bytes"),
        }

        // Element 2: "wss://relay.example.com"
        let elem2 = tag0.next().expect("e2").expect("ok");
        match elem2 {
            notepack::StringType::Str(s) => assert_eq!(s, "wss://relay.example.com"),
            _ => panic!("expected Str"),
        }

        assert!(tag0.next().is_none());
    }

    // Tag 1: ["p", <32 bytes 0xbb>]
    {
        let mut tag1 = tags.next_tag().expect("ok").expect("tag1");

        // Element 0: "p"
        let elem0 = tag1.next().expect("e0").expect("ok");
        match elem0 {
            notepack::StringType::Str(s) => assert_eq!(s, "p"),
            _ => panic!("expected Str"),
        }

        // Element 1: 32 bytes of 0xbb
        let elem1 = tag1.next().expect("e1").expect("ok");
        match elem1 {
            notepack::StringType::Bytes(bs) => {
                assert_eq!(bs.len(), 32);
                assert!(bs.iter().all(|&b| b == 0xbb));
            }
            _ => panic!("expected Bytes"),
        }

        assert!(tag1.next().is_none());
    }

    // No more tags
    assert!(tags.next_tag().expect("ok").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional spec conformance tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spec_version_is_one() {
    let bytes = hex_simd::decode_to_vec(SPEC_BINARY_HEX).expect("valid hex");
    let mut parser = NoteParser::new(&bytes);

    // First field should be Version(1)
    let field = parser.next().expect("has version").expect("ok");
    match field {
        notepack::ParsedField::Version(v) => assert_eq!(v, 1),
        _ => panic!("expected Version"),
    }
}

#[test]
fn spec_varint_encoding_created_at() {
    // From SPEC.md: 1720000000 encodes as 80 bc 94 b4 06
    let note = spec_note();
    let bytes = pack_note(&note).expect("ok");

    // Find the created_at varint in the binary
    // Position: version(1) + id(32) + pubkey(32) + sig(64) = 129
    let created_at_start = 129;
    let created_at_bytes = &bytes[created_at_start..created_at_start + 5];

    assert_eq!(
        created_at_bytes,
        &[0x80, 0xbc, 0x94, 0xb4, 0x06],
        "created_at varint encoding should match spec"
    );
}

#[test]
fn spec_fixed_field_sizes() {
    let bytes = hex_simd::decode_to_vec(SPEC_BINARY_HEX).expect("valid hex");

    // Version at offset 0
    assert_eq!(bytes[0], 0x01);

    // ID: 32 bytes at offset 1
    assert_eq!(&bytes[1..33], &[0x00; 32]);

    // Pubkey: 32 bytes at offset 33
    assert_eq!(&bytes[33..65], &[0x11; 32]);

    // Sig: 64 bytes at offset 65
    assert_eq!(&bytes[65..129], &[0x22; 64]);
}

#[test]
fn spec_tagged_varint_tag_elements() {
    // Verify the tagged varint encoding for tag elements
    // From spec: tagged_varint(len=32, is_bytes=true) = (32 << 1) | 1 = 65 = 0x41
    let note = spec_note();
    let bytes = pack_note(&note).expect("ok");

    // After all header fields + content, find the tags section
    // The hex for the first tag's pubkey element should contain 0x41
    let hex = hex_simd::encode_to_string(&bytes, hex_simd::AsciiCase::Lower);

    // 0x41 appears for the 32-byte hex values
    assert!(
        hex.contains("41"),
        "should contain tagged varint 0x41 for 32-byte hex"
    );
}
