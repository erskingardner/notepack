//! End-to-end roundtrip tests for notepack encoding and decoding.
//!
//! These tests verify that various note configurations survive the
//! encode → decode → to_owned cycle without data loss.

use notepack::{NoteBuf, NoteParser, pack_note, pack_note_to_string};

/// Helper to verify roundtrip preserves all fields
fn assert_roundtrip(original: &NoteBuf) {
    // Binary roundtrip
    let bytes = pack_note(original).expect("encoding should succeed");
    let parsed = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");
    let recovered = parsed.to_owned().expect("to_owned should succeed");

    assert_eq!(original.id, recovered.id, "id mismatch");
    assert_eq!(original.pubkey, recovered.pubkey, "pubkey mismatch");
    assert_eq!(original.sig, recovered.sig, "sig mismatch");
    assert_eq!(
        original.created_at, recovered.created_at,
        "created_at mismatch"
    );
    assert_eq!(original.kind, recovered.kind, "kind mismatch");
    assert_eq!(original.content, recovered.content, "content mismatch");
    assert_eq!(original.tags, recovered.tags, "tags mismatch");
}

/// Helper to verify base64 string roundtrip
fn assert_b64_roundtrip(original: &NoteBuf) {
    let encoded = pack_note_to_string(original).expect("encoding should succeed");
    assert!(encoded.starts_with("notepack_"));

    let bytes = NoteParser::decode(&encoded).expect("decoding should succeed");
    let parsed = NoteParser::new(&bytes)
        .into_note()
        .expect("parsing should succeed");
    let recovered = parsed.to_owned().expect("to_owned should succeed");

    assert_eq!(original.id, recovered.id);
    assert_eq!(original.pubkey, recovered.pubkey);
    assert_eq!(original.content, recovered.content);
    assert_eq!(original.tags, recovered.tags);
}

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

// ─────────────────────────────────────────────────────────────────────────────
// Basic roundtrip tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_minimal_note() {
    assert_roundtrip(&minimal_note());
}

#[test]
fn roundtrip_with_content() {
    let mut note = minimal_note();
    note.content = "Hello, Nostr!".into();
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_empty_content() {
    let note = minimal_note();
    assert!(note.content.is_empty());
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_long_content() {
    let mut note = minimal_note();
    note.content = "x".repeat(10000);
    assert_roundtrip(&note);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unicode content tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_unicode_content() {
    let mut note = minimal_note();
    note.content = "Hello 世界 🌍 مرحبا".into();
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_emoji_content() {
    let mut note = minimal_note();
    note.content = "🎉🔥💯🚀".into();
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_multiline_content() {
    let mut note = minimal_note();
    note.content = "Line 1\nLine 2\nLine 3".into();
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_special_chars_content() {
    let mut note = minimal_note();
    note.content = "Special: \t\r\n\\\"'`".into();
    assert_roundtrip(&note);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tag tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_single_tag() {
    let mut note = minimal_note();
    note.tags = vec![vec!["t".into(), "nostr".into()]];
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_multiple_tags() {
    let mut note = minimal_note();
    note.tags = vec![
        vec!["t".into(), "nostr".into()],
        vec!["t".into(), "bitcoin".into()],
        vec!["t".into(), "rust".into()],
    ];
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_hex_tag_values() {
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
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_mixed_tag_types() {
    let mut note = minimal_note();
    note.tags = vec![
        vec![
            "e".into(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            "wss://relay.example.com".into(),
        ],
        vec!["t".into(), "tag".into()],
        vec![
            "p".into(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        ],
        vec!["relay".into(), "wss://relay.example.com".into()],
    ];
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_empty_tag_element() {
    let mut note = minimal_note();
    note.tags = vec![vec!["".into()]];
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_tag_with_many_elements() {
    let mut note = minimal_note();
    note.tags = vec![vec![
        "a".into(),
        "b".into(),
        "c".into(),
        "d".into(),
        "e".into(),
        "f".into(),
        "g".into(),
    ]];
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_many_tags() {
    let mut note = minimal_note();
    note.tags = (0..100)
        .map(|i| vec!["t".into(), format!("tag{}", i)])
        .collect();
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_unicode_tag_values() {
    let mut note = minimal_note();
    note.tags = vec![
        vec!["t".into(), "日本語".into()],
        vec!["t".into(), "emoji🎉".into()],
    ];
    assert_roundtrip(&note);
}

// ─────────────────────────────────────────────────────────────────────────────
// Numeric field tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_large_timestamp() {
    let mut note = minimal_note();
    note.created_at = u64::MAX;
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_large_kind() {
    let mut note = minimal_note();
    note.kind = u64::MAX;
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_various_kinds() {
    for kind in [0, 1, 3, 4, 5, 6, 7, 40, 42, 1984, 9735, 10000, 30023] {
        let mut note = minimal_note();
        note.kind = kind;
        assert_roundtrip(&note);
    }
}

#[test]
fn roundtrip_timestamp_boundary_values() {
    for ts in [0, 1, 127, 128, 255, 256, 65535, 65536, 1720000000] {
        let mut note = minimal_note();
        note.created_at = ts;
        assert_roundtrip(&note);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 string format tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn b64_roundtrip_minimal() {
    assert_b64_roundtrip(&minimal_note());
}

#[test]
fn b64_roundtrip_with_content() {
    let mut note = minimal_note();
    note.content = "Hello via base64!".into();
    assert_b64_roundtrip(&note);
}

#[test]
fn b64_roundtrip_with_tags() {
    let mut note = minimal_note();
    note.tags = vec![vec![
        "e".into(),
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
    ]];
    assert_b64_roundtrip(&note);
}

#[test]
fn b64_string_has_no_padding() {
    let note = minimal_note();
    let encoded = pack_note_to_string(&note).expect("encoding should succeed");

    assert!(!encoded.contains('='), "base64 should not have padding");
}

#[test]
fn b64_string_prefix_is_correct() {
    let note = minimal_note();
    let encoded = pack_note_to_string(&note).expect("encoding should succeed");

    assert!(encoded.starts_with("notepack_"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Complex note tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_complex_note() {
    let note = NoteBuf {
        id: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd".into(),
        pubkey: "12341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234".replace("1234", "1111")[..64].into(),
        sig: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        created_at: 1720000000,
        kind: 1,
        content: "This is a complex note with various features!\n\nIt has:\n- Multiple lines\n- Unicode: 日本語 🎉\n- Special chars: <>&\"'".into(),
        tags: vec![
            vec!["e".into(), "1111111111111111111111111111111111111111111111111111111111111111".into(), "wss://relay1.example.com".into(), "root".into()],
            vec!["e".into(), "2222222222222222222222222222222222222222222222222222222222222222".into(), "wss://relay2.example.com".into(), "reply".into()],
            vec!["p".into(), "3333333333333333333333333333333333333333333333333333333333333333".into()],
            vec!["t".into(), "nostr".into()],
            vec!["t".into(), "test".into()],
            vec!["client".into(), "notepack-test".into()],
        ],
    };

    assert_roundtrip(&note);
    assert_b64_roundtrip(&note);
}

#[test]
fn roundtrip_contact_list_style_note() {
    // Kind 3 contact list with many "p" tags
    let mut note = minimal_note();
    note.kind = 3;
    note.content = "{}".into(); // Often empty or JSON in contact lists
    note.tags = (0..50)
        .map(|i| {
            let pubkey = format!("{:0>64x}", i);
            vec![
                "p".into(),
                pubkey,
                format!("wss://relay{}.example.com", i % 5),
                "".into(),
            ]
        })
        .collect();

    assert_roundtrip(&note);
}

#[test]
fn roundtrip_replaceable_event() {
    // Kind 10002 relay list
    let mut note = minimal_note();
    note.kind = 10002;
    note.tags = vec![
        vec!["r".into(), "wss://relay1.example.com".into(), "read".into()],
        vec![
            "r".into(),
            "wss://relay2.example.com".into(),
            "write".into(),
        ],
        vec!["r".into(), "wss://relay3.example.com".into()],
    ];

    assert_roundtrip(&note);
}

#[test]
fn roundtrip_addressable_event() {
    // Kind 30023 long-form article
    let mut note = minimal_note();
    note.kind = 30023;
    note.content = "# Article Title\n\nThis is a long-form article content...".into();
    note.tags = vec![
        vec!["d".into(), "my-article-identifier".into()],
        vec!["title".into(), "My Article".into()],
        vec!["summary".into(), "A brief summary".into()],
        vec!["published_at".into(), "1720000000".into()],
        vec!["t".into(), "article".into()],
    ];

    assert_roundtrip(&note);
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_all_zeros() {
    let note = NoteBuf {
        id: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        pubkey: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        sig: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into(),
        created_at: 0,
        kind: 0,
        content: "".into(),
        tags: vec![],
    };
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_all_ones() {
    let note = NoteBuf {
        id: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        pubkey: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        sig: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        created_at: u64::MAX,
        kind: u64::MAX,
        content: "".into(),
        tags: vec![],
    };
    assert_roundtrip(&note);
}

#[test]
fn roundtrip_content_that_looks_like_hex() {
    // Content that looks like hex should remain as content (not compacted)
    let mut note = minimal_note();
    note.content = "aabbccdd".into();
    assert_roundtrip(&note);
    assert_eq!(note.content, "aabbccdd");
}

#[test]
fn roundtrip_tag_with_uppercase_hex() {
    // Uppercase hex should NOT be compacted (treated as text)
    let mut note = minimal_note();
    note.tags = vec![vec!["d".into(), "AABBCCDD".into()]];

    let bytes = pack_note(&note).expect("ok");
    let parsed = NoteParser::new(&bytes).into_note().expect("ok");
    let recovered = parsed.to_owned().expect("ok");

    // The uppercase hex should be preserved as-is
    assert_eq!(recovered.tags[0][1], "AABBCCDD");
}
