#![no_main]

use libfuzzer_sys::fuzz_target;
use notepack::{NoteParser, pack_note};

fuzz_target!(|data: &[u8]| {
    // Exercise the streaming parser state machine (should never panic).
    for _field in NoteParser::new(data) {
        // intentionally discard
    }

    // Exercise full parse + tag iteration + re-encode roundtrip when possible.
    if let Ok(note) = NoteParser::new(data).into_note() {
        if let Ok(owned) = note.to_owned() {
            if let Ok(packed) = pack_note(&owned) {
                if let Ok(note2) = NoteParser::new(&packed).into_note() {
                    if let Ok(owned2) = note2.to_owned() {
                        // Deterministic roundtrip property (owned form).
                        debug_assert_eq!(owned.id, owned2.id);
                        debug_assert_eq!(owned.pubkey, owned2.pubkey);
                        debug_assert_eq!(owned.sig, owned2.sig);
                        debug_assert_eq!(owned.created_at, owned2.created_at);
                        debug_assert_eq!(owned.kind, owned2.kind);
                        debug_assert_eq!(owned.content, owned2.content);
                        debug_assert_eq!(owned.tags, owned2.tags);
                    }
                }
            }
        }
    }
});


