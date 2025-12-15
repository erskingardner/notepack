#![no_main]

use libfuzzer_sys::fuzz_target;
use notepack::NoteParser;

fuzz_target!(|data: &[u8]| {
    // Build an arbitrary UTF-8-ish string and sometimes give it the right prefix.
    let s = String::from_utf8_lossy(data);
    let candidate = if data.first().copied().unwrap_or(0) & 1 == 0 {
        format!("notepack_{s}")
    } else {
        s.into_owned()
    };

    // Should never panic, regardless of contents.
    let _ = NoteParser::decode(&candidate);
});


