#![no_main]

use libfuzzer_sys::fuzz_target;
use notepack::{NoteBuf, NoteParser, pack_note, pack_note_into, pack_note_to_string};

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let n = n.min(data.len());
    let (h, t) = data.split_at(n);
    *data = t;
    h
}

fn take_u8(data: &mut &[u8]) -> u8 {
    if data.is_empty() {
        return 0;
    }
    let b = data[0];
    *data = &data[1..];
    b
}

fn build_note(mut data: &[u8]) -> NoteBuf {
    // Hard bounds so the fuzzer explores logic instead of OOM-ing.
    let max_tags = 16usize;
    let max_elems = 8usize;
    let max_str_len = 128usize;

    // Fixed-size fields: prefer valid lengths frequently so we exercise encoder hot paths.
    let id = {
        let b = take(&mut data, 32);
        if b.len() == 32 { hex_lower(b) } else { String::new() }
    };
    let pubkey = {
        let b = take(&mut data, 32);
        if b.len() == 32 { hex_lower(b) } else { String::new() }
    };
    let sig = {
        let b = take(&mut data, 64);
        if b.len() == 64 { hex_lower(b) } else { String::new() }
    };

    // Integers + content
    let created_at = u64::from_le_bytes({
        let mut a = [0u8; 8];
        let b = take(&mut data, 8);
        a[..b.len()].copy_from_slice(b);
        a
    });
    let kind = u64::from_le_bytes({
        let mut a = [0u8; 8];
        let b = take(&mut data, 8);
        a[..b.len()].copy_from_slice(b);
        a
    });

    let content_len = (take_u8(&mut data) as usize).min(max_str_len).min(data.len());
    let content = String::from_utf8_lossy(take(&mut data, content_len)).into_owned();

    // Tags (bounded)
    let ntags = (take_u8(&mut data) as usize) % (max_tags + 1);
    let mut tags = Vec::with_capacity(ntags);
    for _ in 0..ntags {
        let nelems = (take_u8(&mut data) as usize) % (max_elems + 1);
        let mut tag = Vec::with_capacity(nelems);
        for _ in 0..nelems {
            // Sometimes generate lowercase-hex-looking strings to exercise compaction logic.
            let mode = take_u8(&mut data) % 4;
            let slen = (take_u8(&mut data) as usize).min(max_str_len).min(data.len());
            let raw = take(&mut data, slen);
            let s = match mode {
                0 => String::from_utf8_lossy(raw).into_owned(),
                1 => hex_lower(raw), // always lowercase hex
                2 => {
                    // uppercase-ish (should not be compacted)
                    String::from_utf8_lossy(raw).to_ascii_uppercase()
                }
                _ => String::new(),
            };
            tag.push(s);
        }
        tags.push(tag);
    }

    NoteBuf {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig,
    }
}

fuzz_target!(|data: &[u8]| {
    let note = build_note(data);

    // Exercise all encoding entry points; errors are fine, panics are not.
    if let Ok(packed) = pack_note(&note) {
        // Streaming buffer API
        let mut buf = Vec::new();
        let _ = pack_note_into(&note, &mut buf);

        // Base64 string API → decode → parse
        if let Ok(s) = pack_note_to_string(&note) {
            if let Ok(bytes) = NoteParser::decode(&s) {
                // Should match pack_note output when both succeed.
                debug_assert_eq!(bytes, packed);
            }
        }

        // Roundtrip: packed → parse → owned → packed2 should be stable.
        if let Ok(n2) = NoteParser::new(&packed).into_note() {
            if let Ok(o2) = n2.to_owned() {
                if let Ok(packed2) = pack_note(&o2) {
                    debug_assert_eq!(packed2, packed);
                }
            }
        }
    } else {
        // Still exercise "string" API; should error not panic for invalid hex fields.
        let _ = pack_note_to_string(&note);
    }
});


