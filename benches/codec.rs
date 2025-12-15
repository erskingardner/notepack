use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use notepack::{NoteBuf, NoteParser, StringType, pack_note, pack_note_to_string};
use std::hint::black_box;

#[path = "helpers.rs"]
mod helpers;
use helpers::{format_bytes, format_speedup};

const CONTACTS_JSON: &str = include_str!("contacts.json");

fn parse_iter_only(bytes: &[u8]) -> usize {
    let parser = NoteParser::new(bytes);
    let mut n = 0usize;
    for f in parser {
        let _ = f.expect("parse ok");
        n += 1;
    }
    n
}

fn bench_codec(c: &mut Criterion) {
    // One-time fixture setup outside the timer.
    let json_len = CONTACTS_JSON.len() as u64;

    let note_from_json: NoteBuf = serde_json::from_str(CONTACTS_JSON).expect("valid fixture");
    let notepack_bytes = pack_note(&note_from_json).expect("pack ok");
    let notepack_b64 = pack_note_to_string(&note_from_json).expect("pack to string ok");

    // 1) Streaming-only lower bound: iterate fields without allocating a Note.
    {
        let mut group = c.benchmark_group("contacts/notepack_stream_iter_only");
        group.throughput(Throughput::Bytes(notepack_bytes.len() as u64));
        group.bench_function("contacts.np.iter", |b| {
            b.iter(|| {
                let nfields = parse_iter_only(black_box(&notepack_bytes));
                black_box(nfields);
            });
        });
        group.finish();
    }

    // 2) Base64 notepack string -> bytes -> Note
    {
        let mut group = c.benchmark_group("contacts/notepack_decode_b64_and_parse");
        group.throughput(Throughput::Bytes(notepack_b64.len() as u64));
        group.bench_function("contacts.np.b64", |b| {
            b.iter(|| {
                // Intentionally measure both the decode and parse.
                let bs = NoteParser::decode(black_box(&notepack_b64)).expect("decode ok");
                let note = NoteParser::new(&bs).into_note().expect("parse ok");
                black_box(note);
            });
        });
        group.finish();
    }

    // 3) Notepack bytes -> Note
    {
        let mut group = c.benchmark_group("contacts/notepack_parse_bytes");
        group.throughput(Throughput::Bytes(notepack_bytes.len() as u64));
        group.bench_function("contacts.np", |b| {
            b.iter(|| {
                let note = NoteParser::new(black_box(&notepack_bytes))
                    .into_note()
                    .expect("parse ok");
                black_box(note);
            });
        });
        group.finish();
    }

    // 4) Notepack bytes -> Note + iterate all tags (forces reading all bytes)
    {
        let mut group = c.benchmark_group("contacts/notepack_parse_bytes_and_iter_tags");
        group.throughput(Throughput::Bytes(notepack_bytes.len() as u64));
        group.bench_function("contacts.np.tags", |b| {
            b.iter(|| {
                let note = NoteParser::new(black_box(&notepack_bytes))
                    .into_note()
                    .expect("parse ok");

                // Drain tags so we actually read everything claimed in throughput.
                let mut tags = note.tags; // move out; no need to clone
                let mut acc = 0usize;
                while let Some(mut elems) = tags.next_tag().expect("tag ok") {
                    for item in &mut elems {
                        match item.expect("elem ok") {
                            StringType::Str(s) => acc += s.len(),
                            StringType::Bytes(bs) => acc += bs.len(),
                        }
                    }
                }
                black_box(acc)
            });
        });
        group.finish();
    }

    // 5) JSON -> NoteBuf
    {
        let mut group = c.benchmark_group("contacts/json_from_str");
        group.throughput(Throughput::Bytes(json_len));
        group.bench_function("contacts.json", |b| {
            b.iter(|| {
                let note: NoteBuf =
                    serde_json::from_str(black_box(CONTACTS_JSON)).expect("json->note");
                black_box(note);
            });
        });
        group.finish();
    }

    // 6) JSON -> NoteBuf + iterate tags
    {
        let mut group = c.benchmark_group("contacts/json_from_str_iter");
        group.throughput(Throughput::Bytes(json_len));
        group.bench_function("contacts.json.iter", |b| {
            b.iter(|| {
                let note: NoteBuf =
                    serde_json::from_str(black_box(CONTACTS_JSON)).expect("json->note");

                // apples-to-apples iterate comparison
                let tags = note.tags; // move out; no need to clone
                let mut acc = 0usize;
                for tag in tags {
                    for elem in tag {
                        acc += elem.len();
                    }
                }
                black_box(acc)
            });
        });
        group.finish();
    }

    // 7) NoteBuf -> notepack bytes
    {
        let mut group = c.benchmark_group("contacts/notepack_encode");
        group.throughput(Throughput::Bytes(notepack_bytes.len() as u64));
        group.bench_function("contacts.np.encode", |b| {
            b.iter(|| {
                let bytes = pack_note(black_box(&note_from_json)).expect("pack ok");
                black_box(bytes);
            });
        });
        group.finish();
    }

    // 8) NoteBuf -> notepack base64 string
    {
        let mut group = c.benchmark_group("contacts/notepack_encode_b64");
        group.throughput(Throughput::Bytes(notepack_b64.len() as u64));
        group.bench_function("contacts.np.encode_b64", |b| {
            b.iter(|| {
                let s = pack_note_to_string(black_box(&note_from_json)).expect("pack to string ok");
                black_box(s);
            });
        });
        group.finish();
    }

    // 9) NoteBuf -> JSON string (for comparison)
    {
        let mut group = c.benchmark_group("contacts/json_to_string");
        group.throughput(Throughput::Bytes(json_len));
        group.bench_function("contacts.json.encode", |b| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&note_from_json)).expect("to_string ok");
                black_box(s);
            });
        });
        group.finish();
    }

    // 10) Roundtrip: NoteBuf -> notepack bytes -> Note -> NoteBuf
    {
        let mut group = c.benchmark_group("contacts/notepack_roundtrip");
        group.throughput(Throughput::Bytes(notepack_bytes.len() as u64));
        group.bench_function("contacts.np.roundtrip", |b| {
            b.iter(|| {
                // Encode
                let bytes = pack_note(black_box(&note_from_json)).expect("pack ok");
                // Decode
                let note = NoteParser::new(&bytes).into_note().expect("parse ok");
                // Convert back to owned
                let owned = note.to_owned().expect("to_owned ok");
                black_box(owned);
            });
        });
        group.finish();
    }
}

/// Print a comparison summary table at the end
fn print_comparison_table(_c: &mut Criterion) {
    use std::time::Instant;

    let note: NoteBuf = serde_json::from_str(CONTACTS_JSON).expect("valid");
    let notepack_bytes = pack_note(&note).expect("ok");
    let json_str = CONTACTS_JSON;

    let iterations = 100;

    // Measure JSON encode
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(serde_json::to_string(black_box(&note)).expect("ok"));
    }
    let json_encode_ns = start.elapsed().as_nanos() / iterations;

    // Measure notepack encode
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(pack_note(black_box(&note)).expect("ok"));
    }
    let np_encode_ns = start.elapsed().as_nanos() / iterations;

    // Measure JSON decode
    let start = Instant::now();
    for _ in 0..iterations {
        let n: NoteBuf = serde_json::from_str(black_box(json_str)).expect("ok");
        black_box(n);
    }
    let json_decode_ns = start.elapsed().as_nanos() / iterations;

    // Measure notepack decode (into_note, lazy)
    let start = Instant::now();
    for _ in 0..iterations {
        let parsed = NoteParser::new(black_box(&notepack_bytes))
            .into_note()
            .expect("ok");
        black_box(parsed);
    }
    let np_decode_ns = start.elapsed().as_nanos() / iterations;

    // Measure notepack decode full (with tag iteration)
    let start = Instant::now();
    for _ in 0..iterations {
        let parsed = NoteParser::new(black_box(&notepack_bytes))
            .into_note()
            .expect("ok");
        let mut tags = parsed.tags;
        while let Some(mut elems) = tags.next_tag().expect("ok") {
            for item in &mut elems {
                black_box(item.expect("ok"));
            }
        }
    }
    let np_decode_full_ns = start.elapsed().as_nanos() / iterations;

    let json_bytes = json_str.len();
    let np_bytes = notepack_bytes.len();
    let compression = 100.0 * (1.0 - (np_bytes as f64 / json_bytes as f64));

    // Print table
    eprintln!("\n");
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║           NOTEPACK vs JSON COMPARISON (contacts.json)            ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  Operation          │    JSON     │  notepack   │   Speedup     ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Encode             │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_encode_ns,
        np_encode_ns,
        format_speedup(json_encode_ns, np_encode_ns)
    );
    eprintln!(
        "║  Decode             │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_decode_ns,
        np_decode_ns,
        format_speedup(json_decode_ns, np_decode_ns)
    );
    eprintln!(
        "║  Decode (full)      │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_decode_ns,
        np_decode_full_ns,
        format_speedup(json_decode_ns, np_decode_full_ns)
    );
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Event size         │ {:>9}  │ {:>9}  │  {:>4.1}% smaller ║",
        format_bytes(json_bytes),
        format_bytes(np_bytes),
        compression
    );
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
}

criterion_group!(benches, bench_codec, print_comparison_table);
criterion_main!(benches);
