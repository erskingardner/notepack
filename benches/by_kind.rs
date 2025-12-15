//! Comprehensive benchmarks across multiple Nostr event kinds.
//!
//! Each kind file contains 100 real-world events, giving us a diverse
//! sample of event shapes (varying content lengths, tag counts, etc.).
//!
//! Run with:
//!   cargo bench --bench by_kind
//!
//! Filter to specific kinds or operations:
//!   cargo bench --bench by_kind -- "kind_1"
//!   cargo bench --bench by_kind -- "encode"
//!   cargo bench --bench by_kind -- "json"

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use notepack::{NoteBuf, NoteParser, StringType, pack_note, pack_note_to_string};
use std::hint::black_box;

#[path = "helpers.rs"]
mod helpers;
use helpers::{format_bytes, format_speedup};

/// A loaded test corpus for a single event kind.
struct KindCorpus {
    /// Human-readable name like "kind_1_notes"
    name: &'static str,
    /// Original JSON lines (for JSON benchmarks)
    json_lines: Vec<&'static str>,
    /// Parsed NoteBuf instances
    notes: Vec<NoteBuf>,
    /// Pre-encoded notepack bytes
    notepack_bytes: Vec<Vec<u8>>,
    /// Pre-encoded notepack base64 strings
    notepack_b64: Vec<String>,
    /// Total JSON bytes
    total_json_bytes: u64,
    /// Total notepack bytes
    total_notepack_bytes: u64,
}

impl KindCorpus {
    fn load(name: &'static str, jsonl: &'static str) -> Self {
        let json_lines: Vec<&str> = jsonl.lines().filter(|l| !l.is_empty()).collect();
        let notes: Vec<NoteBuf> = json_lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("valid JSON"))
            .collect();

        let notepack_bytes: Vec<Vec<u8>> = notes
            .iter()
            .map(|n| pack_note(n).expect("pack ok"))
            .collect();

        let notepack_b64: Vec<String> = notes
            .iter()
            .map(|n| pack_note_to_string(n).expect("pack b64 ok"))
            .collect();

        let total_json_bytes: u64 = json_lines.iter().map(|l| l.len() as u64).sum();
        let total_notepack_bytes: u64 = notepack_bytes.iter().map(|b| b.len() as u64).sum();

        Self {
            name,
            json_lines,
            notes,
            notepack_bytes,
            notepack_b64,
            total_json_bytes,
            total_notepack_bytes,
        }
    }
}

// Load all corpora at compile time
macro_rules! load_corpus {
    ($name:literal, $file:literal) => {
        KindCorpus::load($name, include_str!(concat!("by_kind/", $file)))
    };
}

fn load_all_corpora() -> Vec<KindCorpus> {
    vec![
        load_corpus!("kind_0_metadata", "kind_0_metadata.jsonl"),
        load_corpus!("kind_1_notes", "kind_1_notes.jsonl"),
        load_corpus!("kind_3_follows", "kind_3_follows.jsonl"),
        load_corpus!("kind_5_deletion", "kind_5_deletion.jsonl"),
        load_corpus!("kind_6_repost", "kind_6_repost.jsonl"),
        load_corpus!("kind_7_reaction", "kind_7_reaction.jsonl"),
        load_corpus!("kind_1059_giftwrap", "kind_1059_giftwrap.jsonl"),
        load_corpus!("kind_9735_zap", "kind_9735_zap.jsonl"),
        load_corpus!("kind_10002_relays", "kind_10002_relays.jsonl"),
        load_corpus!("kind_30023_article", "kind_30023_article.jsonl"),
    ]
}

/// Benchmark: JSON string → NoteBuf (serde_json)
fn bench_json_decode(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/json_decode");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_json_bytes));
        group.bench_with_input(
            BenchmarkId::new("parse", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for line in &corpus.json_lines {
                        let note: NoteBuf = serde_json::from_str(black_box(line)).expect("ok");
                        black_box(note);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: NoteBuf → JSON string (serde_json)
fn bench_json_encode(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/json_encode");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_json_bytes));
        group.bench_with_input(
            BenchmarkId::new("encode", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for note in &corpus.notes {
                        let s = serde_json::to_string(black_box(note)).expect("ok");
                        black_box(s);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: NoteBuf → notepack bytes
fn bench_notepack_encode(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/notepack_encode");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_notepack_bytes));
        group.bench_with_input(
            BenchmarkId::new("encode", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for note in &corpus.notes {
                        let bytes = pack_note(black_box(note)).expect("ok");
                        black_box(bytes);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: NoteBuf → notepack base64 string
fn bench_notepack_encode_b64(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/notepack_encode_b64");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_notepack_bytes));
        group.bench_with_input(
            BenchmarkId::new("encode_b64", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for note in &corpus.notes {
                        let s = pack_note_to_string(black_box(note)).expect("ok");
                        black_box(s);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: notepack bytes → Note (lazy, header only)
fn bench_notepack_decode(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/notepack_decode");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_notepack_bytes));
        group.bench_with_input(
            BenchmarkId::new("into_note", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for bytes in &corpus.notepack_bytes {
                        let note = NoteParser::new(black_box(bytes))
                            .into_note()
                            .expect("ok");
                        black_box(note);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: notepack bytes → Note + iterate all tags
fn bench_notepack_decode_full(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/notepack_decode_full");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_notepack_bytes));
        group.bench_with_input(
            BenchmarkId::new("into_note+tags", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    let mut acc = 0usize;
                    for bytes in &corpus.notepack_bytes {
                        let note = NoteParser::new(black_box(bytes))
                            .into_note()
                            .expect("ok");

                        // Drain all tags to force full parsing
                        let mut tags = note.tags;
                        while let Some(mut elems) = tags.next_tag().expect("ok") {
                            for item in &mut elems {
                                match item.expect("ok") {
                                    StringType::Str(s) => acc += s.len(),
                                    StringType::Bytes(bs) => acc += bs.len(),
                                }
                            }
                        }
                    }
                    black_box(acc);
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: notepack base64 → bytes → Note
fn bench_notepack_decode_b64(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/notepack_decode_b64");
    for corpus in &corpora {
        let total_b64_bytes: u64 = corpus.notepack_b64.iter().map(|s| s.len() as u64).sum();
        group.throughput(Throughput::Bytes(total_b64_bytes));
        group.bench_with_input(
            BenchmarkId::new("decode+parse", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for b64 in &corpus.notepack_b64 {
                        let bytes = NoteParser::decode(black_box(b64)).expect("ok");
                        let note = NoteParser::new(&bytes).into_note().expect("ok");
                        black_box(note);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Full roundtrip NoteBuf → notepack → Note → NoteBuf
fn bench_roundtrip(c: &mut Criterion) {
    let corpora = load_all_corpora();

    let mut group = c.benchmark_group("by_kind/roundtrip");
    for corpus in &corpora {
        group.throughput(Throughput::Bytes(corpus.total_notepack_bytes));
        group.bench_with_input(
            BenchmarkId::new("full", corpus.name),
            corpus,
            |b, corpus| {
                b.iter(|| {
                    for note in &corpus.notes {
                        let bytes = pack_note(black_box(note)).expect("ok");
                        let parsed = NoteParser::new(&bytes).into_note().expect("ok");
                        let owned = parsed.to_owned().expect("ok");
                        black_box(owned);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Aggregate benchmark: all events combined
fn bench_aggregate(c: &mut Criterion) {
    let corpora = load_all_corpora();

    // Flatten all notes into one big batch
    let all_notes: Vec<&NoteBuf> = corpora.iter().flat_map(|c| &c.notes).collect();
    let all_notepack: Vec<&Vec<u8>> = corpora.iter().flat_map(|c| &c.notepack_bytes).collect();
    let total_np_bytes: u64 = all_notepack.iter().map(|b| b.len() as u64).sum();
    let total_json_bytes: u64 = corpora.iter().map(|c| c.total_json_bytes).sum();

    let mut group = c.benchmark_group("aggregate");

    // Notepack encode all
    group.throughput(Throughput::Bytes(total_np_bytes));
    group.bench_function("notepack_encode_all", |b| {
        b.iter(|| {
            for note in &all_notes {
                let bytes = pack_note(black_box(*note)).expect("ok");
                black_box(bytes);
            }
        });
    });

    // Notepack decode all
    group.throughput(Throughput::Bytes(total_np_bytes));
    group.bench_function("notepack_decode_all", |b| {
        b.iter(|| {
            for bytes in &all_notepack {
                let note = NoteParser::new(black_box(*bytes)).into_note().expect("ok");
                black_box(note);
            }
        });
    });

    // JSON encode all (for comparison)
    group.throughput(Throughput::Bytes(total_json_bytes));
    group.bench_function("json_encode_all", |b| {
        b.iter(|| {
            for note in &all_notes {
                let s = serde_json::to_string(black_box(*note)).expect("ok");
                black_box(s);
            }
        });
    });

    group.finish();
}

/// Print a comparison summary table at the end
fn print_comparison_table(_c: &mut Criterion) {
    use std::time::Instant;

    let corpora = load_all_corpora();
    let all_notes: Vec<&NoteBuf> = corpora.iter().flat_map(|c| &c.notes).collect();
    let all_notepack: Vec<Vec<u8>> = all_notes
        .iter()
        .map(|n| pack_note(n).expect("ok"))
        .collect();
    let all_json: Vec<String> = all_notes
        .iter()
        .map(|n| serde_json::to_string(n).expect("ok"))
        .collect();

    let iterations = 20;

    // Measure JSON encode
    let start = Instant::now();
    for _ in 0..iterations {
        for note in &all_notes {
            black_box(serde_json::to_string(black_box(*note)).expect("ok"));
        }
    }
    let json_encode_ns = start.elapsed().as_nanos() / (iterations * all_notes.len() as u128);

    // Measure notepack encode
    let start = Instant::now();
    for _ in 0..iterations {
        for note in &all_notes {
            black_box(pack_note(black_box(*note)).expect("ok"));
        }
    }
    let np_encode_ns = start.elapsed().as_nanos() / (iterations * all_notes.len() as u128);

    // Measure JSON decode
    let start = Instant::now();
    for _ in 0..iterations {
        for json in &all_json {
            let n: NoteBuf = serde_json::from_str(black_box(json)).expect("ok");
            black_box(n);
        }
    }
    let json_decode_ns = start.elapsed().as_nanos() / (iterations * all_json.len() as u128);

    // Measure notepack decode (into_note, lazy)
    let start = Instant::now();
    for _ in 0..iterations {
        for bytes in &all_notepack {
            let note = NoteParser::new(black_box(bytes)).into_note().expect("ok");
            black_box(note);
        }
    }
    let np_decode_ns = start.elapsed().as_nanos() / (iterations * all_notepack.len() as u128);

    // Measure notepack decode full (with tag iteration)
    let start = Instant::now();
    for _ in 0..iterations {
        for bytes in &all_notepack {
            let note = NoteParser::new(black_box(bytes)).into_note().expect("ok");
            let mut tags = note.tags;
            while let Some(mut elems) = tags.next_tag().expect("ok") {
                for item in &mut elems {
                    black_box(item.expect("ok"));
                }
            }
        }
    }
    let np_decode_full_ns = start.elapsed().as_nanos() / (iterations * all_notepack.len() as u128);

    // Calculate sizes
    let total_json_bytes: usize = all_json.iter().map(|s| s.len()).sum();
    let total_np_bytes: usize = all_notepack.iter().map(|b| b.len()).sum();
    let compression = 100.0 * (1.0 - (total_np_bytes as f64 / total_json_bytes as f64));

    // Print table
    eprintln!("\n");
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║              NOTEPACK vs JSON COMPARISON ({:4} events)           ║", all_notes.len());
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  Operation          │    JSON     │  notepack   │   Speedup     ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Encode             │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_encode_ns, np_encode_ns, format_speedup(json_encode_ns, np_encode_ns)
    );
    eprintln!(
        "║  Decode             │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_decode_ns, np_decode_ns, format_speedup(json_decode_ns, np_decode_ns)
    );
    eprintln!(
        "║  Decode (full)      │ {:>7} ns  │ {:>7} ns  │  {} ║",
        json_decode_ns, np_decode_full_ns, format_speedup(json_decode_ns, np_decode_full_ns)
    );
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Total size         │ {:>9}  │ {:>9}  │  {:>4.1}% smaller ║",
        format_bytes(total_json_bytes),
        format_bytes(total_np_bytes),
        compression
    );
    eprintln!(
        "║  Avg event size     │ {:>9}  │ {:>9}  │                 ║",
        format_bytes(total_json_bytes / all_notes.len()),
        format_bytes(total_np_bytes / all_notes.len())
    );
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
}

criterion_group!(
    benches,
    bench_json_decode,
    bench_json_encode,
    bench_notepack_encode,
    bench_notepack_encode_b64,
    bench_notepack_decode,
    bench_notepack_decode_full,
    bench_notepack_decode_b64,
    bench_roundtrip,
    bench_aggregate,
    print_comparison_table,
);

criterion_main!(benches);

