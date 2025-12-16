//! Roundtrip test and API demonstration for notepack.
//!
//! This example demonstrates:
//! 1. **Roundtrip verification** — JSON → notepack → JSON
//! 2. **NoteBinary API** — faster serialization with binary data
//! 3. **Field accessors** — O(1) filtering without full deserialization
//! 4. **Buffer reuse** — batch serialization optimization
//!
//! Run with: `cargo run --example roundtrip_sample`
//!
//! With release optimizations: `cargo run --release --example roundtrip_sample`

use notepack::{Error, NoteBinary, NoteBuf, NoteParser, pack_note};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

/// Parsed event with binary fields for benchmarking NoteBinary
struct BinaryEvent {
    id: [u8; 32],
    pubkey: [u8; 32],
    sig: [u8; 64],
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
}

impl BinaryEvent {
    /// Parse from NoteBuf, converting hex strings to binary
    fn from_notebuf(note: &NoteBuf) -> Option<Self> {
        let id_bytes = hex_simd::decode_to_vec(&note.id).ok()?;
        let pubkey_bytes = hex_simd::decode_to_vec(&note.pubkey).ok()?;
        let sig_bytes = hex_simd::decode_to_vec(&note.sig).ok()?;

        if id_bytes.len() != 32 || pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
            return None;
        }

        let mut id = [0u8; 32];
        let mut pubkey = [0u8; 32];
        let mut sig = [0u8; 64];

        id.copy_from_slice(&id_bytes);
        pubkey.copy_from_slice(&pubkey_bytes);
        sig.copy_from_slice(&sig_bytes);

        Some(Self {
            id,
            pubkey,
            sig,
            created_at: note.created_at,
            kind: note.kind,
            tags: note.tags.clone(),
            content: note.content.clone(),
        })
    }

    /// Create a NoteBinary reference for fast serialization
    fn as_binary(&self) -> NoteBinary<'_> {
        NoteBinary {
            id: &self.id,
            pubkey: &self.pubkey,
            sig: &self.sig,
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
        }
    }
}

fn main() {
    let path = "data/sample.jsonl";
    let file = File::open(path).unwrap_or_else(|e| panic!("Failed to open {path}: {e}"));
    let reader = BufReader::new(file);

    // Collect all events first
    let mut notes: Vec<NoteBuf> = Vec::new();
    let mut binary_events: Vec<BinaryEvent> = Vec::new();
    let mut total_json_bytes = 0usize;

    println!("Loading events from {path}...");

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.unwrap_or_else(|e| {
            panic!("Failed to read line {}: {e}", line_num + 1);
        });

        if line.trim().is_empty() {
            continue;
        }

        total_json_bytes += line.len();

        let note: NoteBuf = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!(
                "Failed to parse JSON at line {}: {e}\nLine: {}",
                line_num + 1,
                &line[..line.len().min(200)]
            );
        });

        // Also create binary version for NoteBinary benchmarks
        if let Some(binary) = BinaryEvent::from_notebuf(&note) {
            binary_events.push(binary);
        }

        notes.push(note);
    }

    println!("Loaded {} events ({} bytes JSON)\n", notes.len(), total_json_bytes);

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. Roundtrip verification
    // ─────────────────────────────────────────────────────────────────────────────

    println!("═══════════════════════════════════════════════════════════════════");
    println!("1. ROUNDTRIP VERIFICATION");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let mut kind_counts: HashMap<u64, usize> = HashMap::new();
    let mut skipped = 0usize;
    let mut total_notepack_bytes = 0usize;

    let start = Instant::now();

    for (i, note) in notes.iter().enumerate() {
        let packed = pack_note(note).unwrap_or_else(|e| {
            panic!("Failed to encode note {} (kind {}): {e}", i, note.kind);
        });

        total_notepack_bytes += packed.len();

        let parsed = match NoteParser::new(&packed).into_note() {
            Ok(p) => p,
            Err(Error::AllocationLimitExceeded { .. }) => {
                skipped += 1;
                continue;
            }
            Err(e) => panic!("Failed to parse note {} (kind {}): {e}", i, note.kind),
        };

        let recovered = parsed.to_owned().unwrap();

        // Verify all fields
        assert_eq!(note.id, recovered.id, "ID mismatch at {i}");
        assert_eq!(note.pubkey, recovered.pubkey, "Pubkey mismatch at {i}");
        assert_eq!(note.sig, recovered.sig, "Sig mismatch at {i}");
        assert_eq!(note.created_at, recovered.created_at, "Timestamp mismatch at {i}");
        assert_eq!(note.kind, recovered.kind, "Kind mismatch at {i}");
        assert_eq!(note.content, recovered.content, "Content mismatch at {i}");
        assert_eq!(note.tags, recovered.tags, "Tags mismatch at {i}");

        *kind_counts.entry(note.kind).or_insert(0) += 1;
    }

    let roundtrip_time = start.elapsed();
    let total = notes.len() - skipped;

    println!("✓ Roundtrip verified for {total} events ({skipped} skipped)\n");

    // Size comparison
    let compression = 100.0 - (total_notepack_bytes as f64 / total_json_bytes as f64 * 100.0);
    println!("Size comparison:");
    println!("  JSON:     {:>10} bytes", total_json_bytes);
    println!("  Notepack: {:>10} bytes", total_notepack_bytes);
    println!("  Savings:  {:>10.1}%\n", compression);

    // Kind breakdown
    let mut kinds: Vec<_> = kind_counts.into_iter().collect();
    kinds.sort_by_key(|(k, _)| *k);
    println!("Events by kind:");
    for (kind, count) in &kinds {
        println!("  kind {kind:>5}: {count:>6}");
    }
    println!();

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. Serialization benchmark: NoteBuf vs NoteBinary
    // ─────────────────────────────────────────────────────────────────────────────

    println!("═══════════════════════════════════════════════════════════════════");
    println!("2. SERIALIZATION BENCHMARK: NoteBuf vs NoteBinary");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Benchmark NoteBuf (hex strings → decode → serialize)
    let start = Instant::now();
    let mut notebuf_bytes = 0usize;
    for note in &notes {
        let packed = pack_note(note).unwrap();
        notebuf_bytes += packed.len();
    }
    let notebuf_time = start.elapsed();

    // Benchmark NoteBinary (binary data → serialize directly)
    let start = Instant::now();
    let mut notebinary_bytes = 0usize;
    for event in &binary_events {
        let packed = event.as_binary().pack();
        notebinary_bytes += packed.len();
    }
    let notebinary_time = start.elapsed();

    // Benchmark NoteBinary with buffer reuse
    let start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    for event in &binary_events {
        buf.clear();
        event.as_binary().pack_into(&mut buf);
    }
    let notebinary_reuse_time = start.elapsed();

    println!("Serializing {} events:\n", notes.len());
    println!(
        "  NoteBuf (hex strings):     {:>8.2?}  ({:.0} events/sec)",
        notebuf_time,
        notes.len() as f64 / notebuf_time.as_secs_f64()
    );
    println!(
        "  NoteBinary (binary refs):  {:>8.2?}  ({:.0} events/sec)",
        notebinary_time,
        binary_events.len() as f64 / notebinary_time.as_secs_f64()
    );
    println!(
        "  NoteBinary + buffer reuse: {:>8.2?}  ({:.0} events/sec)",
        notebinary_reuse_time,
        binary_events.len() as f64 / notebinary_reuse_time.as_secs_f64()
    );

    let speedup = notebuf_time.as_secs_f64() / notebinary_time.as_secs_f64();
    let speedup_reuse = notebuf_time.as_secs_f64() / notebinary_reuse_time.as_secs_f64();
    println!("\n  NoteBinary speedup:        {speedup:.1}x faster");
    println!("  With buffer reuse:         {speedup_reuse:.1}x faster\n");

    // Verify same output size
    assert_eq!(
        notebuf_bytes, notebinary_bytes,
        "NoteBuf and NoteBinary should produce identical output"
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. Field accessor demo: fast filtering
    // ─────────────────────────────────────────────────────────────────────────────

    println!("═══════════════════════════════════════════════════════════════════");
    println!("3. FIELD ACCESSORS: Fast Filtering Demo");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // First, pack all events to notepack bytes (simulating stored data)
    let packed_events: Vec<Vec<u8>> = notes
        .iter()
        .filter_map(|n| pack_note(n).ok())
        .collect();

    println!("Simulating relay filter queries on {} stored events:\n", packed_events.len());

    // Query 1: Filter by kind (text notes, kind=1)
    let start = Instant::now();
    let mut kind1_count = 0usize;
    for bytes in &packed_events {
        let parser = NoteParser::new(bytes);
        if let Ok(kind) = parser.read_kind() {
            if kind == 1 {
                kind1_count += 1;
            }
        }
    }
    let kind_filter_time = start.elapsed();

    // Compare with full deserialization
    let start = Instant::now();
    let mut kind1_full = 0usize;
    for bytes in &packed_events {
        if let Ok(note) = NoteParser::new(bytes).into_note() {
            if note.kind == 1 {
                kind1_full += 1;
            }
        }
    }
    let full_deser_time = start.elapsed();
    assert_eq!(kind1_count, kind1_full);

    println!("Query: kind == 1");
    println!("  Found: {kind1_count} events");
    println!(
        "  read_kind():    {:>8.2?}  ({:.0} ops/sec)",
        kind_filter_time,
        packed_events.len() as f64 / kind_filter_time.as_secs_f64()
    );
    println!(
        "  Full deser:     {:>8.2?}  ({:.0} ops/sec)",
        full_deser_time,
        packed_events.len() as f64 / full_deser_time.as_secs_f64()
    );
    let filter_speedup = full_deser_time.as_secs_f64() / kind_filter_time.as_secs_f64();
    println!("  Speedup:        {filter_speedup:.1}x faster\n");

    // Query 2: Filter by pubkey (first event's author)
    if let Some(first_bytes) = packed_events.first() {
        if let Ok(target_pubkey) = NoteParser::new(first_bytes).read_pubkey() {
            let target = *target_pubkey;

            let start = Instant::now();
            let mut pubkey_matches = 0usize;
            for bytes in &packed_events {
                let parser = NoteParser::new(bytes);
                if let Ok(pk) = parser.read_pubkey() {
                    if pk == &target {
                        pubkey_matches += 1;
                    }
                }
            }
            let pubkey_filter_time = start.elapsed();

            println!("Query: pubkey == <first event's author>");
            println!("  Found: {pubkey_matches} events");
            println!(
                "  read_pubkey():  {:>8.2?}  (O(1) field access)",
                pubkey_filter_time
            );
        }
    }

    // Query 3: Combined filter (kind + time range)
    let since = 1700000000u64;
    let until = 1800000000u64;

    let start = Instant::now();
    let mut combined_matches = 0usize;
    for bytes in &packed_events {
        let parser = NoteParser::new(bytes);
        if let Ok((created_at, kind)) = parser.read_created_at_and_kind() {
            if kind == 1 && created_at >= since && created_at <= until {
                combined_matches += 1;
            }
        }
    }
    let combined_filter_time = start.elapsed();

    println!("\nQuery: kind == 1 AND created_at in [{since}, {until}]");
    println!("  Found: {combined_matches} events");
    println!(
        "  Combined accessor: {:>8.2?}",
        combined_filter_time
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // Summary
    // ─────────────────────────────────────────────────────────────────────────────

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("SUMMARY");
    println!("═══════════════════════════════════════════════════════════════════\n");

    println!("Total roundtrip time: {:?}", roundtrip_time);
    println!(
        "Throughput: {:.0} events/sec\n",
        total as f64 / roundtrip_time.as_secs_f64()
    );

    println!("Key takeaways:");
    println!("  • NoteBinary with buffer reuse: {speedup_reuse:.1}x faster serialization");
    println!("  • Field accessors: {filter_speedup:.1}x faster than full deserialization");
    println!("  • Notepack: {compression:.1}% smaller than JSON");
    println!();
    println!("Note: NoteBinary shines when you already have binary data (from crypto ops,");
    println!("database storage, etc.) and avoid hex string conversion entirely.");
}
