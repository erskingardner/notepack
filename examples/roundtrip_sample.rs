//! Roundtrip test for all events in `data/sample.jsonl`.
//!
//! This example reads Nostr events from a JSONL file, encodes each to notepack
//! format, decodes it back, and verifies the roundtrip. Panics on any error.
//!
//! Events exceeding the MAX_ALLOCATION_SIZE limit are tracked separately.
//!
//! Run with: `cargo run --example roundtrip_sample`

use notepack::{Error, NoteBuf, NoteParser, pack_note, MAX_ALLOCATION_SIZE};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn main() {
    let path = "data/sample.jsonl";
    let file = File::open(path).unwrap_or_else(|e| panic!("Failed to open {path}: {e}"));
    let reader = BufReader::new(file);

    let mut kind_counts: HashMap<u64, usize> = HashMap::new();
    let mut skipped_counts: HashMap<u64, usize> = HashMap::new();
    let mut total = 0usize;
    let mut skipped = 0usize;
    let mut total_json_bytes = 0usize;
    let mut total_notepack_bytes = 0usize;

    let start = Instant::now();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.unwrap_or_else(|e| {
            panic!("Failed to read line {}: {e}", line_num + 1);
        });

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        total_json_bytes += line.len();

        // Parse JSON to NoteBuf
        let note: NoteBuf = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!(
                "Failed to parse JSON at line {}: {e}\nLine: {}",
                line_num + 1,
                &line[..line.len().min(200)]
            );
        });

        // Encode to notepack binary
        let packed = pack_note(&note).unwrap_or_else(|e| {
            panic!(
                "Failed to encode note at line {} (kind {}): {e}",
                line_num + 1,
                note.kind
            );
        });

        total_notepack_bytes += packed.len();

        // Decode back - handle allocation limit gracefully
        let parsed = match NoteParser::new(&packed).into_note() {
            Ok(p) => p,
            Err(Error::AllocationLimitExceeded { requested, limit }) => {
                // Events with content exceeding MAX_ALLOCATION_SIZE are tracked separately
                eprintln!(
                    "⚠ Line {}: kind {} skipped (content {} bytes > {} limit)",
                    line_num + 1,
                    note.kind,
                    requested,
                    limit
                );
                *skipped_counts.entry(note.kind).or_insert(0) += 1;
                skipped += 1;
                continue;
            }
            Err(e) => {
                panic!(
                    "Failed to parse notepack at line {} (kind {}): {e}",
                    line_num + 1,
                    note.kind
                );
            }
        };

        // Convert to owned to verify all tags
        let recovered = parsed.to_owned().unwrap_or_else(|e| {
            panic!(
                "Failed to convert to owned at line {} (kind {}): {e}",
                line_num + 1,
                note.kind
            );
        });

        // Verify roundtrip
        assert_eq!(
            note.id, recovered.id,
            "ID mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.pubkey, recovered.pubkey,
            "Pubkey mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.sig, recovered.sig,
            "Sig mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.created_at, recovered.created_at,
            "Timestamp mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.kind, recovered.kind,
            "Kind mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.content, recovered.content,
            "Content mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );
        assert_eq!(
            note.tags, recovered.tags,
            "Tags mismatch at line {} (kind {})",
            line_num + 1,
            note.kind
        );

        *kind_counts.entry(note.kind).or_insert(0) += 1;
        total += 1;
    }

    let elapsed = start.elapsed();

    println!("\n✓ Roundtrip successful for {total} events!\n");

    // Sort kinds for display
    let mut kinds: Vec<_> = kind_counts.into_iter().collect();
    kinds.sort_by_key(|(k, _)| *k);

    println!("Events by kind:");
    println!("{:-<40}", "");
    for (kind, count) in &kinds {
        println!("  kind {kind:>5}: {count:>6} events");
    }
    println!("{:-<40}", "");
    println!("  {:>10}: {total:>6} events\n", "total");

    // Show skipped events if any
    if skipped > 0 {
        println!(
            "Skipped {} events (content > {} bytes):",
            skipped, MAX_ALLOCATION_SIZE
        );
        let mut skipped_kinds: Vec<_> = skipped_counts.into_iter().collect();
        skipped_kinds.sort_by_key(|(k, _)| *k);
        for (kind, count) in &skipped_kinds {
            println!("  kind {kind:>5}: {count:>6} events");
        }
        println!();
    }

    let compression = if total_json_bytes > 0 {
        100.0 - (total_notepack_bytes as f64 / total_json_bytes as f64 * 100.0)
    } else {
        0.0
    };

    println!("Size comparison:");
    println!("  JSON:     {:>10} bytes", total_json_bytes);
    println!("  Notepack: {:>10} bytes", total_notepack_bytes);
    println!("  Savings:  {:>10.1}%\n", compression);

    let events_per_sec = if elapsed.as_secs_f64() > 0.0 {
        total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!("Performance:");
    println!("  Time:     {:>10.2?}", elapsed);
    println!("  Rate:     {:>10.0} events/sec", events_per_sec);
}

