//! Shared helper functions for benchmarks.

/// Format a byte count as a human-readable string (KB, MB, etc.)
pub fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a speedup ratio as "Nx faster" or "Nx slower"
pub fn format_speedup(json_ns: u128, np_ns: u128) -> String {
    let ratio = json_ns as f64 / np_ns as f64;
    if ratio >= 1.0 {
        format!("{:>5.1}x faster", ratio)
    } else {
        format!("{:>5.1}x slower", 1.0 / ratio)
    }
}

