/// Represents a parsed tag element from a notepack payload.
///
/// Tag elements in notepack can be either:
/// - **Text** ([`StringType::Str`]): A UTF-8 string stored as-is
/// - **Bytes** ([`StringType::Bytes`]): Raw bytes, typically used for hex-encoded
///   values like public keys or event IDs that were compacted during encoding
///
/// During encoding, strings that look like lowercase hex are automatically
/// compacted to raw bytes. During decoding, you receive either variant and
/// can convert bytes back to hex strings if needed.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteParser, StringType};
///
/// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
/// let note = NoteParser::new(&bytes).into_note().unwrap();
/// let mut tags = note.tags.clone();
///
/// while let Some(mut elems) = tags.next_tag().unwrap() {
///     for elem in &mut elems {
///         match elem.unwrap() {
///             StringType::Str(s) => println!("text: {s}"),
///             StringType::Bytes(bs) => {
///                 // Convert raw bytes back to hex string
///                 let hex = hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower);
///                 println!("hex: {hex}");
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringType<'a> {
    /// Raw bytes, typically a compacted hex value (pubkey, event ID, etc.).
    Bytes(&'a [u8]),
    /// A UTF-8 string element.
    Str(&'a str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_type_str_variant() {
        let st = StringType::Str("hello");
        assert!(matches!(st, StringType::Str("hello")));
    }

    #[test]
    fn string_type_bytes_variant() {
        let data = [0xaa, 0xbb, 0xcc];
        let st = StringType::Bytes(&data);
        assert!(matches!(st, StringType::Bytes(_)));
        if let StringType::Bytes(bs) = st {
            assert_eq!(bs, &[0xaa, 0xbb, 0xcc]);
        }
    }

    #[test]
    fn string_type_debug_str() {
        let st = StringType::Str("test");
        let debug = format!("{:?}", st);
        assert!(debug.contains("Str"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn string_type_debug_bytes() {
        let st = StringType::Bytes(&[0xde, 0xad]);
        let debug = format!("{:?}", st);
        assert!(debug.contains("Bytes"));
    }

    #[test]
    fn string_type_clone() {
        let original = StringType::Str("clone me");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn string_type_eq_str() {
        let a = StringType::Str("same");
        let b = StringType::Str("same");
        let c = StringType::Str("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn string_type_eq_bytes() {
        let a = StringType::Bytes(&[1, 2, 3]);
        let b = StringType::Bytes(&[1, 2, 3]);
        let c = StringType::Bytes(&[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn string_type_different_variants_not_equal() {
        let str_type = StringType::Str("abc");
        let bytes_type = StringType::Bytes(b"abc");
        assert_ne!(str_type, bytes_type);
    }

    #[test]
    fn string_type_empty_str() {
        let st = StringType::Str("");
        assert!(matches!(st, StringType::Str("")));
    }

    #[test]
    fn string_type_empty_bytes() {
        let st = StringType::Bytes(&[]);
        if let StringType::Bytes(bs) = st {
            assert!(bs.is_empty());
        }
    }
}
