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
/// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA").unwrap();
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
#[derive(Debug, Clone)]
pub enum StringType<'a> {
    /// Raw bytes, typically a compacted hex value (pubkey, event ID, etc.).
    Bytes(&'a [u8]),
    /// A UTF-8 string element.
    Str(&'a str),
}
