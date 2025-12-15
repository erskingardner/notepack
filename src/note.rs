use crate::Error;
use crate::parser::read_string;
use crate::stringtype::StringType;
use crate::varint::{read_tagged_varint, read_varint};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

/// An owned Nostr note ready for encoding to notepack format.
///
/// This struct represents a Nostr event with all fields owned as `String` or `Vec`.
/// It can be serialized to/from JSON via serde, and packed into the compact
/// notepack binary format using [`pack_note`](crate::pack_note) or related functions.
///
/// # Fields
///
/// All hex-encoded fields (`id`, `pubkey`, `sig`) must use **lowercase** hex for
/// round-trip encoding to work correctly.
///
/// # Example
///
/// ```rust
/// use notepack::{NoteBuf, pack_note_to_string};
///
/// let note = NoteBuf {
///     id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
///     pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
///     created_at: 1700000000,
///     kind: 1,
///     tags: vec![vec!["p".into(), "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into()]],
///     content: "Hello, Nostr!".into(),
///     sig: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
/// };
///
/// let packed = pack_note_to_string(&note).unwrap();
/// assert!(packed.starts_with("notepack_"));
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NoteBuf {
    /// 32-byte SHA-256 hash of the serialized event data (64 hex chars, lowercase).
    pub id: String,
    /// 32-byte secp256k1 public key of the event creator (64 hex chars, lowercase).
    pub pubkey: String,
    /// Unix timestamp in seconds when the event was created.
    pub created_at: u64,
    /// Event kind as defined by Nostr NIPs (e.g., 1 for text notes).
    pub kind: u64,
    /// Array of tags, where each tag is an array of strings.
    pub tags: Vec<Vec<String>>,
    /// Arbitrary string content of the event.
    pub content: String,
    /// 64-byte Schnorr signature of the event ID (128 hex chars, lowercase).
    pub sig: String,
}

/// A Nostr note in notepack format (zero-copy, borrowed).
///
/// This struct holds references into the original notepack binary data.
/// Use [`Note::to_owned`] to convert to a [`NoteBuf`] if you need owned data.
#[derive(Debug, Clone)]
pub struct Note<'a> {
    /// 32-bytes sha256 of the the serialized event data
    pub id: &'a [u8; 32],
    /// 32-bytes hex-encoded public key of the event creator
    pub pubkey: &'a [u8; 32],
    /// 64-bytes signature of the sha256 hash of the serialized event data, which is the same as the "id" field
    pub sig: &'a [u8; 64],
    /// arbitrary string
    pub content: &'a str,
    /// unix timestamp in seconds
    pub created_at: u64,
    /// integer
    /// 0: NostrEvent
    pub kind: u64,
    /// Tags
    pub tags: Tags<'a>,
}

impl<'a> Note<'a> {
    /// Convert this borrowed [`Note`] to an owned [`NoteBuf`].
    ///
    /// This iterates through all tags and converts them to strings:
    /// - Text elements are copied as-is
    /// - Byte elements are hex-encoded (lowercase)
    ///
    /// # Errors
    ///
    /// Returns an error if tag iteration encounters malformed data (e.g., truncated
    /// input or invalid UTF-8).
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA").unwrap();
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    /// let owned = note.to_owned().unwrap();
    /// assert_eq!(owned.content, "hi");
    /// ```
    pub fn to_owned(&self) -> Result<NoteBuf, Error> {
        // The tag count is attacker-controlled when parsing arbitrary bytes. Avoid preallocating
        // absurd amounts by bounding capacity by remaining bytes (each tag requires >=1 byte).
        let tags_cap = (self.tags.len()).min(self.tags.data.len() as u64) as usize;
        let mut tags_vec: Vec<Vec<String>> = Vec::with_capacity(tags_cap);
        let mut tags = self.tags.clone();

        while let Some(mut elems) = tags.next_tag()? {
            // Same idea for tag element count (each element requires >=1 byte).
            let elems_cap = (elems.remaining).min(elems.cursor.len() as u64) as usize;
            let mut tag_vec: Vec<String> = Vec::with_capacity(elems_cap);
            for elem in &mut elems {
                match elem? {
                    StringType::Str(s) => tag_vec.push(s.to_string()),
                    StringType::Bytes(bs) => {
                        tag_vec.push(hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower))
                    }
                }
            }
            tags_vec.push(tag_vec);
        }

        Ok(NoteBuf {
            id: hex_simd::encode_to_string(self.id, hex_simd::AsciiCase::Lower),
            pubkey: hex_simd::encode_to_string(self.pubkey, hex_simd::AsciiCase::Lower),
            sig: hex_simd::encode_to_string(self.sig, hex_simd::AsciiCase::Lower),
            content: self.content.to_string(),
            created_at: self.created_at,
            kind: self.kind,
            tags: tags_vec,
        })
    }
}

impl<'a> Serialize for Note<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // 7 fields per NIP-01: id, pubkey, created_at, kind, tags, content, sig
        let mut st = serializer.serialize_struct("Note", 7)?;

        // Hex-encode fixed-size fields (lowercase).
        st.serialize_field(
            "id",
            &hex_simd::encode_to_string(self.id, hex_simd::AsciiCase::Lower),
        )?;
        st.serialize_field(
            "pubkey",
            &hex_simd::encode_to_string(self.pubkey, hex_simd::AsciiCase::Lower),
        )?;
        st.serialize_field("created_at", &self.created_at)?;
        st.serialize_field("kind", &self.kind)?;

        // Materialize tags to Vec<Vec<String>> for JSON.
        // Strings pass through; raw bytes become lowercase hex strings.
        let tags_cap = (self.tags.len()).min(self.tags.data.len() as u64) as usize;
        let mut tags_json: Vec<Vec<String>> = Vec::with_capacity(tags_cap);
        let mut tags = self.tags.clone(); // don't mutate self

        while let Some(mut elems) = tags
            .next_tag()
            .map_err(|e| <S::Error as serde::ser::Error>::custom(e.to_string()))?
        {
            let elems_cap = (elems.remaining).min(elems.cursor.len() as u64) as usize;
            let mut tag_vec: Vec<String> = Vec::with_capacity(elems_cap);
            while let Some(elem) = elems
                .next()
                .transpose()
                .map_err(|e| <S::Error as serde::ser::Error>::custom(e.to_string()))?
            {
                match elem {
                    crate::stringtype::StringType::Str(s) => tag_vec.push(s.to_string()),
                    crate::stringtype::StringType::Bytes(bs) => {
                        tag_vec.push(hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower))
                    }
                }
            }
            tags_json.push(tag_vec);
        }

        st.serialize_field("tags", &tags_json)?;
        st.serialize_field("content", &self.content)?;
        st.serialize_field(
            "sig",
            &hex_simd::encode_to_string(self.sig, hex_simd::AsciiCase::Lower),
        )?;

        st.end()
    }
}

/// A **lazy view** over tags in a packed [`Note`].
///
/// This is returned by [`NoteParser::into_note()`](crate::NoteParser::into_note) or [`Tags::parse`].
/// It yields [`TagElems`] iterators—one for each tag block—without pre-scanning
/// or allocating. The underlying data is parsed lazily as you go.
///
/// Each tag is a sequence of elements (e.g. `["p", <pubkey>, "relay"]`), and
/// each element is either a UTF‑8 `str` or raw `&[u8]`, represented as [`StringType`].
///
/// # Example
///
/// ```rust
/// # use notepack::{NoteParser, StringType};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let packed = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA")?;
/// let note = NoteParser::new(&packed).into_note()?;
/// let mut tags = note.tags.clone();
///
/// while let Some(mut elems) = tags.next_tag()? {
///     for elem in &mut elems {
///         match elem? {
///             StringType::Str(s) => println!("str: {s}"),
///             StringType::Bytes(bs) => println!("hex: {}", hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower)),
///         }
///     }
/// }
/// # Ok(()) }
/// ```
///
/// # Notes
///
/// - Dropping a [`TagElems`] early will fast-forward to the next tag automatically.
/// - Use [`TagElems::finish()`] to explicitly surface errors from any skipped elements.
#[derive(Debug, Clone)]
pub struct Tags<'a> {
    data: &'a [u8], // cursor: at the next tag's num_elems varint
    remaining: u64, // tags left
}

/// A lazy iterator over the elements of a single tag.
///
/// Yields each tag element as a [`StringType`] (either a UTF‑8 string or raw bytes),
/// parsed directly from the packed data.
///
/// This struct implements [`Iterator`].
///
/// # Notes
///
/// - Dropping a partially-consumed `TagElems` will fast-forward past remaining elements,
///   so the parent [`Tags`] iterator stays aligned on the next tag.
/// - If you want to catch errors in skipped elements (e.g. malformed UTF-8 or truncation),
///   use [`TagElems::finish()`].
///
/// # Example
///
/// ```rust
/// # use notepack::{NoteParser, StringType};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA")?;
/// let note = NoteParser::new(&bytes).into_note()?;
/// let mut tags = note.tags.clone();
///
/// while let Some(mut elems) = tags.next_tag()? {
///     for elem in &mut elems {
///         match elem? {
///             StringType::Str(s) => println!("text: {s}"),
///             StringType::Bytes(bs) => println!("hex: {}", hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower)),
///         }
///     }
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct TagElems<'a, 'p> {
    cursor: &'p mut &'a [u8], // shared cursor with parent
    remaining: u64,           // elements left in this tag
}

impl<'a> Tags<'a> {
    /// Parse the tags block from a binary notepack cursor.
    ///
    /// This reads the `num_tags` varint from `input` and returns a lazy [`Tags`]
    /// iterator positioned at the first tag's element count.
    ///
    /// # Arguments
    ///
    /// * `input` - Mutable slice reference pointing to the tags block start
    ///   (the `num_tags` varint). The slice is advanced past the varint on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VarintUnterminated`](crate::Error::VarintUnterminated) or
    /// [`Error::VarintOverflow`](crate::Error::VarintOverflow) if the varint is malformed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA").unwrap();
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    /// // Tags are lazily parsed; check the count
    /// println!("tag count: {}", note.tags.len());
    /// ```
    pub fn parse(input: &mut &'a [u8]) -> Result<Self, Error> {
        let num_tags = read_varint(input)?;
        Ok(Self {
            data: *input,
            remaining: num_tags,
        })
    }

    /// Returns the number of tags remaining to iterate.
    ///
    /// This count decreases as you call [`next_tag`](Tags::next_tag).
    #[inline]
    pub fn len(&self) -> u64 {
        self.remaining
    }

    /// Returns `true` if there are no remaining tags to iterate.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    /// Advance to the next tag and return an iterator over its elements.
    ///
    /// Returns `Ok(None)` when all tags have been consumed. Each call reads
    /// only the tag's `num_elems` varint; element payloads are parsed lazily
    /// by the returned [`TagElems`] iterator.
    ///
    /// # Fast-Forward on Drop
    ///
    /// If you drop the [`TagElems`] early (without consuming all elements),
    /// it will automatically fast-forward past the remaining elements so
    /// the parent [`Tags`] cursor stays aligned on the next tag.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the `num_elems` varint fails.
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
    ///         println!("{:?}", elem.unwrap());
    ///     }
    /// }
    /// ```
    pub fn next_tag<'p>(&'p mut self) -> Result<Option<TagElems<'a, 'p>>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        // Read this tag's num_elems; leave cursor at the first element.
        let num_elems = read_varint(&mut self.data)?;
        self.remaining -= 1;
        Ok(Some(TagElems {
            cursor: &mut self.data,
            remaining: num_elems,
        }))
    }
}

impl<'a, 'p> TagElems<'a, 'p> {
    /// Returns the number of elements remaining in this tag.
    ///
    /// This count decreases as you iterate through elements.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA").unwrap();
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    /// let mut tags = note.tags.clone();
    ///
    /// if let Some(elems) = tags.next_tag().unwrap() {
    ///     assert_eq!(elems.remaining(), 2); // This tag has 2 elements
    /// }
    /// ```
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Explicitly consume all remaining elements, returning any errors encountered.
    ///
    /// Call this instead of dropping the iterator if you need to detect truncation
    /// or malformed data in elements you're not reading. The [`Drop`] implementation
    /// performs a best-effort fast-forward but silently ignores errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`](crate::Error::Truncated) if an element claims a
    /// length that exceeds the remaining data, or other errors if varints are malformed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_737yskaxtaKQSL3IPPhOOR8T1R4G/f4ARPHGeNPfOpF4417q9YtU+4JZGOD3+Y0S3uVU6/edo64oTqJQ0pOF29Ms7GmX6fzM4Wjc6sohGPlbdRGLjhuqIRccETX5DliwUFy9qGg2lDD9oMl8ijoNFq4wwJ5Ikmr4Vh7NYWBwOkuo/anEBgECaGkA").unwrap();
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    /// let mut tags = note.tags.clone();
    ///
    /// if let Some(elems) = tags.next_tag().unwrap() {
    ///     // Skip all elements but surface any errors
    ///     elems.finish().expect("tag elements should be valid");
    /// }
    /// ```
    pub fn finish(mut self) -> Result<(), Error> {
        while self.remaining > 0 {
            let (len, _is_bytes) = read_tagged_varint(self.cursor)?;
            let len: usize = usize::try_from(len).map_err(|_| Error::VarintOverflow)?;
            if self.cursor.len() < len {
                return Err(Error::Truncated);
            }
            *self.cursor = &self.cursor[len..];
            self.remaining -= 1;
        }
        Ok(())
    }
}

impl<'a, 'p> Iterator for TagElems<'a, 'p> {
    type Item = Result<StringType<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // Read one tagged string and advance the shared cursor.
        let item = read_string(self.cursor);
        match item {
            Ok(s) => {
                self.remaining -= 1;
                Some(Ok(s))
            }
            Err(e) => {
                // Poison the iterator; parent cursor is wherever the error occurred.
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }
}

/// Best‑effort fast‑forward on early drop so parent cursor lands at the next tag.
/// Errors can’t be propagated in Drop, so this intentionally ignores them.
/// If robust error handling matters, call `finish()` instead.
impl<'a, 'p> Drop for TagElems<'a, 'p> {
    fn drop(&mut self) {
        // If fully drained, do nothing.
        while self.remaining > 0 {
            if let Ok((len, _is_bytes)) = read_tagged_varint(self.cursor) {
                let Ok(len) = usize::try_from(len) else {
                    break; // length doesn't fit in usize; can't safely skip
                };
                if self.cursor.len() < len {
                    break; // truncated; leave cursor as-is
                }
                *self.cursor = &self.cursor[len..];
                self.remaining -= 1;
            } else {
                break; // malformed; leave cursor as-is
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::{write_tagged_varint, write_varint};

    fn push_elem_str(buf: &mut Vec<u8>, s: &str) {
        write_tagged_varint(buf, s.len() as u64, false);
        buf.extend_from_slice(s.as_bytes());
    }

    fn push_elem_bytes(buf: &mut Vec<u8>, bs: &[u8]) {
        write_tagged_varint(buf, bs.len() as u64, true);
        buf.extend_from_slice(bs);
    }

    /// Build a tags block:
    /// [varint num_tags] [varint num_elems][elem..] ... repeated
    fn build_tags_block(tags: &[Vec<ElemSpec>]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, tags.len() as u64);
        for tag in tags {
            write_varint(&mut buf, tag.len() as u64);
            for e in tag {
                match e {
                    ElemSpec::Str(s) => push_elem_str(&mut buf, s),
                    ElemSpec::Bytes(bs) => push_elem_bytes(&mut buf, bs),
                }
            }
        }
        buf
    }

    #[derive(Debug, Clone)]
    enum ElemSpec {
        Str(&'static str),
        Bytes(&'static [u8]),
    }

    #[test]
    fn tags_iterates_all_elements_correctly() -> Result<(), Error> {
        // tag0: ["p", 0xaabb (bytes), "hello"]
        // tag1: [""]
        let block = build_tags_block(&[
            vec![
                ElemSpec::Str("p"),
                ElemSpec::Bytes(&[0xaa, 0xbb]),
                ElemSpec::Str("hello"),
            ],
            vec![ElemSpec::Str("")],
        ]);

        let mut input = block.as_slice();

        // parse the block into a lazy Tags cursor
        let mut tags = Tags::parse(&mut input)?;
        assert_eq!(tags.len(), 2);
        assert!(!tags.is_empty());

        // tag 0
        {
            let mut t0 = tags.next_tag()?.expect("tag0");
            let mut out = Vec::new();
            for x in &mut t0 {
                match x? {
                    StringType::Str(s) => out.push(format!("S:{s}")),
                    StringType::Bytes(bs) => out.push(format!(
                        "B:{}",
                        hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower)
                    )),
                }
            }
            assert_eq!(out, &["S:p", "B:aabb", "S:hello"]);
        }

        // tag 1
        {
            let mut t1 = tags.next_tag()?.expect("tag1");
            let got = t1.next().expect("1 elem")?;
            match got {
                StringType::Str(s) => assert_eq!(s, ""),
                _ => panic!("expected empty string"),
            }
            assert!(t1.next().is_none());
        }

        // done
        assert!(tags.next_tag()?.is_none());
        Ok(())
    }

    #[test]
    fn dropping_tag_elems_early_fast_forwards_to_next_tag() -> Result<(), Error> {
        // tag0: ["a","b","c"] — we'll consume only the first elem then drop
        // tag1: ["z"]
        let block = build_tags_block(&[
            vec![ElemSpec::Str("a"), ElemSpec::Str("b"), ElemSpec::Str("c")],
            vec![ElemSpec::Str("z")],
        ]);

        let mut input = block.as_slice();
        let mut tags = Tags::parse(&mut input)?;

        // tag 0: consume one element and drop early
        {
            let mut t0 = tags.next_tag()?.expect("tag0");
            let first = t0.next().expect("has first")?;
            match first {
                StringType::Str("a") => {}
                _ => panic!("unexpected first element"),
            }
            // t0 dropped here with remaining=2; Drop should skip "b","c"
        }

        // We should now be aligned at tag1
        {
            let mut t1 = tags.next_tag()?.expect("tag1");
            let first = t1.next().expect("has z")?;
            match first {
                StringType::Str("z") => {}
                _ => panic!("expected 'z'"),
            }
            assert!(t1.next().is_none());
        }

        // No more tags
        assert!(tags.next_tag()?.is_none());
        Ok(())
    }

    #[test]
    fn finish_reports_truncation_error() {
        // Build a malformed tag:
        // num_tags=1, tag0 num_elems=1, element claims len=10 but provides only 3 bytes
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // one tag
        write_varint(&mut buf, 1); // one element
        write_tagged_varint(&mut buf, 10, false); // claim 10-byte UTF-8
        buf.extend_from_slice(b"abc"); // only 3 bytes -> truncated

        let mut input = buf.as_slice();
        let mut tags = Tags::parse(&mut input).expect("parse ok");
        let elems = tags.next_tag().expect("ok").expect("tag");

        // Using finish() should surface the error
        let err = elems.finish().unwrap_err();
        match err {
            Error::Truncated => {} // expected
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn tags_empty() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0); // zero tags

        let mut input = buf.as_slice();
        let mut tags = Tags::parse(&mut input).expect("parse ok");
        assert_eq!(tags.len(), 0);
        assert!(tags.is_empty());
        assert!(tags.next_tag().unwrap().is_none());
    }

    #[test]
    fn tag_elems_remaining_decrements() -> Result<(), Error> {
        let block = build_tags_block(&[vec![
            ElemSpec::Str("a"),
            ElemSpec::Str("b"),
            ElemSpec::Str("c"),
        ]]);

        let mut input = block.as_slice();
        let mut tags = Tags::parse(&mut input)?;
        let mut elems = tags.next_tag()?.unwrap();

        assert_eq!(elems.remaining(), 3);
        elems.next();
        assert_eq!(elems.remaining(), 2);
        elems.next();
        assert_eq!(elems.remaining(), 1);
        elems.next();
        assert_eq!(elems.remaining(), 0);
        assert!(elems.next().is_none());

        Ok(())
    }
}

#[cfg(test)]
mod to_owned_tests {
    use crate::NoteParser;

    fn make_test_note_bytes() -> Vec<u8> {
        use crate::varint::{write_tagged_varint, write_varint};

        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0xaa; 32]); // id
        buf.extend_from_slice(&[0xbb; 32]); // pubkey
        buf.extend_from_slice(&[0xcc; 64]); // sig
        write_varint(&mut buf, 1720000000); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 12); // content len
        buf.extend_from_slice(b"Hello, Nostr"); // content

        // Tags: [["e", <32-byte hex>], ["p", <32-byte hex>], ["t", "test"]]
        write_varint(&mut buf, 3); // num_tags

        // Tag 0: ["e", <hex>]
        write_varint(&mut buf, 2);
        write_tagged_varint(&mut buf, 1, false);
        buf.push(b'e');
        write_tagged_varint(&mut buf, 32, true);
        buf.extend_from_slice(&[0xdd; 32]);

        // Tag 1: ["p", <hex>]
        write_varint(&mut buf, 2);
        write_tagged_varint(&mut buf, 1, false);
        buf.push(b'p');
        write_tagged_varint(&mut buf, 32, true);
        buf.extend_from_slice(&[0xee; 32]);

        // Tag 2: ["t", "test"]
        write_varint(&mut buf, 2);
        write_tagged_varint(&mut buf, 1, false);
        buf.push(b't');
        write_tagged_varint(&mut buf, 4, false);
        buf.extend_from_slice(b"test");

        buf
    }

    #[test]
    fn to_owned_converts_id_pubkey_sig_to_hex() {
        let bytes = make_test_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert_eq!(
            owned.id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            owned.pubkey,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            owned.sig,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn to_owned_preserves_content() {
        let bytes = make_test_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert_eq!(owned.content, "Hello, Nostr");
    }

    #[test]
    fn to_owned_preserves_timestamps_and_kind() {
        let bytes = make_test_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert_eq!(owned.created_at, 1720000000);
        assert_eq!(owned.kind, 1);
    }

    #[test]
    fn to_owned_converts_bytes_tags_to_hex() {
        let bytes = make_test_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert_eq!(owned.tags.len(), 3);

        // Tag 0: ["e", <hex>]
        assert_eq!(owned.tags[0][0], "e");
        assert_eq!(
            owned.tags[0][1],
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );

        // Tag 1: ["p", <hex>]
        assert_eq!(owned.tags[1][0], "p");
        assert_eq!(
            owned.tags[1][1],
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );

        // Tag 2: ["t", "test"] - text stays as text
        assert_eq!(owned.tags[2][0], "t");
        assert_eq!(owned.tags[2][1], "test");
    }

    #[test]
    fn to_owned_empty_tags() {
        use crate::varint::write_varint;

        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 0); // created_at
        write_varint(&mut buf, 0); // kind
        write_varint(&mut buf, 0); // content len
        write_varint(&mut buf, 0); // num_tags

        let note = NoteParser::new(&buf).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert!(owned.tags.is_empty());
        assert!(owned.content.is_empty());
    }

    #[test]
    fn to_owned_empty_tag_elements() {
        use crate::varint::{write_tagged_varint, write_varint};

        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 0); // created_at
        write_varint(&mut buf, 0); // kind
        write_varint(&mut buf, 0); // content len
        write_varint(&mut buf, 1); // num_tags
        write_varint(&mut buf, 1); // tag 0 has 1 elem
        write_tagged_varint(&mut buf, 0, false); // empty string

        let note = NoteParser::new(&buf).into_note().unwrap();
        let owned = note.to_owned().unwrap();

        assert_eq!(owned.tags.len(), 1);
        assert_eq!(owned.tags[0].len(), 1);
        assert_eq!(owned.tags[0][0], "");
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use crate::NoteParser;

    fn make_simple_note_bytes() -> Vec<u8> {
        use crate::varint::{write_tagged_varint, write_varint};

        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x11; 32]); // id
        buf.extend_from_slice(&[0x22; 32]); // pubkey
        buf.extend_from_slice(&[0x33; 64]); // sig
        write_varint(&mut buf, 1700000000); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 2); // content len
        buf.extend_from_slice(b"hi"); // content
        write_varint(&mut buf, 1); // num_tags
        write_varint(&mut buf, 2); // tag 0 has 2 elems
        write_tagged_varint(&mut buf, 1, false);
        buf.push(b'p');
        write_tagged_varint(&mut buf, 32, true);
        buf.extend_from_slice(&[0x44; 32]);
        buf
    }

    #[test]
    fn note_serializes_to_json() {
        let bytes = make_simple_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();

        let json = serde_json::to_string(&note).unwrap();

        // Should contain all fields
        assert!(json.contains("\"id\":"));
        assert!(json.contains("\"pubkey\":"));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains("\"kind\":"));
        assert!(json.contains("\"tags\":"));
        assert!(json.contains("\"content\":"));
        assert!(json.contains("\"sig\":"));
    }

    #[test]
    fn note_serializes_id_as_hex() {
        let bytes = make_simple_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();

        let json = serde_json::to_string(&note).unwrap();

        // id should be lowercase hex
        assert!(json.contains(
            "\"id\":\"1111111111111111111111111111111111111111111111111111111111111111\""
        ));
    }

    #[test]
    fn note_serializes_tags_with_hex_for_bytes() {
        let bytes = make_simple_note_bytes();
        let note = NoteParser::new(&bytes).into_note().unwrap();

        let json = serde_json::to_string(&note).unwrap();

        // Tags should include the "p" and hex-encoded pubkey
        assert!(json.contains("\"p\""));
        assert!(json.contains("4444444444444444444444444444444444444444444444444444444444444444"));
    }

    #[test]
    fn note_buf_roundtrip_through_json() {
        let original = NoteBuf {
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            created_at: 1720000000,
            kind: 1,
            tags: vec![
                vec!["e".into(), "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into()],
                vec!["t".into(), "nostr".into()],
            ],
            content: "Hello, world!".into(),
            sig: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        };

        let json = serde_json::to_string(&original).unwrap();
        let recovered: NoteBuf = serde_json::from_str(&json).unwrap();

        assert_eq!(original.id, recovered.id);
        assert_eq!(original.pubkey, recovered.pubkey);
        assert_eq!(original.created_at, recovered.created_at);
        assert_eq!(original.kind, recovered.kind);
        assert_eq!(original.content, recovered.content);
        assert_eq!(original.sig, recovered.sig);
        assert_eq!(original.tags, recovered.tags);
    }

    #[test]
    fn note_buf_default_is_empty() {
        let note = NoteBuf::default();
        assert!(note.id.is_empty());
        assert!(note.pubkey.is_empty());
        assert!(note.sig.is_empty());
        assert!(note.content.is_empty());
        assert!(note.tags.is_empty());
        assert_eq!(note.created_at, 0);
        assert_eq!(note.kind, 0);
    }

    #[test]
    fn note_buf_clone() {
        let original = NoteBuf {
            id: "test".into(),
            pubkey: "pub".into(),
            created_at: 123,
            kind: 1,
            tags: vec![vec!["a".into()]],
            content: "content".into(),
            sig: "sig".into(),
        };

        let cloned = original.clone();
        assert_eq!(original.id, cloned.id);
        assert_eq!(original.tags, cloned.tags);
    }

    #[test]
    fn note_buf_debug() {
        let note = NoteBuf::default();
        let debug = format!("{:?}", note);
        assert!(debug.contains("NoteBuf"));
    }
}
