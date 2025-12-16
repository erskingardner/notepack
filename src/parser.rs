use crate::error::Error;
use crate::stringtype::StringType;
use crate::varint::{read_tagged_varint, read_varint};
use crate::{Note, Tags};

/// Maximum allocation size (256 KB) to prevent OOM from malicious payloads.
pub const MAX_ALLOCATION_SIZE: u64 = 256 * 1024;

/// The currently supported notepack format version.
pub const SUPPORTED_VERSION: u8 = 1;

/// Represents a parsed field from a notepack‐encoded Nostr note.
///
/// Each variant corresponds to a logical field in the binary format,
/// emitted sequentially by the [`NoteParser`] iterator as it reads
/// through the byte stream.
#[derive(Debug, Clone)]
pub enum ParsedField<'a> {
    /// Format version (currently always `1`).
    Version(u8),

    /// 32‑byte event ID (SHA‑256 of serialized event).
    Id(&'a [u8]),

    /// 32‑byte secp256k1 public key of the author.
    Pubkey(&'a [u8]),

    /// 64‑byte Schnorr signature of the event ID.
    Sig(&'a [u8]),

    /// Unix timestamp (seconds) of event creation.
    CreatedAt(u64),

    /// Event kind (u64 varint).
    Kind(u64),

    /// UTF‑8 encoded event body.
    Content(&'a str),

    /// Number of tags present (varint).
    NumTags(u64),

    /// Number of elements in the next tag (varint).
    NumTagElems(u64),

    /// A single tag element: either [`StringType::Str`] or [`StringType::Bytes`].
    Tag(StringType<'a>),
}

/// Stateful streaming parser for notepack binary payloads.
///
/// Yields [`ParsedField`] items in the order they appear in the binary format.
/// Errors are non‑recoverable: once an error is yielded, the parser halts.
///
/// Implements [`Iterator`], so you can do:
///
/// ```rust
/// # use notepack::{NoteParser, ParsedField};
/// if let Ok(bytes) = NoteParser::decode("notepack_Hq7oszfVbWy7ZF...") {
///     let parser = NoteParser::new(&bytes);
///     for field in parser {
///         println!("{:?}", field);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct NoteParser<'a> {
    /// Remaining bytes to parse.
    data: &'a [u8],

    /// Current parsing state machine position.
    state: ParserState,

    /// Number of tags left to read.
    tags_remaining: u64,

    /// Number of elements remaining in the current tag.
    elems_remaining: u64,
}

/// State machine for the [`NoteParser`] streaming parser.
///
/// The parser transitions linearly through states as it reads each field:
///
/// ```text
/// Start → AfterVersion → AfterId → AfterPubkey → AfterSig
///       → AfterCreatedAt → AfterKind → AfterContent → ReadingTags → Done
/// ```
///
/// If an error occurs at any point, the state transitions to [`ParserState::Errored`]
/// and the parser halts (subsequent calls to `next()` return `None`).
///
/// # Example
///
/// ```rust
/// use notepack::{NoteParser, ParserState};
///
/// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
/// let mut parser = NoteParser::new(&bytes);
///
/// // Consume all fields
/// while parser.next().is_some() {}
///
/// assert_eq!(parser.current_state(), ParserState::Done);
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ParserState {
    /// Initial state before any parsing has occurred.
    Start,
    /// After reading the version field.
    AfterVersion,
    /// After reading the 32-byte event ID.
    AfterId,
    /// After reading the 32-byte public key.
    AfterPubkey,
    /// After reading the 64-byte signature.
    AfterSig,
    /// After reading the `created_at` timestamp.
    AfterCreatedAt,
    /// After reading the event kind.
    AfterKind,
    /// After reading the content string.
    AfterContent,
    /// Currently reading tags (may yield multiple [`ParsedField`] items).
    ReadingTags,
    /// Parsing completed successfully.
    Done,
    /// An error occurred; no more fields will be yielded.
    Errored,
}

impl ParserState {
    /// Returns `true` if no more fields will be produced (`Done` or `Errored`).
    fn is_halted(self) -> bool {
        self == Self::Done || self == Self::Errored
    }
}

impl<'a> NoteParser<'a> {
    /// Create a new streaming parser over binary notepack data.
    ///
    /// The parser starts in the [`ParserState::Start`] state and yields
    /// [`ParsedField`] items as you iterate. The input data is borrowed
    /// for the lifetime `'a`, enabling zero-copy access to strings and bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::{NoteParser, ParsedField};
    ///
    /// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
    /// let parser = NoteParser::new(&bytes);
    ///
    /// for field in parser {
    ///     match field.unwrap() {
    ///         ParsedField::Kind(k) => println!("kind: {k}"),
    ///         ParsedField::Content(c) => println!("content: {c}"),
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            state: ParserState::Start,
            tags_remaining: 0,
            elems_remaining: 0,
        }
    }

    /// Parse the notepack data into a zero-copy [`Note`] struct.
    ///
    /// This method consumes the parser and returns a fully-parsed [`Note`]
    /// with borrowed slices pointing into the original data. The `id`, `pubkey`,
    /// `sig`, and `content` fields are zero-copy references.
    ///
    /// The `tags` field is a lazy [`Tags`](crate::Tags) cursor that does **not**
    /// iterate or validate the tags section up-front—errors in tag data will
    /// surface when you iterate through them.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedVersion`] if the version is not 1.
    /// - [`Error::Truncated`] if the data is incomplete.
    /// - [`Error::AllocationLimitExceeded`] if content or tag counts are too large.
    /// - [`Error::Utf8`] if content is not valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    ///
    /// assert_eq!(note.kind, 0);
    /// assert_eq!(note.content, "hello");
    /// ```
    pub fn into_note(mut self) -> Result<Note<'a>, Error> {
        // version - must be 1
        let version = read_varint(&mut self.data)?;
        if version != SUPPORTED_VERSION as u64 {
            return Err(Error::UnsupportedVersion(version));
        }

        // fixed-size fields
        let id = read_bytes(32, &mut self.data)?;
        let pubkey = read_bytes(32, &mut self.data)?;
        let sig = read_bytes(64, &mut self.data)?;

        // integers
        let created_at = read_varint(&mut self.data)?;
        let kind = read_varint(&mut self.data)?;

        // content - check allocation limit
        let content_len = read_varint(&mut self.data)?;
        if content_len > MAX_ALLOCATION_SIZE {
            return Err(Error::AllocationLimitExceeded {
                requested: content_len,
                limit: MAX_ALLOCATION_SIZE,
            });
        }
        let content_bytes = read_bytes(content_len, &mut self.data)?;
        let content = std::str::from_utf8(content_bytes)?;

        // tags: create a lazy cursor positioned at the tags block
        let mut tags_cursor = self.data;
        let tags = Tags::parse(&mut tags_cursor)?; // leaves tags_cursor on first tag's elems

        // Safely coerce slices to fixed-size array refs;
        // These `try_into()` must succeed because we just read exact lengths above.
        let id: &'a [u8; 32] = id.try_into().expect("length checked");
        let pubkey: &'a [u8; 32] = pubkey.try_into().expect("length checked");
        let sig: &'a [u8; 64] = sig.try_into().expect("length checked");

        Ok(Note {
            id,
            pubkey,
            sig,
            content,
            created_at,
            kind,
            tags,
        })
    }

    /// Parse the notepack data into a zero-copy [`Note`] struct, verifying no trailing bytes.
    ///
    /// This is like [`into_note`](Self::into_note) but also validates that there are
    /// no extra bytes after the complete notepack payload, as required by the spec.
    ///
    /// Note: This requires iterating through all tags to verify the payload is complete.
    ///
    /// # Errors
    ///
    /// All errors from [`into_note`](Self::into_note), plus:
    /// - [`Error::TrailingBytes`] if there are extra bytes after the payload.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
    /// let note = NoteParser::new(&bytes).into_note_strict().unwrap();
    /// assert_eq!(note.kind, 0);
    /// ```
    pub fn into_note_strict(mut self) -> Result<Note<'a>, Error> {
        // version - must be 1
        let version = read_varint(&mut self.data)?;
        if version != SUPPORTED_VERSION as u64 {
            return Err(Error::UnsupportedVersion(version));
        }

        // fixed-size fields
        let id = read_bytes(32, &mut self.data)?;
        let pubkey = read_bytes(32, &mut self.data)?;
        let sig = read_bytes(64, &mut self.data)?;

        // integers
        let created_at = read_varint(&mut self.data)?;
        let kind = read_varint(&mut self.data)?;

        // content - check allocation limit
        let content_len = read_varint(&mut self.data)?;
        if content_len > MAX_ALLOCATION_SIZE {
            return Err(Error::AllocationLimitExceeded {
                requested: content_len,
                limit: MAX_ALLOCATION_SIZE,
            });
        }
        let content_bytes = read_bytes(content_len, &mut self.data)?;
        let content = std::str::from_utf8(content_bytes)?;

        // Parse tags: Tags::parse reads num_tags and positions itself at the first tag's data.
        // We then iterate using self.data (which shares the same position) to verify completeness,
        // while tags retains its position for the caller to iterate later.
        let tags = Tags::parse(&mut self.data)?;

        // Iterate all tags using self.data to verify no trailing bytes remain.
        for _ in 0..tags.len() {
            let num_elems = read_varint(&mut self.data)?;
            for _ in 0..num_elems {
                let _ = read_string(&mut self.data)?;
            }
        }

        // Check for trailing bytes
        if !self.data.is_empty() {
            return Err(Error::TrailingBytes);
        }

        // Safely coerce slices to fixed-size array refs
        let id: &'a [u8; 32] = id.try_into().expect("length checked");
        let pubkey: &'a [u8; 32] = pubkey.try_into().expect("length checked");
        let sig: &'a [u8; 64] = sig.try_into().expect("length checked");

        Ok(Note {
            id,
            pubkey,
            sig,
            content,
            created_at,
            kind,
            tags,
        })
    }

    /// Decode a `notepack_...` Base64 string into raw bytes.
    ///
    /// This is typically the first step when parsing a notepack string:
    /// decode to bytes, then pass those bytes to [`NoteParser::new`] or
    /// [`NoteParser::into_note`].
    ///
    /// The input must start with the `notepack_` prefix, followed by
    /// Base64-encoded data (RFC 4648, no padding).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidPrefix`](crate::Error::InvalidPrefix) if the string
    ///   doesn't start with `notepack_`
    /// - [`Error::Decode`](crate::Error::Decode) if the Base64 is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::NoteParser;
    ///
    /// // Decode a notepack string to raw bytes
    /// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
    /// assert!(bytes.len() > 0);
    ///
    /// // Then parse the bytes
    /// let note = NoteParser::new(&bytes).into_note().unwrap();
    /// assert_eq!(note.content, "hello");
    /// ```
    pub fn decode(notepack: &'a str) -> Result<Vec<u8>, Error> {
        if let Some(b64) = notepack.strip_prefix("notepack_") {
            Ok(base64_decode(b64)?)
        } else {
            Err(Error::InvalidPrefix)
        }
    }

    /// Returns the current parser state.
    ///
    /// Useful for debugging or inspecting how far parsing has progressed.
    /// The parser transitions through states linearly from [`ParserState::Start`]
    /// to [`ParserState::Done`], or to [`ParserState::Errored`] if an error occurs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use notepack::{NoteParser, ParserState};
    ///
    /// let bytes = NoteParser::decode("notepack_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIigLyUtAYABWhlbGxvAgMCZUGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqi53c3M6Ly9yZWxheS5leGFtcGxlLmNvbQICcEG7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw").unwrap();
    /// let mut parser = NoteParser::new(&bytes);
    ///
    /// assert_eq!(parser.current_state(), ParserState::Start);
    /// parser.next(); // Parse version
    /// assert_eq!(parser.current_state(), ParserState::AfterVersion);
    /// ```
    pub fn current_state(&self) -> ParserState {
        self.state
    }
}

/// Base64 decode using the RFC 4648 alphabet **without padding** (`=`).
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

    STANDARD_NO_PAD.decode(s)
}

impl<'a> Iterator for NoteParser<'a> {
    type Item = Result<ParsedField<'a>, Error>;

    /// Parse the next [`ParsedField`] from the input buffer.
    ///
    /// Returns `None` when parsing is complete or after an unrecoverable error.
    fn next(&mut self) -> Option<Self::Item> {
        use ParserState::*;

        if self.state.is_halted() {
            return None;
        }

        // small helper to make error propagation less noisy
        macro_rules! read_or_err {
            ($expr:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(e) => {
                        self.state = Errored;
                        return Some(Err(e));
                    }
                }
            };
        }

        let item = match self.state {
            Start => {
                let version = read_or_err!(read_varint(&mut self.data));
                // Note: We don't validate version here - the iterator yields all fields
                // and leaves validation to the consumer. Use into_note() for validation.
                self.state = AfterVersion;
                Ok(ParsedField::Version(version as u8))
            }
            AfterVersion => {
                let id = read_or_err!(read_bytes(32, &mut self.data));
                self.state = AfterId;
                Ok(ParsedField::Id(id))
            }
            AfterId => {
                let pk = read_or_err!(read_bytes(32, &mut self.data));
                self.state = AfterPubkey;
                Ok(ParsedField::Pubkey(pk))
            }
            AfterPubkey => {
                let sig = read_or_err!(read_bytes(64, &mut self.data));
                self.state = AfterSig;
                Ok(ParsedField::Sig(sig))
            }
            AfterSig => {
                let ts = read_or_err!(read_varint(&mut self.data));
                self.state = AfterCreatedAt;
                Ok(ParsedField::CreatedAt(ts))
            }
            AfterCreatedAt => {
                let kind = read_or_err!(read_varint(&mut self.data));
                self.state = AfterKind;
                Ok(ParsedField::Kind(kind))
            }
            AfterKind => {
                let content_len = read_or_err!(read_varint(&mut self.data));
                let bytes = read_or_err!(read_bytes(content_len, &mut self.data));
                let s = read_or_err!(std::str::from_utf8(bytes).map_err(Error::Utf8));
                self.state = AfterContent;
                Ok(ParsedField::Content(s))
            }
            AfterContent => {
                let num_tags = read_or_err!(read_varint(&mut self.data));
                self.tags_remaining = num_tags;
                self.state = if num_tags > 0 { ReadingTags } else { Done };
                Ok(ParsedField::NumTags(num_tags))
            }
            ReadingTags => {
                if self.elems_remaining == 0 {
                    if self.tags_remaining == 0 {
                        self.state = Done;
                        return None;
                    }
                    let num_elems = read_or_err!(read_varint(&mut self.data));
                    self.elems_remaining = num_elems;
                    self.tags_remaining -= 1;
                    return Some(Ok(ParsedField::NumTagElems(num_elems)));
                }

                let tag = read_or_err!(read_string(&mut self.data));
                self.elems_remaining -= 1;
                Ok(ParsedField::Tag(tag))
            }
            Done => return None,
            Errored => return None,
        };

        Some(item)
    }
}

/// Read exactly `len` bytes from the input slice.
///
/// Returns [`Error::Truncated`] if fewer than `len` bytes remain.
#[inline]
fn read_bytes<'a>(len: u64, input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len: usize = usize::try_from(len).map_err(|_| Error::VarintOverflow)?;
    if len > input.len() {
        return Err(Error::Truncated);
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

/// Read a tagged string (see §3.2 of spec) from the input.
///
/// Uses [`read_tagged_varint`] to determine payload length and type.
/// Returns:
///  * [`StringType::Str`] if `is_bytes == false`
///  * [`StringType::Bytes`] if `is_bytes == true`
#[inline]
pub(crate) fn read_string<'a>(input: &mut &'a [u8]) -> Result<StringType<'a>, Error> {
    let (len, is_bytes) = read_tagged_varint(input)?;
    let len: usize = usize::try_from(len).map_err(|_| Error::VarintOverflow)?;
    if input.len() < len {
        return Err(Error::Truncated);
    }
    let (head, tail) = input.split_at(len);
    *input = tail;

    Ok(if is_bytes {
        StringType::Bytes(head)
    } else {
        StringType::Str(std::str::from_utf8(head)?)
    })
}

#[cfg(test)]
mod into_note_tests {
    use super::*;
    use crate::stringtype::StringType;
    use crate::varint::{write_tagged_varint, write_varint};

    // --- helpers to construct a minimal notepack payload ---

    enum TagElem {
        S(&'static str),
        B(&'static [u8]),
    }

    fn push_elem_str(buf: &mut Vec<u8>, s: &str) {
        write_tagged_varint(buf, s.len() as u64, false).unwrap();
        buf.extend_from_slice(s.as_bytes());
    }

    fn push_elem_bytes(buf: &mut Vec<u8>, bs: &[u8]) {
        write_tagged_varint(buf, bs.len() as u64, true).unwrap();
        buf.extend_from_slice(bs);
    }

    /// Build one full notepack note payload:
    /// [varint version=1]
    /// [id:32][pubkey:32][sig:64]
    /// [varint created_at][varint kind]
    /// [varint content_len][content bytes]
    /// [varint num_tags] { [varint num_elems] { elem }* }*
    fn build_note_bytes(
        id: [u8; 32],
        pk: [u8; 32],
        sig: [u8; 64],
        created_at: u64,
        kind: u64,
        content: &str,
        tags: &[&[TagElem]],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // version
        write_varint(&mut buf, 1);
        // fixed fields
        buf.extend_from_slice(&id);
        buf.extend_from_slice(&pk);
        buf.extend_from_slice(&sig);
        // ints
        write_varint(&mut buf, created_at);
        write_varint(&mut buf, kind);
        // content
        write_varint(&mut buf, content.len() as u64);
        buf.extend_from_slice(content.as_bytes());
        // tags
        write_varint(&mut buf, tags.len() as u64);
        for tag in tags {
            write_varint(&mut buf, tag.len() as u64);
            for e in *tag {
                match e {
                    TagElem::S(s) => push_elem_str(&mut buf, s),
                    TagElem::B(bs) => push_elem_bytes(&mut buf, bs),
                }
            }
        }
        buf
    }

    #[test]
    fn into_note_parses_fixed_fields_and_lazy_tags() -> Result<(), Error> {
        // Arrange
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        // tags: [["p", <aabb>, "hello"], [""]]
        let bytes = build_note_bytes(
            id,
            pk,
            sig,
            1_234,
            1,
            "hi",
            &[
                &[
                    TagElem::S("p"),
                    TagElem::B(&[0xaa, 0xbb]),
                    TagElem::S("hello"),
                ],
                &[TagElem::S("")],
            ],
        );

        // Act
        let note = NoteParser::new(&bytes).into_note()?;

        // Assert fixed fields + content
        assert_eq!(note.id, &id);
        assert_eq!(note.pubkey, &pk);
        assert_eq!(note.sig, &sig);
        assert_eq!(note.created_at, 1_234);
        assert_eq!(note.kind, 1);
        assert_eq!(note.content, "hi");

        // Assert tags lazily
        let mut tags = note.tags.clone();

        // tag 0
        {
            let mut t0 = tags.next_tag()?.expect("tag0");
            // "p"
            match t0.next().expect("e0")? {
                StringType::Str(s) => assert_eq!(s, "p"),
                _ => panic!("expected str"),
            }
            // bytes aabb
            match t0.next().expect("e1")? {
                StringType::Bytes(bs) => assert_eq!(bs, &[0xaa, 0xbb]),
                _ => panic!("expected bytes"),
            }
            // "hello"
            match t0.next().expect("e2")? {
                StringType::Str(s) => assert_eq!(s, "hello"),
                _ => panic!("expected str"),
            }
            assert!(t0.next().is_none());
        }

        // tag 1
        {
            let mut t1 = tags.next_tag()?.expect("tag1");
            match t1.next().expect("only elem")? {
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
    fn into_note_tag_drop_realigns_parent_cursor() -> Result<(), Error> {
        // Arrange: tag0 ["a","b","c"] then tag1 ["z"]
        let id = [0x44; 32];
        let pk = [0x55; 32];
        let sig = [0x66; 64];

        let bytes = build_note_bytes(
            id,
            pk,
            sig,
            999,
            42,
            "x",
            &[
                &[TagElem::S("a"), TagElem::S("b"), TagElem::S("c")],
                &[TagElem::S("z")],
            ],
        );

        let note = NoteParser::new(&bytes).into_note()?;
        let mut tags = note.tags.clone();

        // Consume only the first elem of tag0; drop early.
        {
            let mut t0 = tags.next_tag()?.expect("tag0");
            match t0.next().expect("first")? {
                StringType::Str(s) => assert_eq!(s, "a"),
                _ => panic!("expected 'a'"),
            }
            // t0 dropped here with 2 remaining elems; Drop should fast-forward them.
        }

        // Now we should be aligned at tag1.
        {
            let mut t1 = tags.next_tag()?.expect("tag1");
            match t1.next().expect("first of tag1")? {
                StringType::Str(s) => assert_eq!(s, "z"),
                _ => panic!("expected 'z'"),
            }
            assert!(t1.next().is_none());
        }

        assert!(tags.next_tag()?.is_none());
        Ok(())
    }

    #[test]
    fn into_note_succeeds_even_if_later_tag_is_truncated_but_iteration_errors() {
        // Arrange a note where the tag element length claims 10 bytes but we provide 3.
        let id = [0x77; 32];
        let pk = [0x88; 32];
        let sig = [0x99; 64];

        // Build the payload manually so we can truncate the last element.
        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1); // version
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 7); // created_at
        write_varint(&mut bytes, 1); // kind
        write_varint(&mut bytes, 0); // content len
        // content bytes: none
        write_varint(&mut bytes, 1); // num_tags
        write_varint(&mut bytes, 1); // tag0: 1 elem
        write_tagged_varint(&mut bytes, 10, false).unwrap(); // claim 10 bytes (utf8)
        bytes.extend_from_slice(b"abc"); // only 3 bytes => truncated

        // Act: into_note should still succeed (tags are lazy).
        let note = NoteParser::new(&bytes).into_note().expect("note ok");

        // But iterating the tag should error with Truncated.
        let mut tags = note.tags.clone();
        let mut t0 = tags.next_tag().expect("ok").expect("tag0");
        let err = t0.next().unwrap().unwrap_err();
        matches!(err, Error::Truncated);
    }

    #[test]
    fn into_note_rejects_unsupported_version() {
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        // Build with version 2 instead of 1
        let mut bytes = Vec::new();
        write_varint(&mut bytes, 2); // unsupported version
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234); // created_at
        write_varint(&mut bytes, 1); // kind
        write_varint(&mut bytes, 0); // content len
        write_varint(&mut bytes, 0); // num_tags

        let result = NoteParser::new(&bytes).into_note();
        assert!(matches!(result, Err(Error::UnsupportedVersion(2))), "expected UnsupportedVersion(2), got {:?}", result);
    }

    #[test]
    fn into_note_rejects_version_zero() {
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        let mut bytes = Vec::new();
        write_varint(&mut bytes, 0); // version 0
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234);
        write_varint(&mut bytes, 1);
        write_varint(&mut bytes, 0);
        write_varint(&mut bytes, 0);

        let result = NoteParser::new(&bytes).into_note();
        assert!(matches!(result, Err(Error::UnsupportedVersion(0))), "expected UnsupportedVersion(0), got {:?}", result);
    }

    #[test]
    fn into_note_rejects_version_257_not_truncated_to_1() {
        // Regression test: version 257 should NOT be accepted as version 1
        // (257 % 256 == 1, so a truncation bug would accept it)
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        let mut bytes = Vec::new();
        write_varint(&mut bytes, 257); // version 257 (would truncate to 1 if cast to u8)
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234);
        write_varint(&mut bytes, 1);
        write_varint(&mut bytes, 0);
        write_varint(&mut bytes, 0);

        let result = NoteParser::new(&bytes).into_note();
        assert!(matches!(result, Err(Error::UnsupportedVersion(257))), "expected UnsupportedVersion(257), got {:?}", result);
    }

    #[test]
    fn into_note_strict_rejects_trailing_bytes() {
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1); // version
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234); // created_at
        write_varint(&mut bytes, 1); // kind
        write_varint(&mut bytes, 2); // content len
        bytes.extend_from_slice(b"hi"); // content
        write_varint(&mut bytes, 0); // num_tags
        bytes.extend_from_slice(b"extra trailing garbage"); // trailing bytes

        let result = NoteParser::new(&bytes).into_note_strict();
        assert!(matches!(result, Err(Error::TrailingBytes)));
    }

    #[test]
    fn into_note_strict_succeeds_without_trailing_bytes() {
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1); // version
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234); // created_at
        write_varint(&mut bytes, 1); // kind
        write_varint(&mut bytes, 2); // content len
        bytes.extend_from_slice(b"hi"); // content
        write_varint(&mut bytes, 0); // num_tags

        let note = NoteParser::new(&bytes).into_note_strict().expect("should succeed");
        assert_eq!(note.content, "hi");
    }

    #[test]
    fn into_note_rejects_huge_content_length() {
        let id = [0x11; 32];
        let pk = [0x22; 32];
        let sig = [0x33; 64];

        let mut bytes = Vec::new();
        write_varint(&mut bytes, 1); // version
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&pk);
        bytes.extend_from_slice(&sig);
        write_varint(&mut bytes, 1234); // created_at
        write_varint(&mut bytes, 1); // kind
        write_varint(&mut bytes, 1_000_000_000); // huge content len (1GB)
        // No actual content bytes

        let result = NoteParser::new(&bytes).into_note();
        assert!(matches!(
            result,
            Err(Error::AllocationLimitExceeded { .. })
        ));
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn decode_valid_notepack_string() {
        let encoded = "notepack_AQ"; // minimal: version=1, then truncated but decode doesn't validate
        let result = NoteParser::decode(encoded);
        assert!(result.is_ok());
        // Decoded bytes should be [0x01] (version 1)
        assert_eq!(result.unwrap(), vec![0x01]);
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        let result = NoteParser::decode("AQ");
        assert!(matches!(result, Err(Error::InvalidPrefix)));
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        let result = NoteParser::decode("notepackAQ");
        assert!(matches!(result, Err(Error::InvalidPrefix)));
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let result = NoteParser::decode("notepack_!!invalid!!");
        assert!(matches!(result, Err(Error::Decode(_))));
    }

    #[test]
    fn decode_empty_base64_after_prefix() {
        let result = NoteParser::decode("notepack_");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}

#[cfg(test)]
mod iterator_tests {
    use super::*;
    use crate::varint::{write_tagged_varint, write_varint};

    fn build_minimal_note() -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 1720000000); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 5); // content len
        buf.extend_from_slice(b"hello"); // content
        write_varint(&mut buf, 0); // num_tags
        buf
    }

    #[test]
    fn iterator_yields_all_fields_in_order() {
        let bytes = build_minimal_note();
        let mut parser = NoteParser::new(&bytes);

        // Version
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::Version(1)));

        // Id
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::Id(_)));

        // Pubkey
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::Pubkey(_)));

        // Sig
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::Sig(_)));

        // CreatedAt
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::CreatedAt(1720000000)));

        // Kind
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::Kind(1)));

        // Content
        let field = parser.next().unwrap().unwrap();
        if let ParsedField::Content(c) = field {
            assert_eq!(c, "hello");
        } else {
            panic!("expected Content");
        }

        // NumTags
        let field = parser.next().unwrap().unwrap();
        assert!(matches!(field, ParsedField::NumTags(0)));

        // Done
        assert!(parser.next().is_none());
    }

    #[test]
    fn iterator_state_transitions() {
        let bytes = build_minimal_note();
        let mut parser = NoteParser::new(&bytes);

        assert_eq!(parser.current_state(), ParserState::Start);

        parser.next(); // version
        assert_eq!(parser.current_state(), ParserState::AfterVersion);

        parser.next(); // id
        assert_eq!(parser.current_state(), ParserState::AfterId);

        parser.next(); // pubkey
        assert_eq!(parser.current_state(), ParserState::AfterPubkey);

        parser.next(); // sig
        assert_eq!(parser.current_state(), ParserState::AfterSig);

        parser.next(); // created_at
        assert_eq!(parser.current_state(), ParserState::AfterCreatedAt);

        parser.next(); // kind
        assert_eq!(parser.current_state(), ParserState::AfterKind);

        parser.next(); // content
        assert_eq!(parser.current_state(), ParserState::AfterContent);

        parser.next(); // num_tags (0, so goes to Done)
        assert_eq!(parser.current_state(), ParserState::Done);

        // No more items
        assert!(parser.next().is_none());
        assert_eq!(parser.current_state(), ParserState::Done);
    }

    #[test]
    fn iterator_with_tags() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 100); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 0); // content len (empty)
        write_varint(&mut buf, 2); // num_tags

        // Tag 1: ["e", <32-byte hex>]
        write_varint(&mut buf, 2); // num_elems
        write_tagged_varint(&mut buf, 1, false).unwrap(); // "e"
        buf.push(b'e');
        write_tagged_varint(&mut buf, 32, true).unwrap(); // 32 bytes
        buf.extend_from_slice(&[0xaa; 32]);

        // Tag 2: ["p"]
        write_varint(&mut buf, 1); // num_elems
        write_tagged_varint(&mut buf, 1, false).unwrap(); // "p"
        buf.push(b'p');

        let parser = NoteParser::new(&buf);
        let mut tag_count = 0;
        let mut num_tag_elems_count = 0;

        for field in parser {
            let f = field.unwrap();
            if matches!(f, ParsedField::Tag(_)) {
                tag_count += 1;
            }
            if matches!(f, ParsedField::NumTagElems(_)) {
                num_tag_elems_count += 1;
            }
        }

        // NumTagElems is emitted once per tag (2 tags)
        // Tag is emitted for each element across all tags (2 + 1 = 3)
        assert_eq!(num_tag_elems_count, 2);
        assert_eq!(tag_count, 3);
    }

    #[test]
    fn iterator_halts_after_done() {
        let bytes = build_minimal_note();
        let mut parser = NoteParser::new(&bytes);

        // Consume all fields
        while parser.next().is_some() {}

        assert_eq!(parser.current_state(), ParserState::Done);

        // Multiple calls after done return None
        assert!(parser.next().is_none());
        assert!(parser.next().is_none());
        assert!(parser.next().is_none());
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    use crate::varint::write_varint;

    #[test]
    fn error_truncated_id() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 16]); // only 16 bytes, need 32

        let mut parser = NoteParser::new(&buf);
        parser.next(); // version ok
        let result = parser.next(); // id should fail
        assert!(matches!(result, Some(Err(Error::Truncated))));
        assert_eq!(parser.current_state(), ParserState::Errored);
    }

    #[test]
    fn error_truncated_pubkey() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id ok
        buf.extend_from_slice(&[0x11; 16]); // pubkey only 16 bytes

        let mut parser = NoteParser::new(&buf);
        parser.next(); // version
        parser.next(); // id
        let result = parser.next(); // pubkey fails
        assert!(matches!(result, Some(Err(Error::Truncated))));
    }

    #[test]
    fn error_truncated_sig() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 32]); // sig only 32 bytes, need 64

        let mut parser = NoteParser::new(&buf);
        parser.next(); // version
        parser.next(); // id
        parser.next(); // pubkey
        let result = parser.next(); // sig fails
        assert!(matches!(result, Some(Err(Error::Truncated))));
    }

    #[test]
    fn error_truncated_content() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 100); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 100); // content len claims 100 bytes
        buf.extend_from_slice(b"short"); // only 5 bytes

        let mut parser = NoteParser::new(&buf);
        for _ in 0..6 {
            parser.next(); // consume up to kind
        }
        let result = parser.next(); // content fails
        assert!(matches!(result, Some(Err(Error::Truncated))));
    }

    #[test]
    fn error_invalid_utf8_content() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version
        buf.extend_from_slice(&[0x00; 32]); // id
        buf.extend_from_slice(&[0x11; 32]); // pubkey
        buf.extend_from_slice(&[0x22; 64]); // sig
        write_varint(&mut buf, 100); // created_at
        write_varint(&mut buf, 1); // kind
        write_varint(&mut buf, 2); // content len
        buf.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8

        let mut parser = NoteParser::new(&buf);
        for _ in 0..6 {
            parser.next();
        }
        let result = parser.next(); // content fails with UTF-8 error
        assert!(matches!(result, Some(Err(Error::Utf8(_)))));
    }

    #[test]
    fn error_halts_iteration() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1); // version only, then truncated

        let mut parser = NoteParser::new(&buf);
        parser.next(); // version ok
        let result = parser.next(); // should fail
        assert!(matches!(result, Some(Err(_))));

        // After error, parser is halted
        assert!(parser.next().is_none());
        assert!(parser.next().is_none());
    }

    #[test]
    fn error_empty_input() {
        let buf: Vec<u8> = vec![];
        let mut parser = NoteParser::new(&buf);

        // First next should fail (can't read version)
        let result = parser.next();
        assert!(matches!(result, Some(Err(Error::VarintUnterminated))));
    }
}

#[cfg(test)]
mod read_string_tests {
    use super::*;
    use crate::varint::write_tagged_varint;

    #[test]
    fn read_string_utf8() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 5, false).unwrap();
        buf.extend_from_slice(b"hello");

        let mut slice = buf.as_slice();
        let result = read_string(&mut slice).unwrap();
        assert!(matches!(result, StringType::Str("hello")));
        assert!(slice.is_empty());
    }

    #[test]
    fn read_string_bytes() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 3, true).unwrap();
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let mut slice = buf.as_slice();
        let result = read_string(&mut slice).unwrap();
        if let StringType::Bytes(bs) = result {
            assert_eq!(bs, &[0xaa, 0xbb, 0xcc]);
        } else {
            panic!("expected Bytes");
        }
    }

    #[test]
    fn read_string_empty() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 0, false).unwrap();

        let mut slice = buf.as_slice();
        let result = read_string(&mut slice).unwrap();
        assert!(matches!(result, StringType::Str("")));
    }

    #[test]
    fn read_string_truncated() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 10, false).unwrap(); // claims 10 bytes
        buf.extend_from_slice(b"abc"); // only 3

        let mut slice = buf.as_slice();
        let result = read_string(&mut slice);
        assert!(matches!(result, Err(Error::Truncated)));
    }

    #[test]
    fn read_string_invalid_utf8() {
        let mut buf = Vec::new();
        write_tagged_varint(&mut buf, 2, false).unwrap(); // UTF-8 string
        buf.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8

        let mut slice = buf.as_slice();
        let result = read_string(&mut slice);
        assert!(matches!(result, Err(Error::Utf8(_))));
    }
}
