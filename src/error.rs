/// Unified error type for notepack encoding, decoding, and parsing.
///
/// This enum encompasses all errors that can occur during:
/// - Binary encoding of a [`NoteBuf`](crate::NoteBuf) to notepack format
/// - Decoding a Base64 notepack string
/// - Streaming parsing of notepack binary data
/// - JSON serialization/deserialization
///
/// # Example
///
/// ```rust
/// use notepack::{NoteParser, Error};
///
/// let result = NoteParser::decode("invalid_prefix");
/// assert!(matches!(result, Err(Error::InvalidPrefix)));
/// ```
#[derive(Debug)]
pub enum Error {
    /// The input data was truncated before all expected bytes could be read.
    ///
    /// This typically means the notepack binary is incomplete or corrupted.
    Truncated,

    /// A varint exceeded the maximum representable 64-bit value.
    ///
    /// Valid varints should terminate within 10 bytes; this error indicates
    /// a malformed or corrupted varint sequence.
    VarintOverflow,

    /// A varint continuation bit was set but no more bytes were available.
    ///
    /// The input ended mid-varint without a terminating byte (high bit clear).
    VarintUnterminated,

    /// A string field contained invalid UTF-8.
    Utf8(std::str::Utf8Error),

    /// Failed to decode a hex-encoded string (e.g., `id`, `pubkey`, or `sig`).
    ///
    /// This can occur if the hex contains invalid characters, is an odd length,
    /// or contains uppercase letters (only lowercase hex is valid for round-tripping).
    FromHex,

    /// Failed to decode the Base64 portion of a `notepack_...` string.
    Decode(base64::DecodeError),

    /// The input string did not start with the required `notepack_` prefix.
    InvalidPrefix,

    /// A JSON serialization or deserialization error occurred.
    Json(serde_json::Error),

    /// An I/O error occurred during writing.
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => {
                write!(f, "notepack string is truncated")
            }
            Error::VarintOverflow => {
                write!(f, "varint overflowed")
            }
            Error::VarintUnterminated => {
                write!(f, "varint is unterminated")
            }
            Error::Utf8(err) => {
                write!(f, "utf8 error: {err}")
            }
            Error::FromHex => {
                write!(f, "error when converting from hex")
            }
            Error::Decode(err) => {
                write!(f, "base64 decode err: {err}")
            }
            Error::InvalidPrefix => {
                write!(f, "String did not start with notepack_")
            }
            Error::Json(err) => {
                write!(f, "json error: {err}")
            }
            Error::Io(err) => {
                write!(f, "io error: {err}")
            }
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Decode(err)
    }
}

impl From<hex_simd::Error> for Error {
    fn from(_err: hex_simd::Error) -> Self {
        Error::FromHex
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl std::error::Error for Error {}
