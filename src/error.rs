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

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // Display tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn display_truncated() {
        let err = Error::Truncated;
        assert_eq!(err.to_string(), "notepack string is truncated");
    }

    #[test]
    fn display_varint_overflow() {
        let err = Error::VarintOverflow;
        assert_eq!(err.to_string(), "varint overflowed");
    }

    #[test]
    fn display_varint_unterminated() {
        let err = Error::VarintUnterminated;
        assert_eq!(err.to_string(), "varint is unterminated");
    }

    #[test]
    fn display_from_hex() {
        let err = Error::FromHex;
        assert_eq!(err.to_string(), "error when converting from hex");
    }

    #[test]
    fn display_invalid_prefix() {
        let err = Error::InvalidPrefix;
        assert_eq!(err.to_string(), "String did not start with notepack_");
    }

    #[test]
    fn display_utf8_error() {
        // Create an invalid UTF-8 sequence at runtime to avoid compile-time warning
        let bytes: Vec<u8> = vec![0xff, 0xfe];
        let utf8_err = std::str::from_utf8(&bytes).unwrap_err();
        let err = Error::Utf8(utf8_err);
        assert!(err.to_string().starts_with("utf8 error:"));
    }

    #[test]
    fn display_decode_error() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decode_err = STANDARD.decode("!!!invalid!!!").unwrap_err();
        let err = Error::Decode(decode_err);
        assert!(err.to_string().starts_with("base64 decode err:"));
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<String>("not valid json").unwrap_err();
        let err = Error::Json(json_err);
        assert!(err.to_string().starts_with("json error:"));
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::Io(io_err);
        assert!(err.to_string().starts_with("io error:"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // From trait tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn from_utf8_error() {
        // Use Vec to avoid compile-time invalid literal warning
        let bytes: Vec<u8> = vec![0xff, 0xfe];
        let utf8_err = std::str::from_utf8(&bytes).unwrap_err();
        let err: Error = utf8_err.into();
        assert!(matches!(err, Error::Utf8(_)));
    }

    #[test]
    fn from_base64_decode_error() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let decode_err = STANDARD.decode("!!!").unwrap_err();
        let err: Error = decode_err.into();
        assert!(matches!(err, Error::Decode(_)));
    }

    #[test]
    fn from_hex_simd_error() {
        let hex_err = hex_simd::decode_to_vec("zz").unwrap_err();
        let err: Error = hex_err.into();
        assert!(matches!(err, Error::FromHex));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<i32>("nope").unwrap_err();
        let err: Error = json_err.into();
        assert!(matches!(err, Error::Json(_)));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::other("test");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // std::error::Error trait
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn error_trait_implemented() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<Error>();
    }

    #[test]
    fn error_is_debug() {
        let err = Error::Truncated;
        let debug_str = format!("{:?}", err);
        assert_eq!(debug_str, "Truncated");
    }
}
