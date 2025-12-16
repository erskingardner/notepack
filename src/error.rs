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
    FromHex(hex_simd::Error),

    /// Failed to decode the Base64 portion of a `notepack_...` string.
    Decode(base64::DecodeError),

    /// The input string did not start with the required `notepack_` prefix.
    InvalidPrefix,

    /// A JSON serialization or deserialization error occurred.
    Json(serde_json::Error),

    /// An I/O error occurred during writing.
    Io(std::io::Error),

    /// The notepack version is not supported by this decoder.
    ///
    /// Currently only version 1 is supported.
    UnsupportedVersion(u64),

    /// Extra bytes were found after the complete notepack payload.
    ///
    /// Per the spec, decoders must stop exactly at the end of the payload.
    TrailingBytes,

    /// A fixed-size field (id, pubkey, or sig) had an invalid length.
    ///
    /// `id` and `pubkey` must be exactly 32 bytes (64 hex chars),
    /// `sig` must be exactly 64 bytes (128 hex chars).
    InvalidFieldLength {
        /// The name of the field that had an invalid length.
        field: &'static str,
        /// The expected length in bytes.
        expected: usize,
        /// The actual length in bytes.
        actual: usize,
    },

    /// A value is too large for tagged varint encoding.
    ///
    /// Tagged varints shift the value left by 1, so the maximum supported
    /// value is `2^63 - 1`.
    TaggedVarintOverflow,

    /// An allocation size exceeded the maximum allowed limit.
    ///
    /// This prevents denial-of-service attacks via maliciously crafted
    /// payloads claiming huge sizes.
    AllocationLimitExceeded {
        /// The requested allocation size.
        requested: u64,
        /// The maximum allowed size.
        limit: u64,
    },
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
            Error::FromHex(err) => {
                write!(f, "hex decode error: {err}")
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
            Error::UnsupportedVersion(v) => {
                write!(f, "unsupported notepack version: {v} (only version 1 is supported)")
            }
            Error::TrailingBytes => {
                write!(f, "trailing bytes after notepack payload")
            }
            Error::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid {field} length: expected {expected} bytes, got {actual}"
                )
            }
            Error::TaggedVarintOverflow => {
                write!(f, "value too large for tagged varint (max 2^63 - 1)")
            }
            Error::AllocationLimitExceeded { requested, limit } => {
                write!(
                    f,
                    "allocation limit exceeded: requested {requested} bytes, limit is {limit}"
                )
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
    fn from(err: hex_simd::Error) -> Self {
        Error::FromHex(err)
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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Utf8(err) => Some(err),
            Error::FromHex(err) => Some(err),
            Error::Decode(err) => Some(err),
            Error::Json(err) => Some(err),
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

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
        let hex_err = hex_simd::decode_to_vec("zz").unwrap_err();
        let err = Error::FromHex(hex_err);
        assert!(err.to_string().starts_with("hex decode error:"));
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

    #[test]
    fn display_unsupported_version() {
        let err = Error::UnsupportedVersion(2u64);
        assert_eq!(
            err.to_string(),
            "unsupported notepack version: 2 (only version 1 is supported)"
        );
    }

    #[test]
    fn display_trailing_bytes() {
        let err = Error::TrailingBytes;
        assert_eq!(err.to_string(), "trailing bytes after notepack payload");
    }

    #[test]
    fn display_invalid_field_length() {
        let err = Error::InvalidFieldLength {
            field: "id",
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "invalid id length: expected 32 bytes, got 16"
        );
    }

    #[test]
    fn display_tagged_varint_overflow() {
        let err = Error::TaggedVarintOverflow;
        assert_eq!(
            err.to_string(),
            "value too large for tagged varint (max 2^63 - 1)"
        );
    }

    #[test]
    fn display_allocation_limit_exceeded() {
        let err = Error::AllocationLimitExceeded {
            requested: 1_000_000,
            limit: 131_072,
        };
        assert_eq!(
            err.to_string(),
            "allocation limit exceeded: requested 1000000 bytes, limit is 131072"
        );
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
        assert!(matches!(err, Error::FromHex(_)));
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

    #[test]
    fn error_source_utf8() {
        use std::error::Error as StdError;
        let bytes: Vec<u8> = vec![0xff, 0xfe];
        let utf8_err = std::str::from_utf8(&bytes).unwrap_err();
        let err = Error::Utf8(utf8_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn error_source_hex() {
        use std::error::Error as StdError;
        let hex_err = hex_simd::decode_to_vec("zz").unwrap_err();
        let err = Error::FromHex(hex_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn error_source_none_for_simple_variants() {
        use std::error::Error as StdError;
        assert!(Error::Truncated.source().is_none());
        assert!(Error::VarintOverflow.source().is_none());
        assert!(Error::InvalidPrefix.source().is_none());
            assert!(Error::UnsupportedVersion(1u64).source().is_none());
        assert!(Error::TrailingBytes.source().is_none());
        assert!(Error::TaggedVarintOverflow.source().is_none());
    }
}
