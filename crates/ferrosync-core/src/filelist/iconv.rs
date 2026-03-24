//! Filename encoding conversion (`--iconv`).
//!
//! Converts filenames between local encoding and wire encoding (UTF-8)
//! during file list exchange. Used when the local filesystem uses a
//! non-UTF-8 encoding (e.g., Latin-1, Shift_JIS) or when macOS NFD
//! normalization differs from Linux NFC.

/// Bidirectional filename encoding converter.
pub struct FilenameConverter {
    local_encoding: &'static encoding_rs::Encoding,
}

impl FilenameConverter {
    /// Create a converter for the given local charset name.
    ///
    /// Returns `None` if the charset is not recognized. The wire encoding
    /// is always UTF-8 (matching rsync's convention).
    pub fn new(charset: &str) -> Option<Self> {
        let encoding = encoding_rs::Encoding::for_label(charset.as_bytes())?;
        Some(Self {
            local_encoding: encoding,
        })
    }

    /// Convert a filename from local encoding to wire (UTF-8).
    ///
    /// Used by the sender when encoding file list entries.
    pub fn to_wire(&self, name: &[u8]) -> Vec<u8> {
        if self.local_encoding == encoding_rs::UTF_8 {
            return name.to_vec();
        }
        let (cow, _, _) = self.local_encoding.decode(name);
        cow.as_bytes().to_vec()
    }

    /// Convert a filename from wire (UTF-8) to local encoding.
    ///
    /// Used by the receiver when decoding file list entries.
    pub fn from_wire(&self, name: &[u8]) -> Vec<u8> {
        if self.local_encoding == encoding_rs::UTF_8 {
            return name.to_vec();
        }
        let s = String::from_utf8_lossy(name);
        let (cow, _, _) = self.local_encoding.encode(&s);
        cow.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_passthrough() {
        let conv = FilenameConverter::new("UTF-8").unwrap();
        let name = b"hello.txt";
        assert_eq!(conv.to_wire(name), name.to_vec());
        assert_eq!(conv.from_wire(name), name.to_vec());
    }

    #[test]
    fn test_latin1_roundtrip() {
        let conv = FilenameConverter::new("ISO-8859-1").unwrap();
        // Latin-1 byte 0xE9 = 'é'
        let local_name = vec![0x66, 0x69, 0x6C, 0xE9]; // "filé" in Latin-1
        let wire = conv.to_wire(&local_name);
        // Wire should be UTF-8: "filé" = [0x66, 0x69, 0x6C, 0xC3, 0xA9]
        assert_eq!(wire, "filé".as_bytes());
        // Round-trip back
        let back = conv.from_wire(&wire);
        assert_eq!(back, local_name);
    }

    #[test]
    fn test_unknown_charset() {
        assert!(FilenameConverter::new("NONEXISTENT-ENCODING").is_none());
    }

    #[test]
    fn test_ascii_compatible() {
        let conv = FilenameConverter::new("windows-1252").unwrap();
        let name = b"plain_ascii.txt";
        assert_eq!(conv.to_wire(name), name.to_vec());
        assert_eq!(conv.from_wire(name), name.to_vec());
    }
}
