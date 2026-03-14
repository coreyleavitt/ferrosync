//! Glob pattern matching for filter rules.
//!
//! Implements rsync-compatible glob patterns with `*`, `**`, `?`,
//! and `[...]` character classes.

use crate::error::FilterError;

/// A compiled glob pattern.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// The original pattern string.
    source: String,
    /// Whether the pattern is anchored (starts with `/`).
    anchored: bool,
    /// Whether the pattern matches only directories (ends with `/`).
    dir_only: bool,
    /// Compiled regex-like segments for matching.
    segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
enum Segment {
    /// Match any sequence of non-`/` characters.
    Star,
    /// Match any sequence of characters including `/`.
    DoubleStar,
    /// Match a single non-`/` character.
    Question,
    /// Match a literal byte sequence.
    Literal(Vec<u8>),
    /// Match any single byte in the given set.
    CharClass { chars: Vec<u8>, negated: bool },
}

impl Pattern {
    /// Compile a pattern string into a matcher.
    pub fn new(pattern: &str) -> Result<Self, FilterError> {
        let mut source = pattern.to_string();
        let mut anchored = false;
        let mut dir_only = false;

        // Leading / means anchored.
        let pat = if let Some(rest) = source.strip_prefix('/') {
            anchored = true;
            rest
        } else {
            &source
        };

        // Trailing / means directory-only.
        let pat = if let Some(rest) = pat.strip_suffix('/') {
            dir_only = true;
            rest
        } else {
            pat
        };

        // A pattern containing / (after stripping leading/trailing) is implicitly anchored.
        if pat.contains('/') {
            anchored = true;
        }

        let segments = Self::compile(pat.as_bytes())?;

        // Normalize source for display.
        if anchored && !source.starts_with('/') {
            source = format!("/{source}");
        }

        Ok(Self {
            source,
            anchored,
            dir_only,
            segments,
        })
    }

    fn compile(pat: &[u8]) -> Result<Vec<Segment>, FilterError> {
        let mut segments = Vec::new();
        let mut i = 0;

        while i < pat.len() {
            match pat[i] {
                b'*' => {
                    if i + 1 < pat.len() && pat[i + 1] == b'*' {
                        segments.push(Segment::DoubleStar);
                        i += 2;
                        // Skip trailing / after ** (it's implied).
                        if i < pat.len() && pat[i] == b'/' {
                            i += 1;
                        }
                    } else {
                        segments.push(Segment::Star);
                        i += 1;
                    }
                }
                b'?' => {
                    segments.push(Segment::Question);
                    i += 1;
                }
                b'[' => {
                    let (class, end) = Self::parse_char_class(pat, i)?;
                    segments.push(class);
                    i = end;
                }
                _ => {
                    // Accumulate literal bytes.
                    let start = i;
                    while i < pat.len() && pat[i] != b'*' && pat[i] != b'?' && pat[i] != b'[' {
                        i += 1;
                    }
                    segments.push(Segment::Literal(pat[start..i].to_vec()));
                }
            }
        }

        Ok(segments)
    }

    fn parse_char_class(pat: &[u8], start: usize) -> Result<(Segment, usize), FilterError> {
        let mut i = start + 1; // skip '['
        let negated = if i < pat.len() && (pat[i] == b'!' || pat[i] == b'^') {
            i += 1;
            true
        } else {
            false
        };

        let mut chars = Vec::new();
        while i < pat.len() && pat[i] != b']' {
            if i + 2 < pat.len() && pat[i + 1] == b'-' {
                // Range: a-z
                let lo = pat[i];
                let hi = pat[i + 2];
                for c in lo..=hi {
                    chars.push(c);
                }
                i += 3;
            } else {
                chars.push(pat[i]);
                i += 1;
            }
        }

        if i >= pat.len() {
            return Err(FilterError::InvalidPattern {
                pattern: String::from_utf8_lossy(&pat[start..]).to_string(),
                message: "unterminated character class".to_string(),
            });
        }

        Ok((Segment::CharClass { chars, negated }, i + 1)) // skip ']'
    }

    /// Test whether a path matches this pattern.
    ///
    /// - `path`: relative path (e.g., `foo/bar/baz.txt`)
    /// - `is_dir`: whether the path is a directory
    pub fn matches(&self, path: &[u8], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }

        if self.anchored {
            // Match against the full path.
            Self::match_segments(&self.segments, path)
        } else {
            // Try matching against the full path first.
            if Self::match_segments(&self.segments, path) {
                return true;
            }
            // Then try matching against just the filename.
            if let Some(pos) = path.iter().rposition(|&b| b == b'/') {
                Self::match_segments(&self.segments, &path[pos + 1..])
            } else {
                false // already tried full path
            }
        }
    }

    fn match_segments(segments: &[Segment], text: &[u8]) -> bool {
        Self::match_recursive(segments, text, 0)
    }

    fn match_recursive(segments: &[Segment], text: &[u8], seg_idx: usize) -> bool {
        if seg_idx >= segments.len() {
            return text.is_empty();
        }

        match &segments[seg_idx] {
            Segment::Literal(lit) => {
                if text.starts_with(lit) {
                    Self::match_recursive(segments, &text[lit.len()..], seg_idx + 1)
                } else {
                    false
                }
            }
            Segment::Star => {
                // Match any sequence of non-/ characters.
                for i in 0..=text.len() {
                    if i > 0 && text[i - 1] == b'/' {
                        break;
                    }
                    if Self::match_recursive(segments, &text[i..], seg_idx + 1) {
                        return true;
                    }
                }
                false
            }
            Segment::DoubleStar => {
                // Match any sequence including /.
                for i in 0..=text.len() {
                    if Self::match_recursive(segments, &text[i..], seg_idx + 1) {
                        return true;
                    }
                }
                false
            }
            Segment::Question => {
                if !text.is_empty() && text[0] != b'/' {
                    Self::match_recursive(segments, &text[1..], seg_idx + 1)
                } else {
                    false
                }
            }
            Segment::CharClass { chars, negated } => {
                if text.is_empty() {
                    return false;
                }
                let ch = text[0];
                let in_class = chars.contains(&ch);
                let matched = if *negated { !in_class } else { in_class };
                if matched {
                    Self::match_recursive(segments, &text[1..], seg_idx + 1)
                } else {
                    false
                }
            }
        }
    }

    /// The original pattern source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether this pattern only matches directories.
    pub fn dir_only(&self) -> bool {
        self.dir_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_match() {
        let p = Pattern::new("foo.txt").unwrap();
        assert!(p.matches(b"foo.txt", false));
        assert!(p.matches(b"bar/foo.txt", false));
        assert!(!p.matches(b"foo.txt.bak", false));
    }

    #[test]
    fn test_star() {
        let p = Pattern::new("*.txt").unwrap();
        assert!(p.matches(b"foo.txt", false));
        assert!(p.matches(b"bar/baz.txt", false));
        assert!(!p.matches(b"foo.rs", false));
    }

    #[test]
    fn test_double_star() {
        let p = Pattern::new("**/*.txt").unwrap();
        assert!(p.matches(b"foo.txt", false));
        assert!(p.matches(b"a/b/c.txt", false));
        assert!(!p.matches(b"foo.rs", false));
    }

    #[test]
    fn test_question_mark() {
        let p = Pattern::new("?.txt").unwrap();
        assert!(p.matches(b"a.txt", false));
        assert!(!p.matches(b"ab.txt", false));
        assert!(!p.matches(b".txt", false));
    }

    #[test]
    fn test_anchored() {
        let p = Pattern::new("/foo.txt").unwrap();
        assert!(p.matches(b"foo.txt", false));
        assert!(!p.matches(b"bar/foo.txt", false));
    }

    #[test]
    fn test_dir_only() {
        let p = Pattern::new("build/").unwrap();
        assert!(p.matches(b"build", true));
        assert!(!p.matches(b"build", false));
    }

    #[test]
    fn test_char_class() {
        let p = Pattern::new("[abc].txt").unwrap();
        assert!(p.matches(b"a.txt", false));
        assert!(p.matches(b"b.txt", false));
        assert!(!p.matches(b"d.txt", false));
    }

    #[test]
    fn test_negated_char_class() {
        let p = Pattern::new("[!abc].txt").unwrap();
        assert!(!p.matches(b"a.txt", false));
        assert!(p.matches(b"d.txt", false));
    }

    #[test]
    fn test_char_range() {
        let p = Pattern::new("[a-z].txt").unwrap();
        assert!(p.matches(b"m.txt", false));
        assert!(!p.matches(b"1.txt", false));
    }

    #[test]
    fn test_path_with_slashes() {
        let p = Pattern::new("src/*.rs").unwrap();
        assert!(p.matches(b"src/main.rs", false));
        assert!(!p.matches(b"tests/main.rs", false));
        // Anchored because contains /
        assert!(!p.matches(b"foo/src/main.rs", false));
    }

    #[test]
    fn test_double_star_path() {
        let p = Pattern::new("src/**/*.rs").unwrap();
        assert!(p.matches(b"src/main.rs", false));
        assert!(p.matches(b"src/foo/bar/baz.rs", false));
    }

    #[test]
    fn test_unterminated_char_class() {
        let result = Pattern::new("[abc");
        assert!(matches!(result, Err(FilterError::InvalidPattern { .. })));
    }
}
