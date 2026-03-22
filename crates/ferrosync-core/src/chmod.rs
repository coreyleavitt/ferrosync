//! Permission override parsing and application (`--chmod`).
//!
//! Implements rsync's `--chmod` mini-language for modifying file permissions.
//! Specs are comma-separated rules like `Du+rwx,Fog-w,a+r`.

use std::fmt;

/// Error from parsing a chmod spec.
#[derive(Debug, Clone)]
pub struct ChmodError {
    pub spec: String,
    pub message: String,
}

impl fmt::Display for ChmodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid chmod spec '{}': {}", self.spec, self.message)
    }
}

impl std::error::Error for ChmodError {}

/// Scope: which file types the rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChmodScope {
    All,
    Files,
    Dirs,
}

/// Operator: how to modify the permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChmodOp {
    Set,    // =
    Add,    // +
    Remove, // -
}

/// A single chmod rule.
#[derive(Debug, Clone)]
struct ChmodRule {
    scope: ChmodScope,
    op: ChmodOp,
    /// Bitmask selecting which positions to affect (shifted to correct u/g/o positions).
    who_mask: u32,
    /// Permission bits to set/add/remove.
    bits: u32,
    /// Whether this rule uses `X` (conditional execute).
    conditional_exec: bool,
}

/// A parsed chmod specification, ready to apply to file modes.
#[derive(Debug, Clone)]
pub struct ChmodSpec {
    rules: Vec<ChmodRule>,
}

impl ChmodSpec {
    /// Parse a chmod spec string (e.g., `Du+rwx,Fog-w,a+r`).
    pub fn parse(s: &str) -> Result<Self, ChmodError> {
        let mut rules = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            rules.push(parse_rule(part).map_err(|msg| ChmodError {
                spec: part.to_string(),
                message: msg,
            })?);
        }
        Ok(Self { rules })
    }

    /// Apply the chmod spec to a file mode, returning the modified mode.
    ///
    /// Only the permission bits (lower 12 bits: 0o7777) are modified.
    /// The file type bits are preserved.
    pub fn apply(&self, mode: u32, is_dir: bool) -> u32 {
        let mut perms = mode & 0o7777;
        for rule in &self.rules {
            match rule.scope {
                ChmodScope::Files if is_dir => continue,
                ChmodScope::Dirs if !is_dir => continue,
                _ => {}
            }

            let mut bits = rule.bits;
            if rule.conditional_exec {
                // X: set execute only if is_dir or any exec bit already set
                if is_dir || (perms & 0o111) != 0 {
                    bits |= rule.who_mask & 0o111;
                }
            }

            match rule.op {
                ChmodOp::Add => perms |= bits,
                ChmodOp::Remove => perms &= !bits,
                ChmodOp::Set => {
                    // Clear the who positions, then set the new bits
                    perms &= !rule.who_mask;
                    perms |= bits;
                }
            }
        }
        (mode & !0o7777) | perms
    }
}

fn parse_rule(s: &str) -> Result<ChmodRule, String> {
    let bytes = s.as_bytes();
    let mut pos = 0;

    // Optional scope prefix: D or F
    let scope = if pos < bytes.len() && bytes[pos] == b'D' {
        pos += 1;
        ChmodScope::Dirs
    } else if pos < bytes.len() && bytes[pos] == b'F' {
        pos += 1;
        ChmodScope::Files
    } else {
        ChmodScope::All
    };

    // Who: u, g, o, a (can be multiple)
    let mut who_mask: u32 = 0;
    while pos < bytes.len() && matches!(bytes[pos], b'u' | b'g' | b'o' | b'a') {
        match bytes[pos] {
            b'u' => who_mask |= 0o4700,
            b'g' => who_mask |= 0o2070,
            b'o' => who_mask |= 0o1007,
            b'a' => who_mask |= 0o7777,
            _ => unreachable!(),
        }
        pos += 1;
    }
    if who_mask == 0 {
        // Default to 'a' if no who specified
        who_mask = 0o7777;
    }

    // Operator: +, -, =
    if pos >= bytes.len() {
        return Err("missing operator (+, -, =)".to_string());
    }
    let op = match bytes[pos] {
        b'+' => ChmodOp::Add,
        b'-' => ChmodOp::Remove,
        b'=' => ChmodOp::Set,
        c => return Err(format!("expected operator, got '{}'", c as char)),
    };
    pos += 1;

    // Permissions: r, w, x, X, s, t
    let mut bits: u32 = 0;
    let mut conditional_exec = false;
    while pos < bytes.len() {
        match bytes[pos] {
            b'r' => bits |= who_mask & 0o444,
            b'w' => bits |= who_mask & 0o222,
            b'x' => bits |= who_mask & 0o111,
            b'X' => conditional_exec = true,
            b's' => bits |= who_mask & 0o6000,
            b't' => bits |= 0o1000,
            c => return Err(format!("unexpected permission char '{}'", c as char)),
        }
        pos += 1;
    }

    Ok(ChmodRule {
        scope,
        op,
        who_mask,
        bits,
        conditional_exec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_add() {
        let spec = ChmodSpec::parse("u+rwx").unwrap();
        // File mode 0o644 -> add user execute -> 0o744
        assert_eq!(spec.apply(0o100644, false), 0o100744);
    }

    #[test]
    fn test_parse_remove() {
        let spec = ChmodSpec::parse("go-w").unwrap();
        // 0o666 -> remove group+other write -> 0o644
        assert_eq!(spec.apply(0o100666, false), 0o100644);
    }

    #[test]
    fn test_parse_set() {
        let spec = ChmodSpec::parse("a=r").unwrap();
        // Set all to read-only -> 0o444
        assert_eq!(spec.apply(0o100777, false), 0o100444);
    }

    #[test]
    fn test_dir_scope() {
        let spec = ChmodSpec::parse("Du+x").unwrap();
        // Should apply to dirs, not files
        assert_eq!(spec.apply(0o040644, true), 0o040744);
        assert_eq!(spec.apply(0o100644, false), 0o100644); // no change for files
    }

    #[test]
    fn test_file_scope() {
        let spec = ChmodSpec::parse("Fo-x").unwrap();
        // Should apply to files, not dirs
        assert_eq!(spec.apply(0o100755, false), 0o100754);
        assert_eq!(spec.apply(0o040755, true), 0o040755); // no change for dirs
    }

    #[test]
    fn test_multiple_rules() {
        let spec = ChmodSpec::parse("Du+rwx,Fog-w,a+r").unwrap();
        // Dir: u+rwx -> adds exec for user
        assert_eq!(spec.apply(0o040644, true) & 0o7777, 0o744 | 0o004);
        // File: og-w, a+r -> remove group/other write, add read for all
        let result = spec.apply(0o100666, false);
        assert_eq!(result & 0o7777, 0o644);
    }

    #[test]
    fn test_conditional_exec_on_dir() {
        let spec = ChmodSpec::parse("a+X").unwrap();
        // Dirs always get execute
        assert_eq!(spec.apply(0o040644, true) & 0o7777, 0o755);
    }

    #[test]
    fn test_conditional_exec_on_file_with_exec() {
        let spec = ChmodSpec::parse("a+X").unwrap();
        // File with existing exec bit -> add exec for all
        assert_eq!(spec.apply(0o100744, false) & 0o7777, 0o755);
    }

    #[test]
    fn test_conditional_exec_on_file_without_exec() {
        let spec = ChmodSpec::parse("a+X").unwrap();
        // File without exec -> no change
        assert_eq!(spec.apply(0o100644, false) & 0o7777, 0o644);
    }

    #[test]
    fn test_setuid() {
        let spec = ChmodSpec::parse("u+s").unwrap();
        assert_eq!(spec.apply(0o100755, false) & 0o7777, 0o4755);
    }

    #[test]
    fn test_sticky() {
        let spec = ChmodSpec::parse("a+t").unwrap();
        assert_eq!(spec.apply(0o040755, true) & 0o7777, 0o1755);
    }

    #[test]
    fn test_parse_error() {
        assert!(ChmodSpec::parse("z+r").is_err());
    }

    #[test]
    fn test_empty_spec() {
        let spec = ChmodSpec::parse("").unwrap();
        assert_eq!(spec.apply(0o100644, false), 0o100644);
    }
}
