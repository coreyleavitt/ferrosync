//! Challenge-response authentication for the rsync daemon protocol.
//!
//! The rsync daemon uses an MD5-based (historically MD4) challenge-response
//! scheme:
//!
//! 1. Server generates a random challenge and sends it base64-encoded.
//! 2. Client computes `MD5(zero_padded_password + challenge)`, base64-encodes
//!    it, and sends `<user> <hash>\n`.
//! 3. Server looks up the user's password in a secrets file, computes the
//!    same hash, and compares.
//!
//! The secrets file format is one `user:password` entry per line.
//! Lines starting with `#` are comments.
//!
//! Modeled after rsync's `authenticate.c`.

use std::path::Path;

use md5::{Digest, Md5};

/// Authentication-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("failed to read secrets file {path}: {source}")]
    ReadSecretsFile {
        path: String,
        source: std::io::Error,
    },

    #[error("authentication failed for user '{user}'")]
    AuthFailed { user: String },

    #[error("user '{user}' not found in secrets file")]
    UserNotFound { user: String },

    #[error("invalid auth response format")]
    InvalidResponse,
}

/// Maximum password length (matches rsync's zero-padding size).
const MAX_PASSWORD_LEN: usize = 64;

/// Counter for challenge uniqueness within a single process.
static CHALLENGE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Generate a random challenge string, returned as base64.
///
/// The challenge incorporates time, PID, and a counter to ensure
/// uniqueness per connection (matching rsync's approach in
/// `authenticate.c:gen_challenge()` which uses address + time + pid).
pub fn generate_challenge() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut input = [0u8; 32];

    // Mix in current time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs().to_le_bytes();
    let nanos = now.subsec_nanos().to_le_bytes();
    input[..8].copy_from_slice(&secs);
    input[8..12].copy_from_slice(&nanos);

    // Mix in process ID.
    let pid = std::process::id().to_le_bytes();
    input[12..16].copy_from_slice(&pid);

    // Mix in monotonic counter for uniqueness within the same process.
    let counter = CHALLENGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let counter_bytes = counter.to_le_bytes();
    input[16..24].copy_from_slice(&counter_bytes);

    // Hash to produce the challenge digest.
    let mut hasher = Md5::new();
    hasher.update(input);
    let digest = hasher.finalize();

    base64_encode(&digest)
}

/// Compute the expected auth response hash for a given password and challenge.
///
/// This matches the rsync client's computation:
/// 1. Zero-pad the password to 64 bytes.
/// 2. Compute `MD5(padded_password + challenge_bytes)`.
/// 3. Base64-encode the result.
///
/// Note: rsync historically used MD4, but modern versions (protocol 31+)
/// use MD5 for daemon auth. We use MD5 here.
pub fn compute_response(password: &str, challenge: &str) -> String {
    let mut padded = [0u8; MAX_PASSWORD_LEN];
    let pw_bytes = password.as_bytes();
    let copy_len = pw_bytes.len().min(MAX_PASSWORD_LEN);
    padded[..copy_len].copy_from_slice(&pw_bytes[..copy_len]);

    let mut hasher = Md5::new();
    hasher.update(padded);
    hasher.update(challenge.as_bytes());
    let digest = hasher.finalize();

    base64_encode(&digest)
}

/// Verify a client's auth response against a secrets file.
///
/// Returns `Ok(())` if authentication succeeds, or an appropriate error.
///
/// # Arguments
///
/// * `user` - The username sent by the client.
/// * `client_hash` - The base64-encoded hash sent by the client.
/// * `challenge` - The challenge string that was sent to the client.
/// * `secrets_path` - Path to the secrets file.
pub fn verify_response(
    user: &str,
    client_hash: &str,
    challenge: &str,
    secrets_path: &Path,
) -> Result<(), AuthError> {
    let password = lookup_password(user, secrets_path)?;
    let expected_hash = compute_response(&password, challenge);

    if constant_time_eq(expected_hash.as_bytes(), client_hash.as_bytes()) {
        Ok(())
    } else {
        Err(AuthError::AuthFailed {
            user: user.to_string(),
        })
    }
}

/// Parse an auth response line from the client.
///
/// The format is `<user> <hash>\n`. Returns `(user, hash)`.
pub fn parse_auth_response(line: &str) -> Result<(&str, &str), AuthError> {
    let trimmed = line.trim();
    match trimmed.split_once(' ') {
        Some((user, hash)) if !user.is_empty() && !hash.is_empty() => Ok((user, hash)),
        _ => Err(AuthError::InvalidResponse),
    }
}

/// Look up a user's password in a secrets file.
///
/// The secrets file format:
/// - One entry per line: `username:password`
/// - Lines starting with `#` are comments.
/// - Empty lines are skipped.
fn lookup_password(user: &str, secrets_path: &Path) -> Result<String, AuthError> {
    let content =
        std::fs::read_to_string(secrets_path).map_err(|e| AuthError::ReadSecretsFile {
            path: secrets_path.display().to_string(),
            source: e,
        })?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((file_user, password)) = line.split_once(':') {
            if file_user.trim() == user {
                return Ok(password.trim().to_string());
            }
        }
    }

    Err(AuthError::UserNotFound {
        user: user.to_string(),
    })
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Base64 encoder (standard alphabet with padding).
///
/// This is a standalone implementation to avoid adding a dependency,
/// matching the encoder in `transport/daemon.rs`.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        match chunk.len() {
            3 => {
                let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n & 0x3F) as usize] as char);
            }
            2 => {
                let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
                result.push('=');
            }
            1 => {
                let n = (chunk[0] as u32) << 16;
                result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
                result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
                result.push('=');
                result.push('=');
            }
            // chunks(3) only yields slices of length 1, 2, or 3.
            _ => unreachable!("chunks(3) produced an empty slice"),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_challenge_uniqueness() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, c2, "challenges should be unique");
    }

    #[test]
    fn test_generate_challenge_format() {
        let challenge = generate_challenge();
        // MD5 digest is 16 bytes, base64-encoded = 24 chars (with padding).
        assert_eq!(challenge.len(), 24);
        assert!(challenge
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_compute_response_deterministic() {
        let r1 = compute_response("password", "challenge");
        let r2 = compute_response("password", "challenge");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_compute_response_varies_with_password() {
        let r1 = compute_response("pass1", "challenge");
        let r2 = compute_response("pass2", "challenge");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_response_varies_with_challenge() {
        let r1 = compute_response("password", "challenge1");
        let r2 = compute_response("password", "challenge2");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_response_format() {
        let r = compute_response("test", "test");
        // MD5 is 16 bytes -> 24 base64 chars.
        assert_eq!(r.len(), 24);
    }

    #[test]
    fn test_verify_response_success() {
        let mut secrets = NamedTempFile::new().unwrap();
        writeln!(secrets, "admin:s3cret").unwrap();
        writeln!(secrets, "user:password123").unwrap();

        let challenge = generate_challenge();
        let hash = compute_response("s3cret", &challenge);

        let result = verify_response("admin", &hash, &challenge, secrets.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_wrong_password() {
        let mut secrets = NamedTempFile::new().unwrap();
        writeln!(secrets, "admin:correct_password").unwrap();

        let challenge = generate_challenge();
        let hash = compute_response("wrong_password", &challenge);

        let result = verify_response("admin", &hash, &challenge, secrets.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::AuthFailed { user } => assert_eq!(user, "admin"),
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_response_unknown_user() {
        let mut secrets = NamedTempFile::new().unwrap();
        writeln!(secrets, "admin:password").unwrap();

        let challenge = generate_challenge();
        let hash = compute_response("password", &challenge);

        let result = verify_response("unknown", &hash, &challenge, secrets.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::UserNotFound { user } => assert_eq!(user, "unknown"),
            other => panic!("expected UserNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_response_missing_secrets_file() {
        let result = verify_response(
            "admin",
            "hash",
            "challenge",
            Path::new("/nonexistent/secrets"),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::ReadSecretsFile { .. } => {}
            other => panic!("expected ReadSecretsFile, got {other:?}"),
        }
    }

    #[test]
    fn test_lookup_password_with_comments() {
        let mut secrets = NamedTempFile::new().unwrap();
        writeln!(secrets, "# This is a comment").unwrap();
        writeln!(secrets).unwrap();
        writeln!(secrets, "admin:secret").unwrap();
        writeln!(secrets, "# Another comment").unwrap();
        writeln!(secrets, "user:pass").unwrap();

        let pw = lookup_password("admin", secrets.path()).unwrap();
        assert_eq!(pw, "secret");

        let pw = lookup_password("user", secrets.path()).unwrap();
        assert_eq!(pw, "pass");
    }

    #[test]
    fn test_parse_auth_response_valid() {
        let (user, hash) = parse_auth_response("admin abc123hash\n").unwrap();
        assert_eq!(user, "admin");
        assert_eq!(hash, "abc123hash");
    }

    #[test]
    fn test_parse_auth_response_no_newline() {
        let (user, hash) = parse_auth_response("user hashvalue").unwrap();
        assert_eq!(user, "user");
        assert_eq!(hash, "hashvalue");
    }

    #[test]
    fn test_parse_auth_response_invalid_no_space() {
        let result = parse_auth_response("nospace");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_auth_response_invalid_empty() {
        let result = parse_auth_response("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_auth_response_invalid_empty_user() {
        let result = parse_auth_response(" hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_full_auth_round_trip() {
        let mut secrets = NamedTempFile::new().unwrap();
        writeln!(secrets, "backup_user:MyS3cretP@ss").unwrap();

        // Server generates challenge.
        let challenge = generate_challenge();

        // Client computes response (simulating what transport/daemon.rs does).
        let client_hash = compute_response("MyS3cretP@ss", &challenge);
        let auth_line = format!("backup_user {client_hash}");

        // Server parses and verifies.
        let (user, hash) = parse_auth_response(&auth_line).unwrap();
        let result = verify_response(user, hash, &challenge, secrets.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_long_password_truncated() {
        // Passwords longer than 64 bytes should be silently truncated.
        let long_pw = "a".repeat(100);
        let r = compute_response(&long_pw, "challenge");
        // Should equal the response for the first 64 chars.
        let truncated_pw = "a".repeat(64);
        let r_truncated = compute_response(&truncated_pw, "challenge");
        assert_eq!(r, r_truncated);
    }
}
