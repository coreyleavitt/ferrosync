use std::collections::BTreeMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Tree comparison
// ---------------------------------------------------------------------------

/// Recursively collect all files in a directory tree as (relative_path, contents).
pub fn collect_files(root: &Path, current: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    if !current.is_dir() {
        return files;
    }
    for entry in std::fs::read_dir(current).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            files.extend(collect_files(root, &path));
        } else if path.is_file() {
            files.insert(rel, std::fs::read(&path).unwrap());
        }
    }
    files
}

/// Assert two directory trees are identical (file names and contents).
pub fn assert_trees_equal(expected: &Path, actual: &Path) {
    let expected_files = collect_files(expected, expected);
    let actual_files = collect_files(actual, actual);

    assert_eq!(
        expected_files.len(),
        actual_files.len(),
        "file count mismatch: expected {:?}, got {:?}",
        expected_files.keys().collect::<Vec<_>>(),
        actual_files.keys().collect::<Vec<_>>(),
    );

    for (rel_path, expected_content) in &expected_files {
        let actual_content = actual_files
            .get(rel_path)
            .unwrap_or_else(|| panic!("missing file in dest: {rel_path}"));
        assert_eq!(
            expected_content, actual_content,
            "content mismatch for {rel_path}"
        );
    }
}

/// Options for metadata-aware tree comparison.
pub struct TreeMatchOpts {
    /// Compare file contents (always true in practice).
    pub check_content: bool,
    /// Compare file permissions (for `-p` tests).
    pub check_perms: bool,
    /// Compare modification times (for `-t` tests).
    pub check_mtime: bool,
    /// Allowed mtime difference in seconds (clock skew tolerance).
    pub mtime_tolerance_secs: i64,
}

impl Default for TreeMatchOpts {
    fn default() -> Self {
        Self {
            check_content: true,
            check_perms: false,
            check_mtime: false,
            mtime_tolerance_secs: 2,
        }
    }
}

impl TreeMatchOpts {
    pub fn content_only() -> Self {
        Self::default()
    }

    pub fn with_perms() -> Self {
        Self {
            check_perms: true,
            ..Self::default()
        }
    }

    pub fn with_mtime() -> Self {
        Self {
            check_mtime: true,
            ..Self::default()
        }
    }

    pub fn archive() -> Self {
        Self {
            check_content: true,
            check_perms: true,
            check_mtime: true,
            mtime_tolerance_secs: 2,
        }
    }
}

/// Assert two directory trees match, optionally comparing metadata.
///
/// This is the primary assertion for engine and interop tests. Use
/// `TreeMatchOpts` to control which metadata fields are compared.
pub fn assert_trees_match(expected: &Path, actual: &Path, opts: &TreeMatchOpts) {
    let expected_files = collect_files(expected, expected);
    let actual_files = collect_files(actual, actual);

    assert_eq!(
        expected_files.len(),
        actual_files.len(),
        "file count mismatch: expected {:?}, got {:?}",
        expected_files.keys().collect::<Vec<_>>(),
        actual_files.keys().collect::<Vec<_>>(),
    );

    for (rel_path, expected_content) in &expected_files {
        let actual_content = actual_files
            .get(rel_path)
            .unwrap_or_else(|| panic!("missing file in dest: {rel_path}"));

        if opts.check_content {
            assert_eq!(
                expected_content, actual_content,
                "content mismatch for {rel_path}"
            );
        }

        let expected_path = expected.join(rel_path);
        let actual_path = actual.join(rel_path);

        if opts.check_mtime {
            assert_mtime_match(&expected_path, &actual_path, opts.mtime_tolerance_secs, rel_path);
        }

        #[cfg(unix)]
        if opts.check_perms {
            assert_perms_match(&expected_path, &actual_path, rel_path);
        }
    }
}

/// Assert two files have matching mtimes (within tolerance).
fn assert_mtime_match(expected: &Path, actual: &Path, tolerance_secs: i64, context: &str) {
    let expected_mtime = std::fs::metadata(expected)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let actual_mtime = std::fs::metadata(actual)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let diff = (expected_mtime - actual_mtime).abs();
    assert!(
        diff <= tolerance_secs,
        "mtime mismatch for {context}: expected {expected_mtime}, got {actual_mtime} (diff {diff}s, tolerance {tolerance_secs}s)"
    );
}

/// Assert two files have matching permissions.
#[cfg(unix)]
fn assert_perms_match(expected: &Path, actual: &Path, context: &str) {
    use std::os::unix::fs::PermissionsExt;
    let expected_mode = std::fs::metadata(expected).unwrap().permissions().mode() & 0o7777;
    let actual_mode = std::fs::metadata(actual).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        expected_mode, actual_mode,
        "permission mismatch for {context}: expected {expected_mode:04o}, got {actual_mode:04o}"
    );
}

// ---------------------------------------------------------------------------
// Single-file assertions
// ---------------------------------------------------------------------------

/// Assert a file has the expected content.
pub fn assert_file_content(path: &Path, expected: &[u8]) {
    let actual = std::fs::read(path).unwrap_or_else(|e| {
        panic!("failed to read {}: {e}", path.display());
    });
    assert_eq!(
        actual, expected,
        "content mismatch for {}",
        path.display()
    );
}

/// Assert a file does not exist.
pub fn assert_file_absent(path: &Path) {
    assert!(
        !path.exists(),
        "expected {} to not exist, but it does",
        path.display()
    );
}

/// Assert a file exists (without checking content).
pub fn assert_file_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist, but it does not",
        path.display()
    );
}

/// Assert mtime of a file matches expected Unix timestamp (with tolerance).
pub fn assert_mtime(path: &Path, expected_unix: i64, tolerance_secs: i64) {
    let actual = std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let diff = (expected_unix - actual).abs();
    assert!(
        diff <= tolerance_secs,
        "mtime mismatch for {}: expected {expected_unix}, got {actual} (diff {diff}s)",
        path.display()
    );
}

/// Assert file permissions match expected mode.
#[cfg(unix)]
pub fn assert_permissions(path: &Path, expected_mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let actual = std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        actual, expected_mode,
        "permission mismatch for {}: expected {expected_mode:04o}, got {actual:04o}",
        path.display()
    );
}

// ---------------------------------------------------------------------------
// Remote (SSH) assertions
// ---------------------------------------------------------------------------

/// Assert a remote file has the expected content.
pub async fn assert_remote_content(path: &str, expected: &str) {
    let actual = crate::common::ssh::remote_cat(path).await;
    assert_eq!(
        actual, expected,
        "remote content mismatch for {path}"
    );
}

/// Assert a remote file does not exist.
pub async fn assert_remote_absent(path: &str) {
    assert!(
        !crate::common::ssh::remote_exists(path).await,
        "expected remote {path} to not exist, but it does"
    );
}

/// Assert a remote file exists.
pub async fn assert_remote_exists(path: &str) {
    assert!(
        crate::common::ssh::remote_exists(path).await,
        "expected remote {path} to exist, but it does not"
    );
}

// ---------------------------------------------------------------------------
// Hard-link assertions
// ---------------------------------------------------------------------------

/// Assert that two paths refer to the same inode (are hard-linked).
#[cfg(unix)]
pub fn assert_hard_linked(a: &Path, b: &Path) {
    use crate::common::env::inode_of;
    assert_eq!(
        inode_of(a),
        inode_of(b),
        "{} should be hard-linked to {}",
        a.display(),
        b.display(),
    );
}

/// Assert that two paths do NOT share an inode.
#[cfg(unix)]
pub fn assert_not_hard_linked(a: &Path, b: &Path) {
    use crate::common::env::inode_of;
    assert_ne!(
        inode_of(a),
        inode_of(b),
        "{} should NOT be hard-linked to {}",
        a.display(),
        b.display(),
    );
}
