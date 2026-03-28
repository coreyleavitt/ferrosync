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
            assert_mtime_match(
                &expected_path,
                &actual_path,
                opts.mtime_tolerance_secs,
                rel_path,
            );
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
    assert_eq!(actual, expected, "content mismatch for {}", path.display());
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
        actual,
        expected_mode,
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
    assert_eq!(actual, expected, "remote content mismatch for {path}");
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
// Remote metadata assertions
// ---------------------------------------------------------------------------

/// Assert a remote file's mtime matches expected Unix timestamp.
pub async fn assert_remote_mtime(path: &str, expected_unix: i64, tolerance_secs: i64) {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%Y", path]).await;
    let actual: i64 = output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("failed to parse remote mtime for {path}: {output:?}"));
    let diff = (expected_unix - actual).abs();
    assert!(
        diff <= tolerance_secs,
        "remote mtime mismatch for {path}: expected {expected_unix}, got {actual} (diff {diff}s)"
    );
}

/// Assert a remote file has the expected Unix permissions (octal mode & 0o7777).
pub async fn assert_remote_permissions(path: &str, expected_mode: u32) {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%a", path]).await;
    let actual = u32::from_str_radix(output.trim(), 8)
        .unwrap_or_else(|_| panic!("failed to parse remote permissions for {path}: {output:?}"));
    assert_eq!(
        actual, expected_mode,
        "remote permission mismatch for {path}: expected {expected_mode:04o}, got {actual:04o}"
    );
}

/// Assert a remote file has the expected size in bytes.
pub async fn assert_remote_size(path: &str, expected_bytes: u64) {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%s", path]).await;
    let actual: u64 = output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("failed to parse remote size for {path}: {output:?}"));
    assert_eq!(
        actual, expected_bytes,
        "remote size mismatch for {path}: expected {expected_bytes}, got {actual}"
    );
}

/// Assert a remote file has the expected uid:gid.
pub async fn assert_remote_ownership(path: &str, expected_uid: u32, expected_gid: u32) {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%u:%g", path]).await;
    let parts: Vec<&str> = output.trim().split(':').collect();
    let uid: u32 = parts[0].parse().unwrap();
    let gid: u32 = parts[1].parse().unwrap();
    assert_eq!(uid, expected_uid, "remote uid mismatch for {path}");
    assert_eq!(gid, expected_gid, "remote gid mismatch for {path}");
}

/// Get the inode number of a remote file.
pub async fn remote_inode(path: &str) -> u64 {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%i", path]).await;
    output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("failed to parse remote inode for {path}: {output:?}"))
}

/// Assert two remote paths share an inode (are hard-linked).
pub async fn assert_remote_hard_linked(a: &str, b: &str) {
    let inode_a = remote_inode(a).await;
    let inode_b = remote_inode(b).await;
    assert_eq!(inode_a, inode_b, "remote {a} should be hard-linked to {b}");
}

/// Assert two remote paths do NOT share an inode.
pub async fn assert_remote_not_hard_linked(a: &str, b: &str) {
    let inode_a = remote_inode(a).await;
    let inode_b = remote_inode(b).await;
    assert_ne!(
        inode_a, inode_b,
        "remote {a} should NOT be hard-linked to {b}"
    );
}

/// Assert a remote path is a directory.
pub async fn assert_remote_is_dir(path: &str) {
    let output = crate::common::ssh::ssh_cmd(&["test", "-d", path, "&&", "echo", "yes"]).await;
    assert_eq!(
        output.trim(),
        "yes",
        "expected remote {path} to be a directory"
    );
}

/// Get the number of 512-byte disk blocks allocated to a remote file.
pub async fn remote_blocks(path: &str) -> u64 {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%b", path]).await;
    output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("failed to parse remote blocks for {path}: {output:?}"))
}

/// Assert a remote path is a regular file (not a symlink, directory, etc.).
pub async fn assert_remote_is_regular_file(path: &str) {
    let output = crate::common::ssh::ssh_cmd(&["stat", "-c", "%F", path]).await;
    assert_eq!(
        output.trim(),
        "regular file",
        "expected remote {path} to be a regular file, got: {}",
        output.trim()
    );
}

/// Assert a remote path is a symlink.
pub async fn assert_remote_is_symlink(path: &str) {
    let output = crate::common::ssh::ssh_cmd(&["test", "-L", path, "&&", "echo", "yes"]).await;
    assert_eq!(
        output.trim(),
        "yes",
        "expected remote {path} to be a symlink"
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
