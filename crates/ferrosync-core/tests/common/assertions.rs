use std::collections::BTreeMap;
use std::path::Path;

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
