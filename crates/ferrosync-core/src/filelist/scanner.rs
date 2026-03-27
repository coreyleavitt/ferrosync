//! Composable file list scanning pipeline.
//!
//! `FileListScanner` unifies the directory walking logic previously duplicated
//! across `engine/transfer.rs` (build_file_list / collect_directory) and
//! `filelist/walk.rs` (collect_directory_entries) into a single composable
//! implementation.
//!
//! The scanner walks the filesystem, applies filter rules inline during
//! recursion, and runs per-entry enrichers immediately after each entry is
//! scanned. Finalize enrichers run once after all entries are collected
//! (for cross-entry operations like hardlink grouping).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::FsError;
use crate::filelist::entry::{self, FileEntry, S_IFDIR, S_IFMT};
use crate::filter::FilterRuleList;
use crate::fs::{DirEntry, FileSystem};
use crate::options::DirectoryMode;

// ---------------------------------------------------------------------------
// FileListItem
// ---------------------------------------------------------------------------

/// A file list entry with associated source path and index.
///
/// This pairs a `FileEntry` (wire-format metadata) with the filesystem
/// source path needed for the transfer engine to read file data.
#[derive(Debug)]
pub struct FileListItem {
    /// Index in the file list (used for progress events and wire references).
    pub index: i32,
    /// The wire-format file entry metadata.
    pub entry: FileEntry,
    /// Absolute path to the source file on disk.
    pub source_path: PathBuf,
}

// ---------------------------------------------------------------------------
// ScanOptions
// ---------------------------------------------------------------------------

/// Options controlling the file list scan behavior.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// How to handle directories: recurse, list, or skip.
    pub dir_mode: DirectoryMode,
    /// Don't cross filesystem boundaries (`-x`).
    pub one_file_system: bool,
    /// Follow symlinks during scan (`-L`).
    pub copy_links: bool,
    /// Preserve full relative path structure (`-R`).
    pub relative: bool,
    /// Per-directory .rsync-filter merge level: 0=off, 1=-F, 2=-FF.
    pub filter_merge_files: u8,
    /// Compute hardlink groups (`-H`).
    pub preserve_hard_links: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            dir_mode: DirectoryMode::Skip,
            one_file_system: false,
            copy_links: false,
            relative: false,
            filter_merge_files: 0,
            preserve_hard_links: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FileListEnricher trait
// ---------------------------------------------------------------------------

/// Trait for per-entry and post-scan enrichment of file list entries.
///
/// Enrichers are composable pipeline stages that augment scanned entries
/// with additional data (e.g., symlink targets, hardlink grouping).
pub trait FileListEnricher {
    /// Called for each entry immediately after it is scanned.
    ///
    /// The enricher may modify the entry in place (e.g., populate
    /// `link_target` for symlinks). The `path` is the absolute filesystem
    /// path of the entry.
    fn enrich(&self, _entry: &mut FileEntry, _path: &Path) {}

    /// Called once after all entries have been collected.
    ///
    /// Used for cross-entry operations like hardlink group detection.
    fn finalize(&self, _items: &mut [FileListItem]) {}
}

// ---------------------------------------------------------------------------
// SymlinkEnricher
// ---------------------------------------------------------------------------

/// Enricher that reads symlink targets for symlink entries.
///
/// When `copy_links` is false and an entry is a symlink, this enricher
/// reads the link target from the filesystem and populates
/// `entry.link_target`.
pub struct SymlinkEnricher<'a> {
    fs: &'a dyn FileSystem,
}

impl<'a> SymlinkEnricher<'a> {
    pub fn new(fs: &'a dyn FileSystem) -> Self {
        Self { fs }
    }
}

impl<'a> FileListEnricher for SymlinkEnricher<'a> {
    fn enrich(&self, entry: &mut FileEntry, path: &Path) {
        if entry.is_symlink() {
            entry.link_target = match self.fs.read_link(path) {
                Ok(target) => target,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to read symlink target");
                    Vec::new()
                }
            };
        }
    }
}

// ---------------------------------------------------------------------------
// AclEnricher
// ---------------------------------------------------------------------------

/// Enricher that reads POSIX ACLs from filesystem xattrs.
///
/// Reads `system.posix_acl_access` (and `system.posix_acl_default` for
/// directories) xattrs and populates `entry.acl`.
#[cfg(unix)]
pub struct AclEnricher<'a> {
    fs: &'a dyn FileSystem,
}

#[cfg(unix)]
impl<'a> AclEnricher<'a> {
    pub fn new(fs: &'a dyn FileSystem) -> Self {
        Self { fs }
    }
}

#[cfg(unix)]
impl<'a> FileListEnricher for AclEnricher<'a> {
    fn enrich(&self, entry: &mut FileEntry, path: &Path) {
        // Symlinks don't have ACLs.
        if entry.is_symlink() {
            return;
        }

        let access = match self.fs.get_xattr(path, b"system.posix_acl_access") {
            Ok(Some(data)) => match crate::acl::parse_posix_acl_binary(&data) {
                Ok(acl) => Some(acl),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to parse access ACL");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::trace!(path = %path.display(), error = %e, "no access ACL");
                None
            }
        };

        let default = if entry.is_dir() {
            match self.fs.get_xattr(path, b"system.posix_acl_default") {
                Ok(Some(data)) => match crate::acl::parse_posix_acl_binary(&data) {
                    Ok(acl) => Some(acl),
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "failed to parse default ACL");
                        None
                    }
                },
                Ok(None) => None,
                Err(_) => None,
            }
        } else {
            None
        };

        if let Some(access_acl) = access {
            entry.acl = Some(crate::acl::Acl::Posix(crate::acl::PosixAcl {
                access: access_acl,
                default,
            }));
        }
    }
}

// ---------------------------------------------------------------------------
// XattrEnricher
// ---------------------------------------------------------------------------

/// Enricher that reads extended attributes from the filesystem.
///
/// Reads all xattrs via `fs.list_xattrs()` + `fs.get_xattr()`, filtering out:
/// - `system.posix_acl_access` and `system.posix_acl_default` (handled by --acls)
/// - `system.*` namespace (requires root on Linux)
/// - `user.rsync.%*` internal attributes
///
/// Entries are sorted by name for deterministic dedup.
#[cfg(unix)]
pub struct XattrEnricher<'a> {
    fs: &'a dyn FileSystem,
}

#[cfg(unix)]
impl<'a> XattrEnricher<'a> {
    pub fn new(fs: &'a dyn FileSystem) -> Self {
        Self { fs }
    }

    /// Check if an xattr name should be skipped.
    fn should_skip(name: &[u8]) -> bool {
        // Skip POSIX ACL xattrs (handled by --acls).
        if name == b"system.posix_acl_access" || name == b"system.posix_acl_default" {
            return true;
        }
        // Skip system.* namespace (requires root on Linux).
        if name.starts_with(b"system.") {
            return true;
        }
        // Skip rsync internal attributes.
        if name.starts_with(b"user.rsync.%") {
            return true;
        }
        false
    }
}

#[cfg(unix)]
impl<'a> FileListEnricher for XattrEnricher<'a> {
    fn enrich(&self, entry: &mut FileEntry, path: &Path) {
        // Symlinks don't have xattrs (lgetxattr is used but most
        // filesystems don't support xattrs on symlinks).
        if entry.is_symlink() {
            return;
        }

        let names = match self.fs.list_xattrs(path) {
            Ok(names) => names,
            Err(e) => {
                tracing::trace!(path = %path.display(), error = %e, "no xattrs");
                return;
            }
        };

        let mut xattr_entries = Vec::new();
        for name in names {
            if Self::should_skip(&name) {
                continue;
            }

            match self.fs.get_xattr(path, &name) {
                Ok(Some(value)) => {
                    // Add null terminator to name for wire format.
                    let mut wire_name = name;
                    wire_name.push(0);
                    xattr_entries.push(crate::xattr::XattrEntry {
                        name: wire_name,
                        value,
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to read xattr value"
                    );
                }
            }
        }

        // Sort by name for deterministic dedup.
        xattr_entries.sort_by(|a, b| a.name.cmp(&b.name));

        if !xattr_entries.is_empty() {
            entry.xattrs = Some(crate::xattr::ExtendedAttributes {
                entries: xattr_entries,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// HardLinkGrouper
// ---------------------------------------------------------------------------

/// Finalize enricher that groups entries by (dev, ino) for hardlink support.
///
/// All but the first occurrence in each (dev, ino) group get their
/// `hlink_source` set to the first entry's name, enabling the transfer
/// engine to defer hardlink creation.
pub struct HardLinkGrouper;

impl FileListEnricher for HardLinkGrouper {
    fn finalize(&self, items: &mut [FileListItem]) {
        let mut first_occurrence: HashMap<(u64, u64), usize> = HashMap::new();
        for i in 0..items.len() {
            if let Some(ref info) = items[i].entry.hard_link_info {
                if info.nlink > 1 {
                    let key = (info.dev, info.ino);
                    if let Some(&first_idx) = first_occurrence.get(&key) {
                        items[i].entry.hlink_source = Some(items[first_idx].entry.name.clone());
                    } else {
                        first_occurrence.insert(key, i);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FileListScanner
// ---------------------------------------------------------------------------

/// Composable file list scanner.
///
/// Walks the filesystem starting from one or more source paths, applies
/// filter rules inline during recursion, and runs enrichers on each entry.
pub struct FileListScanner<'a> {
    fs: &'a dyn FileSystem,
    options: ScanOptions,
    enrichers: Vec<Box<dyn FileListEnricher + 'a>>,
}

impl<'a> FileListScanner<'a> {
    /// Create a new scanner with the given filesystem and options.
    pub fn new(fs: &'a dyn FileSystem, options: ScanOptions) -> Self {
        Self {
            fs,
            options,
            enrichers: Vec::new(),
        }
    }

    /// Add an enricher to the pipeline.
    pub fn add_enricher(&mut self, enricher: Box<dyn FileListEnricher + 'a>) {
        self.enrichers.push(enricher);
    }

    /// Scan multiple source paths and return a unified file list.
    ///
    /// Top-level directory source paths are not filtered (matching rsync
    /// behavior where command-line sources bypass filter rules). Non-directory
    /// sources are filtered normally.
    pub fn scan(
        &self,
        source_paths: &[PathBuf],
        filters: &mut FilterRuleList,
    ) -> Result<Vec<FileListItem>, FsError> {
        let mut items = Vec::new();
        let mut index = 0i32;

        for source in source_paths {
            let meta = if self.options.copy_links {
                match self.fs.stat(source) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::warn!(path = %source.display(), "skipping broken symlink");
                        continue;
                    }
                }
            } else {
                self.fs.lstat(source)?
            };
            let name = entry::compute_entry_name(source, self.options.relative);
            let is_dir = meta.mode & S_IFMT == S_IFDIR;

            // Don't apply filter rules to top-level source arguments that
            // are directories. rsync only filters discovered children within
            // recursive scans, not the command-line source paths themselves.
            // Without this, `--exclude '*'` would skip the source directory
            // before any children are scanned.
            if !is_dir && !filters.is_included(&name, false) {
                continue;
            }

            if is_dir {
                match self.options.dir_mode {
                    DirectoryMode::Recurse => {
                        let root_dev = if self.options.one_file_system {
                            Some(meta.dev)
                        } else {
                            None
                        };
                        let prefix = if self.options.relative {
                            name.clone()
                        } else {
                            Vec::new()
                        };
                        self.collect_directory(
                            source, &prefix, &mut items, &mut index, filters, root_dev,
                        )?;
                    }
                    DirectoryMode::List => {
                        let entry = meta.to_file_entry(name);
                        items.push(FileListItem {
                            index,
                            entry,
                            source_path: source.to_path_buf(),
                        });
                        index += 1;
                    }
                    DirectoryMode::Skip => {}
                }
            } else {
                let mut entry = meta.to_file_entry(name);

                // Run per-entry enrichers.
                for enricher in &self.enrichers {
                    enricher.enrich(&mut entry, source);
                }

                items.push(FileListItem {
                    index,
                    entry,
                    source_path: source.to_path_buf(),
                });
                index += 1;
            }
        }

        // Run finalize enrichers.
        for enricher in &self.enrichers {
            enricher.finalize(&mut items);
        }

        Ok(items)
    }

    /// Scan a single directory and return `FileEntry` entries (no source paths).
    ///
    /// This is the simplified interface used by the session layers
    /// (engine/session.rs and server/session.rs) which only need `FileEntry`
    /// entries without source path tracking.
    pub fn scan_entries(
        &self,
        source_paths: &[PathBuf],
        filters: &mut FilterRuleList,
    ) -> Result<Vec<FileEntry>, FsError> {
        // For session callers, we collect FileEntry directly via a simplified path.
        let mut entries = Vec::new();

        for source in source_paths {
            let meta = if self.options.copy_links {
                match self.fs.stat(source) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::warn!(path = %source.display(), "skipping broken symlink");
                        continue;
                    }
                }
            } else {
                self.fs.lstat(source)?
            };
            let name = entry::compute_entry_name(source, self.options.relative);
            let is_dir = meta.mode & S_IFMT == S_IFDIR;

            if !is_dir && !filters.is_included(&name, is_dir) {
                continue;
            }

            if is_dir && self.options.dir_mode == DirectoryMode::Recurse {
                let prefix = if self.options.relative {
                    name.clone()
                } else {
                    Vec::new()
                };
                self.collect_directory_entries(source, &prefix, &mut entries, filters)?;
            } else if is_dir && self.options.dir_mode == DirectoryMode::List {
                entries.push(meta.to_file_entry(name));
            } else if !is_dir {
                let mut entry = meta.to_file_entry(name);
                for enricher in &self.enrichers {
                    enricher.enrich(&mut entry, source);
                }
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Scan a single directory path into `FileEntry` entries.
    ///
    /// Used by module-based callers (server/session.rs) that scan a single
    /// directory root.
    pub fn scan_directory(
        &self,
        dir_path: &Path,
        filters: &mut FilterRuleList,
    ) -> Result<Vec<FileEntry>, FsError> {
        let meta = self.fs.lstat(dir_path)?;
        let is_dir = meta.mode & S_IFMT == S_IFDIR;

        if is_dir && self.options.dir_mode == DirectoryMode::Recurse {
            let mut entries = Vec::new();
            self.collect_directory_entries(dir_path, &[], &mut entries, filters)?;
            Ok(entries)
        } else if is_dir {
            // Non-recursive: directory itself + immediate non-directory children.
            let mut entries = Vec::new();
            entries.push(meta.to_file_entry(b".".to_vec()));
            let mut children: Vec<DirEntry> = self.fs.read_dir(dir_path)?;
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for child in children {
                let is_child_dir = child.metadata.mode & S_IFMT == S_IFDIR;
                if !filters.is_included(&child.name, is_child_dir) {
                    continue;
                }
                if !is_child_dir {
                    entries.push(child.metadata.to_file_entry(child.name));
                }
            }
            Ok(entries)
        } else {
            // Single file.
            let name = dir_path
                .file_name()
                .map(|n| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::OsStrExt;
                        n.as_bytes().to_vec()
                    }
                    #[cfg(not(unix))]
                    {
                        n.to_string_lossy().as_bytes().to_vec()
                    }
                })
                .unwrap_or_default();
            Ok(vec![meta.to_file_entry(name)])
        }
    }

    // -----------------------------------------------------------------------
    // Internal: recursive directory collection (with source paths)
    // -----------------------------------------------------------------------

    fn collect_directory(
        &self,
        dir_path: &Path,
        prefix: &[u8],
        items: &mut Vec<FileListItem>,
        index: &mut i32,
        filters: &mut FilterRuleList,
        root_dev: Option<u64>,
    ) -> Result<(), FsError> {
        // Check filesystem boundary (--one-file-system).
        #[cfg(unix)]
        if let Some(dev) = root_dev {
            if let Ok(current_dev) = self.fs.device_id(dir_path) {
                if current_dev != dev {
                    return Ok(());
                }
            }
        }
        #[cfg(not(unix))]
        let _ = root_dev;

        // Add the directory itself.
        let dir_meta = if self.options.copy_links {
            self.fs.stat(dir_path)?
        } else {
            self.fs.lstat(dir_path)?
        };
        let dir_name = if prefix.is_empty() {
            b".".to_vec()
        } else {
            prefix.to_vec()
        };

        let mut dir_entry = dir_meta.to_file_entry(dir_name);
        // Run per-entry enrichers on the directory itself.
        for enricher in &self.enrichers {
            enricher.enrich(&mut dir_entry, dir_path);
        }
        items.push(FileListItem {
            index: *index,
            entry: dir_entry,
            source_path: dir_path.to_path_buf(),
        });
        *index += 1;

        // Per-directory filter merge (-F).
        let merged = self.push_filter_scope(dir_path, filters);

        let mut children: Vec<DirEntry> = self.fs.read_dir(dir_path)?;
        children.sort_by(|a, b| a.name.cmp(&b.name));

        for child in children {
            let child_name = if prefix.is_empty() {
                child.name.clone()
            } else {
                let mut n = prefix.to_vec();
                n.push(b'/');
                n.extend(&child.name);
                n
            };

            let child_path = dir_path.join(FileEntry::name_to_pathbuf(&child.name));

            let child_meta = if self.options.copy_links {
                match self.fs.stat(&child_path) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::warn!(path = %child_path.display(), "skipping broken symlink");
                        continue;
                    }
                }
            } else {
                child.metadata.clone()
            };

            let is_dir = child_meta.mode & S_IFMT == S_IFDIR;

            if !filters.is_included(&child_name, is_dir) {
                continue;
            }

            if is_dir {
                self.collect_directory(&child_path, &child_name, items, index, filters, root_dev)?;
            } else {
                let mut entry = child_meta.to_file_entry(child_name);

                // Run per-entry enrichers.
                for enricher in &self.enrichers {
                    enricher.enrich(&mut entry, &child_path);
                }

                items.push(FileListItem {
                    index: *index,
                    entry,
                    source_path: child_path,
                });
                *index += 1;
            }
        }

        if merged {
            filters.pop_scope();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: recursive directory collection (FileEntry only)
    // -----------------------------------------------------------------------

    fn collect_directory_entries(
        &self,
        dir_path: &Path,
        prefix: &[u8],
        entries: &mut Vec<FileEntry>,
        filters: &mut FilterRuleList,
    ) -> Result<(), FsError> {
        let dir_meta = if self.options.copy_links {
            self.fs.stat(dir_path)?
        } else {
            self.fs.lstat(dir_path)?
        };
        let dir_name = if prefix.is_empty() {
            b".".to_vec()
        } else {
            prefix.to_vec()
        };
        let mut dir_entry = dir_meta.to_file_entry(dir_name);
        // Run per-entry enrichers on the directory itself.
        for enricher in &self.enrichers {
            enricher.enrich(&mut dir_entry, dir_path);
        }
        entries.push(dir_entry);

        // Per-directory filter merge (-F).
        let merged = self.push_filter_scope(dir_path, filters);

        let mut children: Vec<DirEntry> = self.fs.read_dir(dir_path)?;
        children.sort_by(|a, b| a.name.cmp(&b.name));

        for child in children {
            let child_name = if prefix.is_empty() {
                child.name.clone()
            } else {
                let mut n = prefix.to_vec();
                n.push(b'/');
                n.extend(&child.name);
                n
            };

            let child_path = dir_path.join(FileEntry::name_to_pathbuf(&child.name));

            let child_meta = if self.options.copy_links {
                match self.fs.stat(&child_path) {
                    Ok(m) => m,
                    Err(_) => {
                        tracing::warn!(path = %child_path.display(), "skipping broken symlink");
                        continue;
                    }
                }
            } else {
                child.metadata.clone()
            };

            let is_dir = child_meta.mode & S_IFMT == S_IFDIR;
            if !filters.is_included(&child_name, is_dir) {
                continue;
            }

            if is_dir {
                self.collect_directory_entries(&child_path, &child_name, entries, filters)?;
            } else {
                let mut entry = child_meta.to_file_entry(child_name);

                // Run per-entry enrichers.
                for enricher in &self.enrichers {
                    enricher.enrich(&mut entry, &child_path);
                }

                entries.push(entry);
            }
        }

        if merged {
            filters.pop_scope();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: per-directory filter merge
    // -----------------------------------------------------------------------

    fn push_filter_scope(&self, dir_path: &Path, filters: &mut FilterRuleList) -> bool {
        if self.options.filter_merge_files > 0 {
            let filter_path = dir_path.join(".rsync-filter");
            if filter_path.exists() {
                filters.push_scope();
                let _ = filters.merge_filter_file(&filter_path);
                if self.options.filter_merge_files >= 2 {
                    let _ = filters.add_exclude(".rsync-filter");
                }
                return true;
            }
        }
        false
    }
}

/// Build a file list from a `--files-from` file.
///
/// Each line in the file is a relative path resolved against the first
/// source path (matching rsync behavior).
pub fn build_file_list_from_file(
    fs: &dyn FileSystem,
    source_paths: &[PathBuf],
    files_from: &Path,
    filters: &FilterRuleList,
) -> Result<Vec<FileListItem>, FsError> {
    let base = source_paths.first().ok_or_else(|| FsError::NotFound {
        path: PathBuf::from("<no source>"),
    })?;

    let content = fs.read_file(files_from)?;
    let text = String::from_utf8_lossy(&content);

    let mut items = Vec::new();
    let mut index = 0i32;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let full_path = base.join(line);
        let name = line.as_bytes().to_vec();

        if !filters.is_included(&name, false) {
            continue;
        }

        let meta = match fs.lstat(&full_path) {
            Ok(m) => m,
            Err(_) => continue, // skip missing files
        };

        items.push(FileListItem {
            index,
            entry: meta.to_file_entry(name),
            source_path: full_path,
        });
        index += 1;
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::FilterRuleList;

    #[cfg(unix)]
    fn make_fs() -> crate::fs::unix::UnixFileSystem {
        crate::fs::unix::UnixFileSystem::new()
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("hello.txt"), "hello").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Skip,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        let items = scanner
            .scan(&[tmp.path().join("hello.txt")], &mut filters)
            .unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry.name, b"hello.txt");
        assert!(items[0].entry.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_recursive_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
        std::fs::write(tmp.path().join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp.path().join("sub/b.txt"), "bbb").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Recurse,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        let items = scanner
            .scan(&[tmp.path().to_path_buf()], &mut filters)
            .unwrap();

        // Should have: "." dir, "a.txt", "sub" dir, "sub/b.txt"
        assert_eq!(items.len(), 4);
        let names: Vec<&[u8]> = items.iter().map(|i| i.entry.name.as_slice()).collect();
        assert!(names.contains(&b".".as_slice()));
        assert!(names.contains(&b"a.txt".as_slice()));
        assert!(names.contains(&b"sub".as_slice()));
        assert!(names.contains(&b"sub/b.txt".as_slice()));
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_with_filter() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("dir")).unwrap();
        std::fs::write(tmp.path().join("dir/keep.txt"), "k").unwrap();
        std::fs::write(tmp.path().join("dir/skip.tmp"), "s").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Recurse,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        filters.add_exclude("*.tmp").unwrap();
        let items = scanner
            .scan(&[tmp.path().join("dir")], &mut filters)
            .unwrap();

        let names: Vec<&[u8]> = items.iter().map(|i| i.entry.name.as_slice()).collect();
        assert!(names.contains(&b"keep.txt".as_slice()));
        assert!(!names.contains(&b"skip.tmp".as_slice()));
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_directory_not_filtered_at_top_level() {
        // Top-level directory sources bypass filter rules.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file.txt"), "x").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Recurse,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        filters.add_exclude("*").unwrap();
        let items = scanner
            .scan(&[tmp.path().to_path_buf()], &mut filters)
            .unwrap();

        // The directory itself should be included (bypasses filter),
        // but children should be excluded.
        assert_eq!(items.len(), 1);
        assert!(items[0].entry.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_entries() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file.txt"), "data").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Recurse,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        let entries = scanner
            .scan_entries(&[tmp.path().to_path_buf()], &mut filters)
            .unwrap();

        assert_eq!(entries.len(), 2); // "." + "file.txt"
        assert!(entries[0].is_dir());
        assert!(entries[1].is_file());
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_directory_module() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "b").unwrap();

        let fs = make_fs();
        let opts = ScanOptions {
            dir_mode: DirectoryMode::Recurse,
            ..Default::default()
        };
        let scanner = FileListScanner::new(&fs, opts);
        let mut filters = FilterRuleList::new();
        let entries = scanner.scan_directory(tmp.path(), &mut filters).unwrap();

        assert_eq!(entries.len(), 3); // "." + "a.txt" + "b.txt"
    }

    #[cfg(unix)]
    #[test]
    fn test_hardlink_grouper() {
        let mut items = vec![
            FileListItem {
                index: 0,
                entry: FileEntry {
                    name: b"first".to_vec(),
                    hard_link_info: Some(crate::filelist::codec::HardLinkInfo {
                        dev: 1,
                        ino: 100,
                        nlink: 2,
                    }),
                    ..Default::default()
                },
                source_path: PathBuf::from("/a"),
            },
            FileListItem {
                index: 1,
                entry: FileEntry {
                    name: b"second".to_vec(),
                    hard_link_info: Some(crate::filelist::codec::HardLinkInfo {
                        dev: 1,
                        ino: 100,
                        nlink: 2,
                    }),
                    ..Default::default()
                },
                source_path: PathBuf::from("/b"),
            },
        ];

        let grouper = HardLinkGrouper;
        grouper.finalize(&mut items);

        assert!(items[0].entry.hlink_source.is_none());
        assert_eq!(
            items[1].entry.hlink_source.as_deref(),
            Some(b"first".as_slice())
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_enricher() {
        let tmp = tempfile::tempdir().unwrap();
        let link_path = tmp.path().join("link");
        std::os::unix::fs::symlink("target", &link_path).unwrap();

        let fs = make_fs();
        let enricher = SymlinkEnricher::new(&fs);

        let meta = fs.lstat(&link_path).unwrap();
        let mut entry = meta.to_file_entry(b"link".to_vec());
        assert!(entry.is_symlink());
        assert!(entry.link_target.is_empty());

        enricher.enrich(&mut entry, &link_path);
        assert_eq!(entry.link_target, b"target");
    }

    #[cfg(unix)]
    #[test]
    fn test_build_file_list_from_file() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("a.txt"), "a").unwrap();
        std::fs::write(base.join("b.txt"), "b").unwrap();

        let files_from = tmp.path().join("files.txt");
        std::fs::write(&files_from, "a.txt\nb.txt\nmissing.txt\n").unwrap();

        let fs = make_fs();
        let filters = FilterRuleList::new();
        let items =
            build_file_list_from_file(&fs, std::slice::from_ref(&base), &files_from, &filters)
                .unwrap();

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].entry.name, b"a.txt");
        assert_eq!(items[1].entry.name, b"b.txt");
    }
}
