//! Transfer options builder.
//!
//! Maps to rsync's command-line flags. The builder pattern allows
//! constructing options incrementally, with sensible defaults.

use std::path::PathBuf;

/// Delete mode for `--delete` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeleteMode {
    /// No deletion of extraneous files.
    #[default]
    None,
    /// Delete before transfer (`--delete-before`).
    Before,
    /// Delete during transfer (`--delete-during`, the default for `--delete`).
    During,
    /// Delete after transfer (`--delete-after`).
    After,
    /// Delete excluded files too (`--delete-excluded`).
    Excluded,
}

/// Verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Verbosity {
    /// Quiet (`-q`).
    Quiet,
    /// Normal (no flag).
    #[default]
    Normal,
    /// Verbose (`-v`).
    Verbose,
    /// Very verbose (`-vv`).
    VeryVerbose,
    /// Debug (`-vvv`).
    Debug,
}

/// Transfer options controlling rsync behavior.
///
/// Construct via [`TransferOptions::builder()`].
#[derive(Debug, Clone)]
pub struct TransferOptions {
    // --- Archive mode components ---
    /// Recurse into directories (`-r`).
    pub recursive: bool,
    /// Preserve symlinks as symlinks (`-l`).
    pub preserve_links: bool,
    /// Preserve permissions (`-p`).
    pub preserve_perms: bool,
    /// Preserve modification times (`-t`).
    pub preserve_times: bool,
    /// Preserve group (`-g`).
    pub preserve_group: bool,
    /// Preserve owner (`-o`, requires root).
    pub preserve_owner: bool,
    /// Preserve device files (`-D` component).
    pub preserve_devices: bool,
    /// Preserve special files (`-D` component).
    pub preserve_specials: bool,

    // --- Transfer behavior ---
    /// Use checksums for change detection instead of size+mtime (`-c`).
    pub checksum_mode: bool,
    /// Whole-file transfer, skip delta algorithm (`--whole-file`).
    pub whole_file: bool,
    /// Update only: skip files newer on receiver (`-u`).
    pub update: bool,
    /// In-place file updates (`--inplace`).
    pub inplace: bool,

    // --- Delete ---
    /// How to handle extraneous files on the receiver.
    pub delete: DeleteMode,

    // --- Compression ---
    /// Enable compression (`-z`).
    pub compress: bool,
    /// Compression level (1-9, default 6).
    pub compress_level: u32,

    // --- Output ---
    /// Verbosity level.
    pub verbosity: Verbosity,
    /// Show per-file transfer progress (`--progress`).
    pub progress: bool,
    /// Print transfer statistics at end (`--stats`).
    pub stats: bool,
    /// Dry run: show what would be transferred (`-n`).
    pub dry_run: bool,
    /// Itemize changes (`-i` / `--itemize-changes`).
    pub itemize_changes: bool,

    // --- Filtering ---
    /// Exclude patterns (`--exclude`).
    pub exclude: Vec<String>,
    /// Include patterns (`--include`).
    pub include: Vec<String>,
    /// Filter rules (`--filter` / `-f`).
    pub filter: Vec<String>,

    // --- Paths ---
    /// Source path(s).
    pub source: Vec<PathBuf>,
    /// Destination path.
    pub dest: Option<PathBuf>,

    // --- Limits ---
    /// Bandwidth limit in bytes/sec (`--bwlimit`).
    pub bwlimit: Option<u64>,
    /// Maximum file size to transfer (`--max-size`).
    pub max_size: Option<u64>,
    /// Minimum file size to transfer (`--min-size`).
    pub min_size: Option<u64>,
    /// Timeout in seconds (`--timeout`).
    pub timeout: Option<u64>,

    // --- Misc ---
    /// Don't cross filesystem boundaries (`-x` / `--one-file-system`).
    pub one_file_system: bool,
    /// Use numeric uid/gid instead of names (`--numeric-ids`).
    pub numeric_ids: bool,
    /// Sparse file handling (`--sparse`).
    pub sparse: bool,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            preserve_links: false,
            preserve_perms: false,
            preserve_times: false,
            preserve_group: false,
            preserve_owner: false,
            preserve_devices: false,
            preserve_specials: false,
            checksum_mode: false,
            whole_file: false,
            update: false,
            inplace: false,
            delete: DeleteMode::None,
            compress: false,
            compress_level: 6,
            verbosity: Verbosity::Normal,
            progress: false,
            stats: false,
            dry_run: false,
            itemize_changes: false,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
            source: Vec::new(),
            dest: None,
            bwlimit: None,
            max_size: None,
            min_size: None,
            timeout: None,
            one_file_system: false,
            numeric_ids: false,
            sparse: false,
        }
    }
}

impl TransferOptions {
    /// Create a new builder for transfer options.
    pub fn builder() -> TransferOptionsBuilder {
        TransferOptionsBuilder::default()
    }

    /// Returns `true` if archive mode flags are all set (`-a` = `-rlptgoD`).
    pub fn is_archive(&self) -> bool {
        self.recursive
            && self.preserve_links
            && self.preserve_perms
            && self.preserve_times
            && self.preserve_group
            && self.preserve_owner
            && self.preserve_devices
            && self.preserve_specials
    }
}

/// Builder for [`TransferOptions`].
#[derive(Debug, Default)]
pub struct TransferOptionsBuilder {
    opts: TransferOptions,
}

impl TransferOptionsBuilder {
    /// Enable archive mode (`-a` = `-rlptgoD`).
    pub fn archive(mut self) -> Self {
        self.opts.recursive = true;
        self.opts.preserve_links = true;
        self.opts.preserve_perms = true;
        self.opts.preserve_times = true;
        self.opts.preserve_group = true;
        self.opts.preserve_owner = true;
        self.opts.preserve_devices = true;
        self.opts.preserve_specials = true;
        self
    }

    pub fn recursive(mut self, v: bool) -> Self {
        self.opts.recursive = v;
        self
    }

    pub fn preserve_links(mut self, v: bool) -> Self {
        self.opts.preserve_links = v;
        self
    }

    pub fn preserve_perms(mut self, v: bool) -> Self {
        self.opts.preserve_perms = v;
        self
    }

    pub fn preserve_times(mut self, v: bool) -> Self {
        self.opts.preserve_times = v;
        self
    }

    pub fn preserve_group(mut self, v: bool) -> Self {
        self.opts.preserve_group = v;
        self
    }

    pub fn preserve_owner(mut self, v: bool) -> Self {
        self.opts.preserve_owner = v;
        self
    }

    pub fn preserve_devices(mut self, v: bool) -> Self {
        self.opts.preserve_devices = v;
        self
    }

    pub fn preserve_specials(mut self, v: bool) -> Self {
        self.opts.preserve_specials = v;
        self
    }

    pub fn checksum_mode(mut self, v: bool) -> Self {
        self.opts.checksum_mode = v;
        self
    }

    pub fn whole_file(mut self, v: bool) -> Self {
        self.opts.whole_file = v;
        self
    }

    pub fn update(mut self, v: bool) -> Self {
        self.opts.update = v;
        self
    }

    pub fn inplace(mut self, v: bool) -> Self {
        self.opts.inplace = v;
        self
    }

    pub fn delete(mut self, mode: DeleteMode) -> Self {
        self.opts.delete = mode;
        self
    }

    pub fn compress(mut self, v: bool) -> Self {
        self.opts.compress = v;
        self
    }

    pub fn compress_level(mut self, level: u32) -> Self {
        self.opts.compress_level = level.clamp(1, 9);
        self
    }

    pub fn verbosity(mut self, v: Verbosity) -> Self {
        self.opts.verbosity = v;
        self
    }

    pub fn progress(mut self, v: bool) -> Self {
        self.opts.progress = v;
        self
    }

    pub fn stats(mut self, v: bool) -> Self {
        self.opts.stats = v;
        self
    }

    pub fn dry_run(mut self, v: bool) -> Self {
        self.opts.dry_run = v;
        self
    }

    pub fn itemize_changes(mut self, v: bool) -> Self {
        self.opts.itemize_changes = v;
        self
    }

    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.opts.exclude.push(pattern.into());
        self
    }

    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.opts.include.push(pattern.into());
        self
    }

    pub fn filter(mut self, rule: impl Into<String>) -> Self {
        self.opts.filter.push(rule.into());
        self
    }

    pub fn source(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.source.push(path.into());
        self
    }

    pub fn dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.dest = Some(path.into());
        self
    }

    pub fn bwlimit(mut self, bytes_per_sec: u64) -> Self {
        self.opts.bwlimit = Some(bytes_per_sec);
        self
    }

    pub fn max_size(mut self, bytes: u64) -> Self {
        self.opts.max_size = Some(bytes);
        self
    }

    pub fn min_size(mut self, bytes: u64) -> Self {
        self.opts.min_size = Some(bytes);
        self
    }

    pub fn timeout(mut self, seconds: u64) -> Self {
        self.opts.timeout = Some(seconds);
        self
    }

    pub fn one_file_system(mut self, v: bool) -> Self {
        self.opts.one_file_system = v;
        self
    }

    pub fn numeric_ids(mut self, v: bool) -> Self {
        self.opts.numeric_ids = v;
        self
    }

    pub fn sparse(mut self, v: bool) -> Self {
        self.opts.sparse = v;
        self
    }

    /// Build the [`TransferOptions`].
    pub fn build(self) -> TransferOptions {
        self.opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = TransferOptions::default();
        assert!(!opts.recursive);
        assert!(!opts.compress);
        assert!(!opts.dry_run);
        assert_eq!(opts.delete, DeleteMode::None);
        assert_eq!(opts.verbosity, Verbosity::Normal);
        assert!(!opts.is_archive());
    }

    #[test]
    fn test_archive_mode() {
        let opts = TransferOptions::builder().archive().build();
        assert!(opts.is_archive());
        assert!(opts.recursive);
        assert!(opts.preserve_links);
        assert!(opts.preserve_perms);
        assert!(opts.preserve_times);
        assert!(opts.preserve_group);
        assert!(opts.preserve_owner);
        assert!(opts.preserve_devices);
        assert!(opts.preserve_specials);
    }

    #[test]
    fn test_builder_chaining() {
        let opts = TransferOptions::builder()
            .recursive(true)
            .compress(true)
            .compress_level(3)
            .delete(DeleteMode::During)
            .dry_run(true)
            .verbosity(Verbosity::Verbose)
            .exclude("*.tmp")
            .exclude("*.log")
            .source("/src")
            .dest("/dst")
            .build();

        assert!(opts.recursive);
        assert!(opts.compress);
        assert_eq!(opts.compress_level, 3);
        assert_eq!(opts.delete, DeleteMode::During);
        assert!(opts.dry_run);
        assert_eq!(opts.verbosity, Verbosity::Verbose);
        assert_eq!(opts.exclude, vec!["*.tmp", "*.log"]);
        assert_eq!(opts.source, vec![PathBuf::from("/src")]);
        assert_eq!(opts.dest, Some(PathBuf::from("/dst")));
    }

    #[test]
    fn test_compress_level_clamped() {
        let opts = TransferOptions::builder().compress_level(99).build();
        assert_eq!(opts.compress_level, 9);

        let opts = TransferOptions::builder().compress_level(0).build();
        assert_eq!(opts.compress_level, 1);
    }
}
