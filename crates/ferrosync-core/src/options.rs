//! Transfer options builder.
//!
//! Maps to rsync's command-line flags. The builder pattern allows
//! constructing options incrementally, with sensible defaults.
//! All fields are private; use the builder or getter methods.

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

/// Directory traversal mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectoryMode {
    /// Neither `-d` nor `-r`: directories in source list are skipped.
    #[default]
    Skip,
    /// `-d`: include directory entries but don't recurse into them.
    List,
    /// `-r`: full recursive traversal.
    Recurse,
}

/// Transfer options controlling rsync behavior.
///
/// Construct via [`TransferOptions::builder()`]. Access fields via getter methods.
#[derive(Debug, Clone)]
pub struct TransferOptions {
    // --- Archive mode components ---
    dir_mode: DirectoryMode,
    preserve_links: bool,
    preserve_perms: bool,
    preserve_times: bool,
    preserve_group: bool,
    preserve_owner: bool,
    preserve_devices: bool,
    preserve_specials: bool,

    // --- Transfer behavior ---
    checksum_mode: bool,
    whole_file: bool,
    update: bool,
    inplace: bool,

    // --- Delete ---
    delete: DeleteMode,

    // --- Compression ---
    compress: bool,
    compress_level: u32,

    // --- Output ---
    verbosity: Verbosity,
    progress: bool,
    stats: bool,
    dry_run: bool,
    itemize_changes: bool,

    // --- Filtering ---
    exclude: Vec<String>,
    include: Vec<String>,
    filter: Vec<String>,

    // --- Paths ---
    source: Vec<PathBuf>,
    dest: Option<PathBuf>,

    // --- Limits ---
    bwlimit: Option<u64>,
    max_size: Option<u64>,
    min_size: Option<u64>,
    timeout: Option<u64>,

    // --- Basis directories ---
    link_dest: Vec<PathBuf>,
    copy_dest: Vec<PathBuf>,
    compare_dest: Vec<PathBuf>,

    // --- Backup ---
    backup: bool,
    backup_dir: Option<PathBuf>,
    suffix: String,

    // --- Partial ---
    partial: bool,
    partial_dir: Option<PathBuf>,

    // --- Append ---
    append: bool,

    // --- Files-from ---
    files_from: Option<PathBuf>,

    // --- Concurrency ---
    concurrent: usize,

    // --- Skip behavior ---
    ignore_times: bool,
    size_only: bool,
    existing: bool,
    ignore_existing: bool,

    // --- Delete limits ---
    max_delete: Option<u64>,

    // --- Post-transfer ---
    prune_empty_dirs: bool,

    // --- Symlink behavior ---
    copy_links: bool,
    safe_links: bool,
    keep_dirlinks: bool,

    // --- Source cleanup ---
    remove_source_files: bool,

    // --- Timestamp comparison ---
    modify_window: u32,

    // --- Append verification ---
    append_verify: bool,

    // --- Filter files ---
    exclude_from: Vec<PathBuf>,
    include_from: Vec<PathBuf>,
    cvs_exclude: bool,

    // --- Delta tuning ---
    block_size: Option<i32>,

    // --- Permission/ownership override ---
    chmod: Vec<String>,
    chown_uid: Option<u32>,
    chown_gid: Option<u32>,

    // --- Path handling ---
    relative: bool,

    // --- Filter merge ---
    filter_merge_files: u8,

    // --- Output ---
    list_only: bool,

    // --- Basis search ---
    fuzzy: bool,

    // --- Misc ---
    one_file_system: bool,
    numeric_ids: bool,
    sparse: bool,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            dir_mode: DirectoryMode::Skip,
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
            link_dest: Vec::new(),
            copy_dest: Vec::new(),
            compare_dest: Vec::new(),
            backup: false,
            backup_dir: None,
            suffix: "~".to_string(),
            partial: false,
            partial_dir: None,
            append: false,
            files_from: None,
            concurrent: 1,
            ignore_times: false,
            size_only: false,
            existing: false,
            ignore_existing: false,
            max_delete: None,
            prune_empty_dirs: false,
            copy_links: false,
            safe_links: false,
            keep_dirlinks: false,
            remove_source_files: false,
            modify_window: 0,
            append_verify: false,
            exclude_from: Vec::new(),
            include_from: Vec::new(),
            cvs_exclude: false,
            block_size: None,
            chmod: Vec::new(),
            chown_uid: None,
            chown_gid: None,
            relative: false,
            filter_merge_files: 0,
            list_only: false,
            fuzzy: false,
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
        self.dir_mode == DirectoryMode::Recurse
            && self.preserve_links
            && self.preserve_perms
            && self.preserve_times
            && self.preserve_group
            && self.preserve_owner
            && self.preserve_devices
            && self.preserve_specials
    }

    // --- Getter methods ---

    /// Recurse into directories (`-r`).
    pub fn recursive(&self) -> bool {
        self.dir_mode == DirectoryMode::Recurse
    }
    /// Transfer directories without recursing (`-d`).
    pub fn dirs(&self) -> bool {
        self.dir_mode == DirectoryMode::List
    }
    /// Directory traversal mode.
    pub fn dir_mode(&self) -> DirectoryMode {
        self.dir_mode
    }
    /// Preserve symlinks as symlinks (`-l`).
    pub fn preserve_links(&self) -> bool {
        self.preserve_links
    }
    /// Preserve permissions (`-p`).
    pub fn preserve_perms(&self) -> bool {
        self.preserve_perms
    }
    /// Preserve modification times (`-t`).
    pub fn preserve_times(&self) -> bool {
        self.preserve_times
    }
    /// Preserve group (`-g`).
    pub fn preserve_group(&self) -> bool {
        self.preserve_group
    }
    /// Preserve owner (`-o`, requires root).
    pub fn preserve_owner(&self) -> bool {
        self.preserve_owner
    }
    /// Preserve device files (`-D` component).
    pub fn preserve_devices(&self) -> bool {
        self.preserve_devices
    }
    /// Preserve special files (`-D` component).
    pub fn preserve_specials(&self) -> bool {
        self.preserve_specials
    }
    /// Use checksums for change detection (`-c`).
    pub fn checksum_mode(&self) -> bool {
        self.checksum_mode
    }
    /// Whole-file transfer (`--whole-file`).
    pub fn whole_file(&self) -> bool {
        self.whole_file
    }
    /// Update only: skip files newer on receiver (`-u`).
    pub fn update(&self) -> bool {
        self.update
    }
    /// In-place file updates (`--inplace`).
    pub fn inplace(&self) -> bool {
        self.inplace
    }
    /// How to handle extraneous files on the receiver.
    pub fn delete(&self) -> DeleteMode {
        self.delete
    }
    /// Whether compression is enabled (`-z`).
    pub fn compress(&self) -> bool {
        self.compress
    }
    /// Compression level (1-9).
    pub fn compress_level(&self) -> u32 {
        self.compress_level
    }
    /// Current verbosity level.
    pub fn verbosity(&self) -> Verbosity {
        self.verbosity
    }
    /// Whether per-file transfer progress is enabled (`--progress`).
    pub fn progress(&self) -> bool {
        self.progress
    }
    /// Whether transfer statistics are printed at end (`--stats`).
    pub fn stats(&self) -> bool {
        self.stats
    }
    /// Dry run mode (`-n`).
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }
    /// Whether itemized changes are enabled (`-i`).
    pub fn itemize_changes(&self) -> bool {
        self.itemize_changes
    }
    /// Exclude patterns (`--exclude`).
    pub fn exclude(&self) -> &[String] {
        &self.exclude
    }
    /// Include patterns (`--include`).
    pub fn include(&self) -> &[String] {
        &self.include
    }
    /// Filter rules (`--filter`).
    pub fn filter(&self) -> &[String] {
        &self.filter
    }
    /// Source path(s).
    pub fn source(&self) -> &[PathBuf] {
        &self.source
    }
    /// Destination path.
    pub fn dest(&self) -> Option<&PathBuf> {
        self.dest.as_ref()
    }
    /// Bandwidth limit in bytes/sec.
    pub fn bwlimit(&self) -> Option<u64> {
        self.bwlimit
    }
    /// Maximum file size to transfer.
    pub fn max_size(&self) -> Option<u64> {
        self.max_size
    }
    /// Minimum file size to transfer.
    pub fn min_size(&self) -> Option<u64> {
        self.min_size
    }
    /// Timeout in seconds.
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }
    /// Hard-link basis directories (`--link-dest`).
    pub fn link_dest(&self) -> &[PathBuf] {
        &self.link_dest
    }
    /// Copy basis directories (`--copy-dest`).
    pub fn copy_dest(&self) -> &[PathBuf] {
        &self.copy_dest
    }
    /// Compare basis directories (`--compare-dest`).
    pub fn compare_dest(&self) -> &[PathBuf] {
        &self.compare_dest
    }
    /// Whether backup is enabled (`-b`).
    pub fn backup(&self) -> bool {
        self.backup
    }
    /// Backup directory path.
    pub fn backup_dir(&self) -> Option<&PathBuf> {
        self.backup_dir.as_ref()
    }
    /// Suffix for backup files.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
    /// Keep partial files on interruption (`--partial`).
    pub fn partial(&self) -> bool {
        self.partial
    }
    /// Partial transfer directory.
    pub fn partial_dir(&self) -> Option<&PathBuf> {
        self.partial_dir.as_ref()
    }
    /// Append mode (`--append`).
    pub fn append(&self) -> bool {
        self.append
    }
    /// Files-from path.
    pub fn files_from(&self) -> Option<&PathBuf> {
        self.files_from.as_ref()
    }
    /// Never skip based on mtime, always transfer (`-I`).
    pub fn ignore_times(&self) -> bool {
        self.ignore_times
    }
    /// Skip if sizes match, ignore mtime (`--size-only`).
    pub fn size_only(&self) -> bool {
        self.size_only
    }
    /// Only update files that already exist on dest (`--existing`).
    pub fn existing(&self) -> bool {
        self.existing
    }
    /// Don't update files that exist on dest (`--ignore-existing`).
    pub fn ignore_existing(&self) -> bool {
        self.ignore_existing
    }
    /// Cap number of deletions (`--max-delete=N`).
    pub fn max_delete(&self) -> Option<u64> {
        self.max_delete
    }
    /// Remove empty dirs after transfer (`-m`).
    pub fn prune_empty_dirs(&self) -> bool {
        self.prune_empty_dirs
    }
    /// Follow symlinks during file list building (`-L`).
    pub fn copy_links(&self) -> bool {
        self.copy_links
    }
    /// Skip symlinks that point outside the destination tree (`--safe-links`).
    pub fn safe_links(&self) -> bool {
        self.safe_links
    }
    /// Keep symlinks to directories on receiver (`-K`).
    pub fn keep_dirlinks(&self) -> bool {
        self.keep_dirlinks
    }
    /// Delete source files after successful transfer (`--remove-source-files`).
    pub fn remove_source_files(&self) -> bool {
        self.remove_source_files
    }
    /// Timestamp comparison fuzz in seconds (`-@`).
    pub fn modify_window(&self) -> u32 {
        self.modify_window
    }
    /// Append mode with post-transfer checksum verification (`--append-verify`).
    pub fn append_verify(&self) -> bool {
        self.append_verify
    }
    /// Files containing exclude patterns (`--exclude-from`).
    pub fn exclude_from(&self) -> &[PathBuf] {
        &self.exclude_from
    }
    /// Files containing include patterns (`--include-from`).
    pub fn include_from(&self) -> &[PathBuf] {
        &self.include_from
    }
    /// Auto-exclude VCS artifacts (`-C`).
    pub fn cvs_exclude(&self) -> bool {
        self.cvs_exclude
    }
    /// Override automatic block size for delta checksums (`-B`).
    pub fn block_size(&self) -> Option<i32> {
        self.block_size
    }
    /// Permission override specs (`--chmod`).
    pub fn chmod(&self) -> &[String] {
        &self.chmod
    }
    /// Override owner uid (`--chown`).
    pub fn chown_uid(&self) -> Option<u32> {
        self.chown_uid
    }
    /// Override owner gid (`--chown`).
    pub fn chown_gid(&self) -> Option<u32> {
        self.chown_gid
    }
    /// Preserve full source path at destination (`-R`).
    pub fn relative(&self) -> bool {
        self.relative
    }
    /// Per-directory .rsync-filter merge file level (`-F`).
    pub fn filter_merge_files(&self) -> u8 {
        self.filter_merge_files
    }
    /// List files without transferring (`--list-only`).
    pub fn list_only(&self) -> bool {
        self.list_only
    }
    /// Search for similar basis files for delta (`-y`).
    pub fn fuzzy(&self) -> bool {
        self.fuzzy
    }
    /// Don't cross filesystem boundaries (`-x`).
    pub fn one_file_system(&self) -> bool {
        self.one_file_system
    }
    /// Use numeric uid/gid (`--numeric-ids`).
    pub fn numeric_ids(&self) -> bool {
        self.numeric_ids
    }
    /// Sparse file handling (`--sparse`).
    pub fn sparse(&self) -> bool {
        self.sparse
    }
    /// Number of concurrent file transfers (`--concurrent`).
    pub fn concurrent(&self) -> usize {
        self.concurrent
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
        self.opts.dir_mode = DirectoryMode::Recurse;
        self.opts.preserve_links = true;
        self.opts.preserve_perms = true;
        self.opts.preserve_times = true;
        self.opts.preserve_group = true;
        self.opts.preserve_owner = true;
        self.opts.preserve_devices = true;
        self.opts.preserve_specials = true;
        self
    }

    /// Enable or disable recursive directory traversal (`-r`).
    pub fn recursive(mut self, v: bool) -> Self {
        self.opts.dir_mode = if v {
            DirectoryMode::Recurse
        } else {
            DirectoryMode::Skip
        };
        self
    }

    /// Enable or disable directory listing without recursion (`-d`).
    pub fn dirs(mut self, v: bool) -> Self {
        if v {
            self.opts.dir_mode = DirectoryMode::List;
        }
        self
    }

    /// Enable or disable symlink preservation (`-l`).
    pub fn preserve_links(mut self, v: bool) -> Self {
        self.opts.preserve_links = v;
        self
    }

    /// Enable or disable permission preservation (`-p`).
    pub fn preserve_perms(mut self, v: bool) -> Self {
        self.opts.preserve_perms = v;
        self
    }

    /// Enable or disable modification time preservation (`-t`).
    pub fn preserve_times(mut self, v: bool) -> Self {
        self.opts.preserve_times = v;
        self
    }

    /// Enable or disable group preservation (`-g`).
    pub fn preserve_group(mut self, v: bool) -> Self {
        self.opts.preserve_group = v;
        self
    }

    /// Enable or disable owner preservation (`-o`).
    pub fn preserve_owner(mut self, v: bool) -> Self {
        self.opts.preserve_owner = v;
        self
    }

    /// Enable or disable device file preservation (`-D` component).
    pub fn preserve_devices(mut self, v: bool) -> Self {
        self.opts.preserve_devices = v;
        self
    }

    /// Enable or disable special file preservation (`-D` component).
    pub fn preserve_specials(mut self, v: bool) -> Self {
        self.opts.preserve_specials = v;
        self
    }

    /// Enable or disable checksum-based change detection (`-c`).
    pub fn checksum_mode(mut self, v: bool) -> Self {
        self.opts.checksum_mode = v;
        self
    }

    /// Enable or disable whole-file transfer (`--whole-file`).
    pub fn whole_file(mut self, v: bool) -> Self {
        self.opts.whole_file = v;
        self
    }

    /// Enable or disable update-only mode (`-u`).
    pub fn update(mut self, v: bool) -> Self {
        self.opts.update = v;
        self
    }

    /// Enable or disable in-place file updates (`--inplace`).
    pub fn inplace(mut self, v: bool) -> Self {
        self.opts.inplace = v;
        self
    }

    /// Set the delete mode for extraneous files on the receiver.
    pub fn delete(mut self, mode: DeleteMode) -> Self {
        self.opts.delete = mode;
        self
    }

    /// Enable or disable compression (`-z`).
    pub fn compress(mut self, v: bool) -> Self {
        self.opts.compress = v;
        self
    }

    /// Set the compression level (clamped to 1-9).
    pub fn compress_level(mut self, level: u32) -> Self {
        self.opts.compress_level = level.clamp(1, 9);
        self
    }

    /// Set the verbosity level.
    pub fn verbosity(mut self, v: Verbosity) -> Self {
        self.opts.verbosity = v;
        self
    }

    /// Enable or disable per-file transfer progress (`--progress`).
    pub fn progress(mut self, v: bool) -> Self {
        self.opts.progress = v;
        self
    }

    /// Enable or disable transfer statistics at end (`--stats`).
    pub fn stats(mut self, v: bool) -> Self {
        self.opts.stats = v;
        self
    }

    /// Enable or disable dry run mode (`-n`).
    pub fn dry_run(mut self, v: bool) -> Self {
        self.opts.dry_run = v;
        self
    }

    /// Enable or disable itemized changes output (`-i`).
    pub fn itemize_changes(mut self, v: bool) -> Self {
        self.opts.itemize_changes = v;
        self
    }

    /// Add an exclude pattern (`--exclude`).
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.opts.exclude.push(pattern.into());
        self
    }

    /// Add an include pattern (`--include`).
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.opts.include.push(pattern.into());
        self
    }

    /// Add a filter rule (`--filter`).
    pub fn filter(mut self, rule: impl Into<String>) -> Self {
        self.opts.filter.push(rule.into());
        self
    }

    /// Add a source path.
    pub fn source(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.source.push(path.into());
        self
    }

    /// Set the destination path.
    pub fn dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.dest = Some(path.into());
        self
    }

    /// Set the bandwidth limit in bytes per second (`--bwlimit`).
    pub fn bwlimit(mut self, bytes_per_sec: u64) -> Self {
        self.opts.bwlimit = Some(bytes_per_sec);
        self
    }

    /// Set the maximum file size to transfer (`--max-size`).
    pub fn max_size(mut self, bytes: u64) -> Self {
        self.opts.max_size = Some(bytes);
        self
    }

    /// Set the minimum file size to transfer (`--min-size`).
    pub fn min_size(mut self, bytes: u64) -> Self {
        self.opts.min_size = Some(bytes);
        self
    }

    /// Set the I/O timeout in seconds (`--timeout`).
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.opts.timeout = Some(seconds);
        self
    }

    /// Enable or disable ignore-times mode (`-I`).
    pub fn ignore_times(mut self, v: bool) -> Self {
        self.opts.ignore_times = v;
        self
    }

    /// Enable or disable size-only mode (`--size-only`).
    pub fn size_only(mut self, v: bool) -> Self {
        self.opts.size_only = v;
        self
    }

    /// Enable or disable existing mode (`--existing`).
    pub fn existing(mut self, v: bool) -> Self {
        self.opts.existing = v;
        self
    }

    /// Enable or disable ignore-existing mode (`--ignore-existing`).
    pub fn ignore_existing(mut self, v: bool) -> Self {
        self.opts.ignore_existing = v;
        self
    }

    /// Set the maximum number of deletions (`--max-delete`).
    pub fn max_delete(mut self, n: u64) -> Self {
        self.opts.max_delete = Some(n);
        self
    }

    /// Enable or disable empty directory pruning (`-m`).
    pub fn prune_empty_dirs(mut self, v: bool) -> Self {
        self.opts.prune_empty_dirs = v;
        self
    }

    /// Enable or disable following symlinks during scan (`-L`).
    pub fn copy_links(mut self, v: bool) -> Self {
        self.opts.copy_links = v;
        self
    }

    /// Enable or disable safe-links mode (`--safe-links`).
    pub fn safe_links(mut self, v: bool) -> Self {
        self.opts.safe_links = v;
        self
    }

    /// Enable or disable keeping dir symlinks on receiver (`-K`).
    pub fn keep_dirlinks(mut self, v: bool) -> Self {
        self.opts.keep_dirlinks = v;
        self
    }

    /// Enable or disable source file deletion after transfer (`--remove-source-files`).
    pub fn remove_source_files(mut self, v: bool) -> Self {
        self.opts.remove_source_files = v;
        self
    }

    /// Set the timestamp comparison fuzz in seconds (`-@`).
    pub fn modify_window(mut self, n: u32) -> Self {
        self.opts.modify_window = n;
        self
    }

    /// Enable or disable append-verify mode (`--append-verify`).
    pub fn append_verify(mut self, v: bool) -> Self {
        self.opts.append_verify = v;
        self
    }

    /// Add a file containing exclude patterns (`--exclude-from`).
    pub fn exclude_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.exclude_from.push(path.into());
        self
    }

    /// Add a file containing include patterns (`--include-from`).
    pub fn include_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.include_from.push(path.into());
        self
    }

    /// Enable or disable CVS exclude patterns (`-C`).
    pub fn cvs_exclude(mut self, v: bool) -> Self {
        self.opts.cvs_exclude = v;
        self
    }

    /// Set the delta checksum block size (`-B`).
    pub fn block_size(mut self, n: i32) -> Self {
        self.opts.block_size = Some(n);
        self
    }

    /// Add a permission override spec (`--chmod`).
    pub fn chmod(mut self, spec: impl Into<String>) -> Self {
        self.opts.chmod.push(spec.into());
        self
    }

    /// Set the owner uid override (`--chown`).
    pub fn chown_uid(mut self, uid: u32) -> Self {
        self.opts.chown_uid = Some(uid);
        self
    }

    /// Set the owner gid override (`--chown`).
    pub fn chown_gid(mut self, gid: u32) -> Self {
        self.opts.chown_gid = Some(gid);
        self
    }

    /// Enable or disable relative path preservation (`-R`).
    pub fn relative(mut self, v: bool) -> Self {
        self.opts.relative = v;
        self
    }

    /// Set per-directory filter merge file level (`-F`).
    pub fn filter_merge_files(mut self, n: u8) -> Self {
        self.opts.filter_merge_files = n;
        self
    }

    /// Enable or disable list-only mode (`--list-only`).
    pub fn list_only(mut self, v: bool) -> Self {
        self.opts.list_only = v;
        self
    }

    /// Enable or disable fuzzy basis search (`-y`).
    pub fn fuzzy(mut self, v: bool) -> Self {
        self.opts.fuzzy = v;
        self
    }

    /// Enable or disable single-filesystem mode (`-x`).
    pub fn one_file_system(mut self, v: bool) -> Self {
        self.opts.one_file_system = v;
        self
    }

    /// Enable or disable numeric uid/gid (`--numeric-ids`).
    pub fn numeric_ids(mut self, v: bool) -> Self {
        self.opts.numeric_ids = v;
        self
    }

    /// Enable or disable sparse file handling (`--sparse`).
    pub fn sparse(mut self, v: bool) -> Self {
        self.opts.sparse = v;
        self
    }

    /// Set the number of concurrent file transfers (`--concurrent` / `-j`).
    ///
    /// Clamped to the range 1..=64. A value of 1 (the default) processes
    /// files sequentially, matching traditional rsync behavior.
    pub fn concurrent(mut self, n: usize) -> Self {
        self.opts.concurrent = n.clamp(1, 64);
        self
    }

    /// Add a hard-link basis directory (`--link-dest`).
    pub fn link_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.link_dest.push(path.into());
        self
    }

    /// Add a copy basis directory (`--copy-dest`).
    pub fn copy_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.copy_dest.push(path.into());
        self
    }

    /// Add a compare basis directory (`--compare-dest`).
    pub fn compare_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.compare_dest.push(path.into());
        self
    }

    /// Enable or disable backup of overwritten/deleted files (`-b`).
    pub fn backup(mut self, v: bool) -> Self {
        self.opts.backup = v;
        self
    }

    /// Set the directory for backup files (`--backup-dir`).
    pub fn backup_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.backup_dir = Some(path.into());
        self
    }

    /// Set the suffix for backup files (`--suffix`).
    pub fn suffix(mut self, s: impl Into<String>) -> Self {
        self.opts.suffix = s.into();
        self
    }

    /// Enable or disable keeping partial files (`--partial`).
    pub fn partial(mut self, v: bool) -> Self {
        self.opts.partial = v;
        self
    }

    /// Set the directory for partial transfers (`--partial-dir`).
    pub fn partial_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.partial_dir = Some(path.into());
        self
    }

    /// Enable or disable append mode (`--append`).
    pub fn append(mut self, v: bool) -> Self {
        self.opts.append = v;
        self
    }

    /// Set the file list source path (`--files-from`).
    pub fn files_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.opts.files_from = Some(path.into());
        self
    }

    /// Set exclude patterns in bulk (replaces existing excludes).
    pub fn excludes(mut self, patterns: Vec<String>) -> Self {
        self.opts.exclude = patterns;
        self
    }

    /// Set include patterns in bulk (replaces existing includes).
    pub fn includes(mut self, patterns: Vec<String>) -> Self {
        self.opts.include = patterns;
        self
    }

    /// Set filter rules in bulk (replaces existing filters).
    pub fn filters(mut self, rules: Vec<String>) -> Self {
        self.opts.filter = rules;
        self
    }

    /// Set source paths in bulk (replaces existing sources).
    pub fn sources(mut self, paths: Vec<PathBuf>) -> Self {
        self.opts.source = paths;
        self
    }

    /// Set link-dest directories in bulk.
    pub fn link_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.opts.link_dest = paths;
        self
    }

    /// Set copy-dest directories in bulk.
    pub fn copy_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.opts.copy_dest = paths;
        self
    }

    /// Set compare-dest directories in bulk.
    pub fn compare_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.opts.compare_dest = paths;
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
        assert!(!opts.recursive());
        assert!(!opts.compress());
        assert!(!opts.dry_run());
        assert_eq!(opts.delete(), DeleteMode::None);
        assert_eq!(opts.verbosity(), Verbosity::Normal);
        assert!(!opts.is_archive());
    }

    #[test]
    fn test_archive_mode() {
        let opts = TransferOptions::builder().archive().build();
        assert!(opts.is_archive());
        assert!(opts.recursive());
        assert!(opts.preserve_links());
        assert!(opts.preserve_perms());
        assert!(opts.preserve_times());
        assert!(opts.preserve_group());
        assert!(opts.preserve_owner());
        assert!(opts.preserve_devices());
        assert!(opts.preserve_specials());
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

        assert!(opts.recursive());
        assert!(opts.compress());
        assert_eq!(opts.compress_level(), 3);
        assert_eq!(opts.delete(), DeleteMode::During);
        assert!(opts.dry_run());
        assert_eq!(opts.verbosity(), Verbosity::Verbose);
        assert_eq!(opts.exclude(), &["*.tmp", "*.log"]);
        assert_eq!(opts.source(), &[PathBuf::from("/src")]);
        assert_eq!(opts.dest(), Some(&PathBuf::from("/dst")));
    }

    #[test]
    fn test_compress_level_clamped() {
        let opts = TransferOptions::builder().compress_level(99).build();
        assert_eq!(opts.compress_level(), 9);

        let opts = TransferOptions::builder().compress_level(0).build();
        assert_eq!(opts.compress_level(), 1);
    }
}
