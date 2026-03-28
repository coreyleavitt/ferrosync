//! Transfer configuration.
//!
//! Maps to rsync's command-line flags. The builder pattern allows
//! constructing options incrementally, with sensible defaults.
//!
//! The configuration is decomposed into focused sub-config structs
//! ([`PathConfig`], [`PreservationConfig`], [`FileSelectionConfig`], etc.)
//! grouped under [`TransferConfig`]. Each subsystem receives only the
//! sub-config(s) it needs.
//!
//! [`TransferOptions`] is a type alias for [`TransferConfig`] for backward
//! compatibility.

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

/// Legacy type alias for backward compatibility.
///
/// New code should use [`TransferConfig`] directly.
pub type TransferOptions = TransferConfig;

/// Legacy builder type alias for backward compatibility.
///
/// New code should use [`TransferConfigBuilder`] directly.
pub type TransferOptionsBuilder = TransferConfigBuilder;

// ===========================================================================
// Decomposed config structs (issue #99)
// ===========================================================================

/// Source and destination paths.
#[derive(Debug, Clone, Default)]
pub struct PathConfig {
    pub source: Vec<PathBuf>,
    pub dest: Option<PathBuf>,
}

/// Metadata preservation flags.
#[derive(Debug, Clone, Default)]
pub struct PreservationConfig {
    pub times: bool,
    pub perms: bool,
    pub owner: bool,
    pub group: bool,
    pub links: bool,
    pub hard_links: bool,
    pub devices: bool,
    pub specials: bool,
    pub acls: bool,
    pub xattrs: bool,
    pub numeric_ids: bool,
    pub chmod: Vec<String>,
    pub chown_uid: Option<u32>,
    pub chown_gid: Option<u32>,
}

/// File selection and quick-check options.
#[derive(Debug, Clone, Default)]
pub struct FileSelectionConfig {
    pub checksum_mode: bool,
    pub update: bool,
    pub ignore_times: bool,
    pub size_only: bool,
    pub existing: bool,
    pub ignore_existing: bool,
    pub max_size: Option<u64>,
    pub min_size: Option<u64>,
    pub modify_window: u32,
    pub fuzzy: bool,
}

/// File write strategy options.
#[derive(Debug, Clone)]
pub struct FileWriteConfig {
    pub inplace: bool,
    pub whole_file: bool,
    pub sparse: bool,
    pub backup: bool,
    pub backup_dir: Option<PathBuf>,
    pub suffix: String,
    pub partial: bool,
    pub partial_dir: Option<PathBuf>,
    pub append: bool,
    pub append_verify: bool,
    pub remove_source_files: bool,
    pub safe_links: bool,
    pub keep_dirlinks: bool,
    pub link_dest: Vec<PathBuf>,
    pub copy_dest: Vec<PathBuf>,
    pub compare_dest: Vec<PathBuf>,
}

impl Default for FileWriteConfig {
    fn default() -> Self {
        Self {
            inplace: false,
            whole_file: false,
            sparse: false,
            backup: false,
            backup_dir: None,
            suffix: "~".to_string(),
            partial: false,
            partial_dir: None,
            append: false,
            append_verify: false,
            remove_source_files: false,
            safe_links: false,
            keep_dirlinks: false,
            link_dest: Vec::new(),
            copy_dest: Vec::new(),
            compare_dest: Vec::new(),
        }
    }
}

/// Filter and exclusion options.
#[derive(Debug, Clone, Default)]
pub struct FilteringConfig {
    pub exclude: Vec<String>,
    pub include: Vec<String>,
    pub filter: Vec<String>,
    pub exclude_from: Vec<PathBuf>,
    pub include_from: Vec<PathBuf>,
    pub cvs_exclude: bool,
    pub filter_merge_files: u8,
}

/// Directory traversal options.
#[derive(Debug, Clone, Default)]
pub struct TraversalConfig {
    pub dir_mode: DirectoryMode,
    pub one_file_system: bool,
    pub relative: bool,
    pub copy_links: bool,
}

/// Deletion behavior options.
#[derive(Debug, Clone, Default)]
pub struct DeletionConfig {
    pub mode: DeleteMode,
    pub max_delete: Option<u64>,
    pub prune_empty_dirs: bool,
}

/// Protocol negotiation options.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub compress: bool,
    pub compress_level: u32,
    pub checksum_choice: Option<String>,
    pub compress_choice: Option<String>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            compress: false,
            compress_level: 6,
            checksum_choice: None,
            compress_choice: None,
        }
    }
}

/// Resource limit options.
#[derive(Debug, Clone, Default)]
pub struct LimitsConfig {
    pub bwlimit: Option<u64>,
    pub timeout: Option<u64>,
    pub block_size: Option<i32>,
}

/// Output and display options.
#[derive(Debug, Clone, Default)]
pub struct OutputConfig {
    pub verbosity: Verbosity,
    pub progress: bool,
    pub stats: bool,
    pub dry_run: bool,
    pub itemize_changes: bool,
    pub list_only: bool,
    pub fake_super: bool,
}

/// Decomposed transfer configuration.
///
/// Groups the 76+ fields of `TransferOptions` into focused sub-configs.
/// Each subsystem receives only the sub-config(s) it needs.
#[derive(Debug, Clone, Default)]
pub struct TransferConfig {
    pub paths: PathConfig,
    pub preservation: PreservationConfig,
    pub file_selection: FileSelectionConfig,
    pub file_write: FileWriteConfig,
    pub filtering: FilteringConfig,
    pub traversal: TraversalConfig,
    pub deletion: DeletionConfig,
    pub protocol: ProtocolConfig,
    pub limits: LimitsConfig,
    pub output: OutputConfig,
    /// Filename encoding conversion charset (`--iconv`).
    pub iconv: Option<String>,
    /// Read file list from this path (`--files-from`).
    pub files_from: Option<PathBuf>,
    /// Record transfer to batch file (`--write-batch`).
    pub write_batch: Option<PathBuf>,
    /// Replay transfer from batch file (`--read-batch`).
    pub read_batch: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Convenience getters on TransferConfig (mirror the old TransferOptions API)
// ---------------------------------------------------------------------------

impl TransferConfig {
    /// Create a new builder for transfer configuration.
    pub fn builder() -> TransferConfigBuilder {
        TransferConfigBuilder::default()
    }

    /// Returns `true` if archive mode flags are all set (`-a` = `-rlptgoD`).
    pub fn is_archive(&self) -> bool {
        self.traversal.dir_mode == DirectoryMode::Recurse
            && self.preservation.links
            && self.preservation.perms
            && self.preservation.times
            && self.preservation.group
            && self.preservation.owner
            && self.preservation.devices
            && self.preservation.specials
    }

    pub fn recursive(&self) -> bool {
        self.traversal.dir_mode == DirectoryMode::Recurse
    }
    pub fn dirs(&self) -> bool {
        self.traversal.dir_mode == DirectoryMode::List
    }
    pub fn dir_mode(&self) -> DirectoryMode {
        self.traversal.dir_mode
    }
    pub fn preserve_links(&self) -> bool {
        self.preservation.links
    }
    pub fn preserve_perms(&self) -> bool {
        self.preservation.perms
    }
    pub fn preserve_times(&self) -> bool {
        self.preservation.times
    }
    pub fn preserve_group(&self) -> bool {
        self.preservation.group
    }
    pub fn preserve_owner(&self) -> bool {
        self.preservation.owner
    }
    pub fn preserve_devices(&self) -> bool {
        self.preservation.devices
    }
    pub fn preserve_specials(&self) -> bool {
        self.preservation.specials
    }
    pub fn preserve_hard_links(&self) -> bool {
        self.preservation.hard_links
    }
    pub fn preserve_acls(&self) -> bool {
        self.preservation.acls
    }
    pub fn preserve_xattrs(&self) -> bool {
        self.preservation.xattrs
    }
    pub fn numeric_ids(&self) -> bool {
        self.preservation.numeric_ids
    }
    pub fn chmod(&self) -> &[String] {
        &self.preservation.chmod
    }
    pub fn chown_uid(&self) -> Option<u32> {
        self.preservation.chown_uid
    }
    pub fn chown_gid(&self) -> Option<u32> {
        self.preservation.chown_gid
    }
    pub fn checksum_mode(&self) -> bool {
        self.file_selection.checksum_mode
    }
    pub fn update(&self) -> bool {
        self.file_selection.update
    }
    pub fn ignore_times(&self) -> bool {
        self.file_selection.ignore_times
    }
    pub fn size_only(&self) -> bool {
        self.file_selection.size_only
    }
    pub fn existing(&self) -> bool {
        self.file_selection.existing
    }
    pub fn ignore_existing(&self) -> bool {
        self.file_selection.ignore_existing
    }
    pub fn max_size(&self) -> Option<u64> {
        self.file_selection.max_size
    }
    pub fn min_size(&self) -> Option<u64> {
        self.file_selection.min_size
    }
    pub fn modify_window(&self) -> u32 {
        self.file_selection.modify_window
    }
    pub fn fuzzy(&self) -> bool {
        self.file_selection.fuzzy
    }
    pub fn inplace(&self) -> bool {
        self.file_write.inplace
    }
    pub fn whole_file(&self) -> bool {
        self.file_write.whole_file
    }
    pub fn sparse(&self) -> bool {
        self.file_write.sparse
    }
    pub fn backup(&self) -> bool {
        self.file_write.backup
    }
    pub fn backup_dir(&self) -> Option<&PathBuf> {
        self.file_write.backup_dir.as_ref()
    }
    pub fn suffix(&self) -> &str {
        &self.file_write.suffix
    }
    pub fn partial(&self) -> bool {
        self.file_write.partial
    }
    pub fn partial_dir(&self) -> Option<&PathBuf> {
        self.file_write.partial_dir.as_ref()
    }
    pub fn append(&self) -> bool {
        self.file_write.append
    }
    pub fn append_verify(&self) -> bool {
        self.file_write.append_verify
    }
    pub fn remove_source_files(&self) -> bool {
        self.file_write.remove_source_files
    }
    pub fn safe_links(&self) -> bool {
        self.file_write.safe_links
    }
    pub fn keep_dirlinks(&self) -> bool {
        self.file_write.keep_dirlinks
    }
    pub fn link_dest(&self) -> &[PathBuf] {
        &self.file_write.link_dest
    }
    pub fn copy_dest(&self) -> &[PathBuf] {
        &self.file_write.copy_dest
    }
    pub fn compare_dest(&self) -> &[PathBuf] {
        &self.file_write.compare_dest
    }
    pub fn exclude(&self) -> &[String] {
        &self.filtering.exclude
    }
    pub fn include(&self) -> &[String] {
        &self.filtering.include
    }
    pub fn filter(&self) -> &[String] {
        &self.filtering.filter
    }
    pub fn exclude_from(&self) -> &[PathBuf] {
        &self.filtering.exclude_from
    }
    pub fn include_from(&self) -> &[PathBuf] {
        &self.filtering.include_from
    }
    pub fn cvs_exclude(&self) -> bool {
        self.filtering.cvs_exclude
    }
    pub fn filter_merge_files(&self) -> u8 {
        self.filtering.filter_merge_files
    }
    pub fn one_file_system(&self) -> bool {
        self.traversal.one_file_system
    }
    pub fn relative(&self) -> bool {
        self.traversal.relative
    }
    pub fn copy_links(&self) -> bool {
        self.traversal.copy_links
    }
    pub fn delete(&self) -> DeleteMode {
        self.deletion.mode
    }
    pub fn max_delete(&self) -> Option<u64> {
        self.deletion.max_delete
    }
    pub fn prune_empty_dirs(&self) -> bool {
        self.deletion.prune_empty_dirs
    }
    pub fn compress(&self) -> bool {
        self.protocol.compress
    }
    pub fn compress_level(&self) -> u32 {
        self.protocol.compress_level
    }
    pub fn checksum_choice(&self) -> Option<&str> {
        self.protocol.checksum_choice.as_deref()
    }
    pub fn compress_choice(&self) -> Option<&str> {
        self.protocol.compress_choice.as_deref()
    }
    pub fn bwlimit(&self) -> Option<u64> {
        self.limits.bwlimit
    }
    pub fn timeout(&self) -> Option<u64> {
        self.limits.timeout
    }
    pub fn block_size(&self) -> Option<i32> {
        self.limits.block_size
    }
    pub fn verbosity(&self) -> Verbosity {
        self.output.verbosity
    }
    pub fn progress(&self) -> bool {
        self.output.progress
    }
    pub fn stats(&self) -> bool {
        self.output.stats
    }
    pub fn dry_run(&self) -> bool {
        self.output.dry_run
    }
    pub fn itemize_changes(&self) -> bool {
        self.output.itemize_changes
    }
    pub fn list_only(&self) -> bool {
        self.output.list_only
    }
    pub fn fake_super(&self) -> bool {
        self.output.fake_super
    }
    pub fn source(&self) -> &[PathBuf] {
        &self.paths.source
    }
    pub fn dest(&self) -> Option<&PathBuf> {
        self.paths.dest.as_ref()
    }
    pub fn iconv(&self) -> Option<&str> {
        self.iconv.as_deref()
    }
    pub fn files_from(&self) -> Option<&PathBuf> {
        self.files_from.as_ref()
    }
    pub fn write_batch(&self) -> Option<&PathBuf> {
        self.write_batch.as_ref()
    }
    pub fn read_batch(&self) -> Option<&PathBuf> {
        self.read_batch.as_ref()
    }
}

// ---------------------------------------------------------------------------
// TransferConfigBuilder
// ---------------------------------------------------------------------------

/// Builder for [`TransferConfig`].
#[derive(Debug, Default)]
pub struct TransferConfigBuilder {
    cfg: TransferConfig,
}

impl TransferConfigBuilder {
    /// Initialize builder from an existing config, allowing selective overrides.
    pub fn from(mut self, cfg: TransferConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Enable archive mode (`-a` = `-rlptgoD`).
    pub fn archive(mut self) -> Self {
        self.cfg.traversal.dir_mode = DirectoryMode::Recurse;
        self.cfg.preservation.links = true;
        self.cfg.preservation.perms = true;
        self.cfg.preservation.times = true;
        self.cfg.preservation.group = true;
        self.cfg.preservation.owner = true;
        self.cfg.preservation.devices = true;
        self.cfg.preservation.specials = true;
        self
    }

    pub fn recursive(mut self, v: bool) -> Self {
        self.cfg.traversal.dir_mode = if v {
            DirectoryMode::Recurse
        } else {
            DirectoryMode::Skip
        };
        self
    }
    pub fn dirs(mut self, v: bool) -> Self {
        if v {
            self.cfg.traversal.dir_mode = DirectoryMode::List;
        }
        self
    }
    pub fn preserve_links(mut self, v: bool) -> Self {
        self.cfg.preservation.links = v;
        self
    }
    pub fn preserve_perms(mut self, v: bool) -> Self {
        self.cfg.preservation.perms = v;
        self
    }
    pub fn preserve_times(mut self, v: bool) -> Self {
        self.cfg.preservation.times = v;
        self
    }
    pub fn preserve_group(mut self, v: bool) -> Self {
        self.cfg.preservation.group = v;
        self
    }
    pub fn preserve_owner(mut self, v: bool) -> Self {
        self.cfg.preservation.owner = v;
        self
    }
    pub fn preserve_devices(mut self, v: bool) -> Self {
        self.cfg.preservation.devices = v;
        self
    }
    pub fn preserve_specials(mut self, v: bool) -> Self {
        self.cfg.preservation.specials = v;
        self
    }
    pub fn preserve_hard_links(mut self, v: bool) -> Self {
        self.cfg.preservation.hard_links = v;
        self
    }
    pub fn preserve_acls(mut self, v: bool) -> Self {
        self.cfg.preservation.acls = v;
        self
    }
    pub fn preserve_xattrs(mut self, v: bool) -> Self {
        self.cfg.preservation.xattrs = v;
        self
    }
    pub fn numeric_ids(mut self, v: bool) -> Self {
        self.cfg.preservation.numeric_ids = v;
        self
    }
    pub fn chmod(mut self, spec: impl Into<String>) -> Self {
        self.cfg.preservation.chmod.push(spec.into());
        self
    }
    pub fn chown_uid(mut self, uid: u32) -> Self {
        self.cfg.preservation.chown_uid = Some(uid);
        self
    }
    pub fn chown_gid(mut self, gid: u32) -> Self {
        self.cfg.preservation.chown_gid = Some(gid);
        self
    }
    pub fn checksum_mode(mut self, v: bool) -> Self {
        self.cfg.file_selection.checksum_mode = v;
        self
    }
    pub fn whole_file(mut self, v: bool) -> Self {
        self.cfg.file_write.whole_file = v;
        self
    }
    pub fn update(mut self, v: bool) -> Self {
        self.cfg.file_selection.update = v;
        self
    }
    pub fn inplace(mut self, v: bool) -> Self {
        self.cfg.file_write.inplace = v;
        self
    }
    pub fn delete(mut self, mode: DeleteMode) -> Self {
        self.cfg.deletion.mode = mode;
        self
    }
    pub fn compress(mut self, v: bool) -> Self {
        self.cfg.protocol.compress = v;
        self
    }
    pub fn compress_level(mut self, level: u32) -> Self {
        self.cfg.protocol.compress_level = level.clamp(1, 9);
        self
    }
    pub fn verbosity(mut self, v: Verbosity) -> Self {
        self.cfg.output.verbosity = v;
        self
    }
    pub fn progress(mut self, v: bool) -> Self {
        self.cfg.output.progress = v;
        self
    }
    pub fn stats(mut self, v: bool) -> Self {
        self.cfg.output.stats = v;
        self
    }
    pub fn dry_run(mut self, v: bool) -> Self {
        self.cfg.output.dry_run = v;
        self
    }
    pub fn itemize_changes(mut self, v: bool) -> Self {
        self.cfg.output.itemize_changes = v;
        self
    }
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.cfg.filtering.exclude.push(pattern.into());
        self
    }
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.cfg.filtering.include.push(pattern.into());
        self
    }
    pub fn filter(mut self, rule: impl Into<String>) -> Self {
        self.cfg.filtering.filter.push(rule.into());
        self
    }
    pub fn source(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.paths.source.push(path.into());
        self
    }
    pub fn dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.paths.dest = Some(path.into());
        self
    }
    pub fn bwlimit(mut self, bytes_per_sec: u64) -> Self {
        self.cfg.limits.bwlimit = Some(bytes_per_sec);
        self
    }
    pub fn max_size(mut self, bytes: u64) -> Self {
        self.cfg.file_selection.max_size = Some(bytes);
        self
    }
    pub fn min_size(mut self, bytes: u64) -> Self {
        self.cfg.file_selection.min_size = Some(bytes);
        self
    }
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.cfg.limits.timeout = Some(seconds);
        self
    }
    pub fn ignore_times(mut self, v: bool) -> Self {
        self.cfg.file_selection.ignore_times = v;
        self
    }
    pub fn size_only(mut self, v: bool) -> Self {
        self.cfg.file_selection.size_only = v;
        self
    }
    pub fn existing(mut self, v: bool) -> Self {
        self.cfg.file_selection.existing = v;
        self
    }
    pub fn ignore_existing(mut self, v: bool) -> Self {
        self.cfg.file_selection.ignore_existing = v;
        self
    }
    pub fn max_delete(mut self, n: u64) -> Self {
        self.cfg.deletion.max_delete = Some(n);
        self
    }
    pub fn prune_empty_dirs(mut self, v: bool) -> Self {
        self.cfg.deletion.prune_empty_dirs = v;
        self
    }
    pub fn copy_links(mut self, v: bool) -> Self {
        self.cfg.traversal.copy_links = v;
        self
    }
    pub fn safe_links(mut self, v: bool) -> Self {
        self.cfg.file_write.safe_links = v;
        self
    }
    pub fn keep_dirlinks(mut self, v: bool) -> Self {
        self.cfg.file_write.keep_dirlinks = v;
        self
    }
    pub fn remove_source_files(mut self, v: bool) -> Self {
        self.cfg.file_write.remove_source_files = v;
        self
    }
    pub fn modify_window(mut self, n: u32) -> Self {
        self.cfg.file_selection.modify_window = n;
        self
    }
    pub fn append_verify(mut self, v: bool) -> Self {
        self.cfg.file_write.append_verify = v;
        self
    }
    pub fn exclude_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.filtering.exclude_from.push(path.into());
        self
    }
    pub fn include_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.filtering.include_from.push(path.into());
        self
    }
    pub fn cvs_exclude(mut self, v: bool) -> Self {
        self.cfg.filtering.cvs_exclude = v;
        self
    }
    pub fn block_size(mut self, n: i32) -> Self {
        self.cfg.limits.block_size = Some(n);
        self
    }
    pub fn one_file_system(mut self, v: bool) -> Self {
        self.cfg.traversal.one_file_system = v;
        self
    }
    pub fn sparse(mut self, v: bool) -> Self {
        self.cfg.file_write.sparse = v;
        self
    }
    pub fn relative(mut self, v: bool) -> Self {
        self.cfg.traversal.relative = v;
        self
    }
    pub fn filter_merge_files(mut self, n: u8) -> Self {
        self.cfg.filtering.filter_merge_files = n;
        self
    }
    pub fn list_only(mut self, v: bool) -> Self {
        self.cfg.output.list_only = v;
        self
    }
    pub fn fuzzy(mut self, v: bool) -> Self {
        self.cfg.file_selection.fuzzy = v;
        self
    }
    pub fn fake_super(mut self, v: bool) -> Self {
        self.cfg.output.fake_super = v;
        self
    }
    pub fn checksum_choice(mut self, name: impl Into<String>) -> Self {
        self.cfg.protocol.checksum_choice = Some(name.into());
        self
    }
    pub fn compress_choice(mut self, name: impl Into<String>) -> Self {
        self.cfg.protocol.compress_choice = Some(name.into());
        self
    }
    pub fn iconv(mut self, charset: impl Into<String>) -> Self {
        self.cfg.iconv = Some(charset.into());
        self
    }
    pub fn write_batch(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.write_batch = Some(path.into());
        self
    }
    pub fn read_batch(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.read_batch = Some(path.into());
        self
    }
    pub fn link_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.file_write.link_dest.push(path.into());
        self
    }
    pub fn copy_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.file_write.copy_dest.push(path.into());
        self
    }
    pub fn compare_dest(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.file_write.compare_dest.push(path.into());
        self
    }
    pub fn backup(mut self, v: bool) -> Self {
        self.cfg.file_write.backup = v;
        self
    }
    pub fn backup_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.file_write.backup_dir = Some(path.into());
        self
    }
    pub fn suffix(mut self, s: impl Into<String>) -> Self {
        self.cfg.file_write.suffix = s.into();
        self
    }
    pub fn partial(mut self, v: bool) -> Self {
        self.cfg.file_write.partial = v;
        self
    }
    pub fn partial_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.file_write.partial_dir = Some(path.into());
        self
    }
    pub fn append(mut self, v: bool) -> Self {
        self.cfg.file_write.append = v;
        self
    }
    pub fn files_from(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.files_from = Some(path.into());
        self
    }
    pub fn excludes(mut self, patterns: Vec<String>) -> Self {
        self.cfg.filtering.exclude = patterns;
        self
    }
    pub fn includes(mut self, patterns: Vec<String>) -> Self {
        self.cfg.filtering.include = patterns;
        self
    }
    pub fn filters(mut self, rules: Vec<String>) -> Self {
        self.cfg.filtering.filter = rules;
        self
    }
    pub fn sources(mut self, paths: Vec<PathBuf>) -> Self {
        self.cfg.paths.source = paths;
        self
    }
    pub fn link_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.cfg.file_write.link_dest = paths;
        self
    }
    pub fn copy_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.cfg.file_write.copy_dest = paths;
        self
    }
    pub fn compare_dests(mut self, paths: Vec<PathBuf>) -> Self {
        self.cfg.file_write.compare_dest = paths;
        self
    }

    /// Build the [`TransferConfig`].
    pub fn build(self) -> TransferConfig {
        self.cfg
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

    // --- TransferConfig tests ---

    #[test]
    fn test_config_default() {
        let cfg = TransferConfig::default();
        assert!(!cfg.recursive());
        assert!(!cfg.compress());
        assert!(!cfg.dry_run());
        assert_eq!(cfg.delete(), DeleteMode::None);
        assert_eq!(cfg.verbosity(), Verbosity::Normal);
        assert!(!cfg.is_archive());
    }

    #[test]
    fn test_config_archive() {
        let cfg = TransferConfig::builder().archive().build();
        assert!(cfg.is_archive());
        assert!(cfg.recursive());
        assert!(cfg.preserve_links());
        assert!(cfg.preserve_perms());
        assert!(cfg.preserve_times());
        assert!(cfg.preserve_group());
        assert!(cfg.preserve_owner());
        assert!(cfg.preserve_devices());
        assert!(cfg.preserve_specials());
    }

    #[test]
    fn test_config_builder_chaining() {
        let cfg = TransferConfig::builder()
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

        assert!(cfg.recursive());
        assert!(cfg.compress());
        assert_eq!(cfg.compress_level(), 3);
        assert_eq!(cfg.delete(), DeleteMode::During);
        assert!(cfg.dry_run());
        assert_eq!(cfg.verbosity(), Verbosity::Verbose);
        assert_eq!(cfg.exclude(), &["*.tmp", "*.log"]);
        assert_eq!(cfg.source(), &[PathBuf::from("/src")]);
        assert_eq!(cfg.dest(), Some(&PathBuf::from("/dst")));
    }

    #[test]
    fn test_config_compress_level_clamped() {
        let cfg = TransferConfig::builder().compress_level(99).build();
        assert_eq!(cfg.compress_level(), 9);
    }
}
