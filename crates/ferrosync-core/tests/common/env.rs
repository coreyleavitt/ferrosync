use std::path::{Path, PathBuf};

use filetime::FileTime;

/// Builder for test environments with source, destination, and previous snapshot directories.
///
/// Creates a temporary directory with `src/`, `dst/`, and optionally `prev/` subdirectories,
/// populated with specified files and mtimes.
pub struct TestEnv {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

struct FileSpec {
    rel_path: String,
    content: Vec<u8>,
    mtime: Option<i64>,
}

enum DirTarget {
    Src,
    Prev,
}

struct DirSpec {
    target: DirTarget,
    rel_path: String,
}

struct SymlinkSpec {
    target: String,
    link_name: String,
}

pub struct TestEnvBuilder {
    src_files: Vec<FileSpec>,
    dst_files: Vec<FileSpec>,
    prev_files: Vec<FileSpec>,
    extra_dirs: Vec<DirSpec>,
    src_symlinks: Vec<SymlinkSpec>,
}

impl TestEnvBuilder {
    pub fn new() -> Self {
        Self {
            src_files: Vec::new(),
            dst_files: Vec::new(),
            prev_files: Vec::new(),
            extra_dirs: Vec::new(),
            src_symlinks: Vec::new(),
        }
    }

    /// Add a file to the source directory.
    pub fn with_src_file(mut self, path: &str, content: &[u8], mtime: Option<i64>) -> Self {
        self.src_files.push(FileSpec {
            rel_path: path.to_string(),
            content: content.to_vec(),
            mtime,
        });
        self
    }

    /// Add a subdirectory to the source directory.
    pub fn with_src_dir(mut self, path: &str) -> Self {
        self.extra_dirs.push(DirSpec {
            target: DirTarget::Src,
            rel_path: path.to_string(),
        });
        self
    }

    /// Add a file to the previous snapshot directory (for --link-dest, --compare-dest, etc.).
    pub fn with_prev_file(mut self, path: &str, content: &[u8], mtime: Option<i64>) -> Self {
        self.prev_files.push(FileSpec {
            rel_path: path.to_string(),
            content: content.to_vec(),
            mtime,
        });
        self
    }

    /// Add a subdirectory to the previous snapshot directory.
    pub fn with_prev_dir(mut self, path: &str) -> Self {
        self.extra_dirs.push(DirSpec {
            target: DirTarget::Prev,
            rel_path: path.to_string(),
        });
        self
    }

    /// Add a pre-existing file to the destination directory.
    ///
    /// Useful for testing delta transfers, `--update`, `--existing`, etc.
    /// where the destination already has files before the transfer.
    pub fn with_dst_file(mut self, path: &str, content: &[u8], mtime: Option<i64>) -> Self {
        self.dst_files.push(FileSpec {
            rel_path: path.to_string(),
            content: content.to_vec(),
            mtime,
        });
        self
    }

    /// Add a symlink to the source directory.
    #[cfg(unix)]
    pub fn with_src_symlink(mut self, target: &str, link_name: &str) -> Self {
        self.src_symlinks.push(SymlinkSpec {
            target: target.to_string(),
            link_name: link_name.to_string(),
        });
        self
    }

    pub fn build(self) -> TestEnv {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let src = root.join("src");
        let dst = root.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        // Create extra source directories.
        for dir in &self.extra_dirs {
            let base = match dir.target {
                DirTarget::Src => &src,
                DirTarget::Prev => &root.join("prev"),
            };
            std::fs::create_dir_all(base.join(&dir.rel_path)).unwrap();
        }

        // Write source files.
        for f in &self.src_files {
            let path = src.join(&f.rel_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, &f.content).unwrap();
            if let Some(mtime) = f.mtime {
                set_mtime(&path, mtime);
            }
        }

        // Write destination files (pre-existing dest for delta/update tests).
        for f in &self.dst_files {
            let path = dst.join(&f.rel_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, &f.content).unwrap();
            if let Some(mtime) = f.mtime {
                set_mtime(&path, mtime);
            }
        }

        // Create symlinks in source directory.
        #[cfg(unix)]
        for link in &self.src_symlinks {
            let link_path = src.join(&link.link_name);
            if let Some(parent) = link_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::os::unix::fs::symlink(&link.target, &link_path).unwrap();
        }

        // Write prev files (creates prev/ on demand).
        if !self.prev_files.is_empty() {
            let prev = root.join("prev");
            std::fs::create_dir_all(&prev).unwrap();
            for f in &self.prev_files {
                let path = prev.join(&f.rel_path);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(&path, &f.content).unwrap();
                if let Some(mtime) = f.mtime {
                    set_mtime(&path, mtime);
                }
            }
        }

        TestEnv { _tmp: tmp, root }
    }
}

impl TestEnv {
    pub fn builder() -> TestEnvBuilder {
        TestEnvBuilder::new()
    }

    /// Path to the source directory.
    pub fn src(&self) -> PathBuf {
        self.root.join("src")
    }

    /// Path to the destination directory.
    pub fn dst(&self) -> PathBuf {
        self.root.join("dst")
    }

    /// Path to the previous snapshot directory (for --link-dest, etc.).
    pub fn prev(&self) -> PathBuf {
        self.root.join("prev")
    }

    /// Path to the root temporary directory.
    pub fn dir(&self) -> &Path {
        &self.root
    }
}

/// Set the mtime of a file to a specific Unix timestamp.
pub fn set_mtime(path: &Path, unix_secs: i64) {
    let ft = FileTime::from_unix_time(unix_secs, 0);
    filetime::set_file_mtime(path, ft).unwrap();
}

/// Get the inode number of a file (Unix only).
#[cfg(unix)]
pub fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().ino()
}

/// Create a platform-appropriate FileSystem implementation.
pub fn test_filesystem() -> Box<dyn ferrosync_core::fs::FileSystem> {
    #[cfg(unix)]
    {
        Box::new(ferrosync_core::fs::unix::UnixFileSystem::new())
    }
    #[cfg(windows)]
    {
        Box::new(ferrosync_core::fs::windows::WindowsFileSystem::new())
    }
}

/// Create a filesystem wrapped with FakeSuperFs for --fake-super tests.
#[cfg(unix)]
pub fn test_filesystem_fake_super() -> Box<dyn ferrosync_core::fs::FileSystem> {
    Box::new(ferrosync_core::fs::fake_super::FakeSuperFs::new(
        Box::new(ferrosync_core::fs::unix::UnixFileSystem::new()),
    ))
}
