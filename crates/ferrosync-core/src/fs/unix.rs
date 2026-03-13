//! Unix filesystem implementation.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::error::FsError;

use super::metadata::FileMetadata;
use super::{DirEntry, FileSystem};

type Result<T> = std::result::Result<T, FsError>;

/// Standard Unix filesystem implementation.
#[derive(Debug, Default)]
pub struct UnixFileSystem;

impl UnixFileSystem {
    pub fn new() -> Self {
        Self
    }

    fn map_io_err(path: &Path, e: std::io::Error) -> FsError {
        match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound {
                path: path.to_path_buf(),
            },
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
                path: path.to_path_buf(),
            },
            _ => FsError::Io {
                path: path.to_path_buf(),
                source: e,
            },
        }
    }

    fn metadata_from_std(m: &std::fs::Metadata) -> FileMetadata {
        FileMetadata {
            len: m.len() as i64,
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec() as u32,
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            rdev: m.rdev(),
            dev: m.dev(),
            ino: m.ino(),
            nlink: m.nlink(),
        }
    }
}

impl FileSystem for UnixFileSystem {
    fn lstat(&self, path: &Path) -> Result<FileMetadata> {
        let m = std::fs::symlink_metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(Self::metadata_from_std(&m))
    }

    fn stat(&self, path: &Path) -> Result<FileMetadata> {
        let m = std::fs::metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(Self::metadata_from_std(&m))
    }

    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let target = std::fs::read_link(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(target.as_os_str().as_bytes().to_vec())
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn write_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        // Write to a temp file in the same directory, then rename for atomicity.
        let parent = path.parent().unwrap_or(Path::new("."));
        let tmp_name = format!(
            ".ferrosync.{}.tmp",
            std::process::id()
        );
        let tmp_path = parent.join(&tmp_name);

        std::fs::write(&tmp_path, data).map_err(|e| Self::map_io_err(&tmp_path, e))?;

        if let Some(m) = mode {
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(m))
                .map_err(|e| Self::map_io_err(&tmp_path, e))?;
        }

        std::fs::rename(&tmp_path, path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn mkdir(&self, path: &Path, mode: u32) -> Result<()> {
        std::fs::create_dir_all(path).map_err(|e| Self::map_io_err(path, e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn create_symlink(&self, target: &[u8], link_path: &Path) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Remove existing symlink if present.
        if link_path.symlink_metadata().is_ok() {
            std::fs::remove_file(link_path).map_err(|e| Self::map_io_err(link_path, e))?;
        }

        let target_os = OsStr::from_bytes(target);
        std::os::unix::fs::symlink(target_os, link_path)
            .map_err(|e| Self::map_io_err(link_path, e))?;
        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn set_mtime(&self, path: &Path, mtime: i64, mtime_nsec: u32) -> Result<()> {
        let times = [
            // atime: preserve by using current
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            // mtime: set to desired value
            libc::timespec {
                tv_sec: mtime,
                tv_nsec: mtime_nsec as i64,
            },
        ];

        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| FsError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path contains null byte",
                ),
            })?;

        let ret = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        if ret != 0 {
            return Err(Self::map_io_err(path, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| FsError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path contains null byte",
                ),
            })?;

        let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        if ret != 0 {
            return Err(Self::map_io_err(path, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        std::fs::remove_file(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        std::fs::remove_dir(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        use std::os::unix::ffi::OsStrExt;
        let mut entries = Vec::new();
        let rd = std::fs::read_dir(path).map_err(|e| Self::map_io_err(path, e))?;

        for entry in rd {
            let entry = entry.map_err(|e| Self::map_io_err(path, e))?;
            let name = entry.file_name().as_os_str().as_bytes().to_vec();
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| Self::map_io_err(&entry.path(), e))?;
            entries.push(DirEntry {
                name,
                metadata: Self::metadata_from_std(&meta),
            });
        }

        Ok(entries)
    }

    fn lexists(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn device_id(&self, path: &Path) -> Result<u64> {
        let m = std::fs::metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(m.dev())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, UnixFileSystem) {
        (TempDir::new().unwrap(), UnixFileSystem::new())
    }

    #[test]
    fn test_write_and_read_file() {
        let (tmp, fs) = setup();
        let path = tmp.path().join("test.txt");
        fs.write_file(&path, b"hello world", Some(0o644)).unwrap();

        let data = fs.read_file(&path).unwrap();
        assert_eq!(data, b"hello world");

        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.mode & 0o777, 0o644);
    }

    #[test]
    fn test_mkdir_and_read_dir() {
        let (tmp, fs) = setup();
        let dir = tmp.path().join("subdir");
        fs.mkdir(&dir, 0o755).unwrap();

        fs.write_file(&dir.join("a.txt"), b"a", None).unwrap();
        fs.write_file(&dir.join("b.txt"), b"b", None).unwrap();

        let entries = fs.read_dir(&dir).unwrap();
        assert_eq!(entries.len(), 2);

        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert!(names.contains(&b"a.txt".as_slice()));
        assert!(names.contains(&b"b.txt".as_slice()));
    }

    #[test]
    fn test_symlink() {
        let (tmp, fs) = setup();
        let target_path = tmp.path().join("target.txt");
        fs.write_file(&target_path, b"target", None).unwrap();

        let link_path = tmp.path().join("link.txt");
        fs.create_symlink(b"target.txt", &link_path).unwrap();

        let read_target = fs.read_link(&link_path).unwrap();
        assert_eq!(read_target, b"target.txt");

        let meta = fs.lstat(&link_path).unwrap();
        assert_eq!(meta.mode & crate::filelist::entry::S_IFMT, libc::S_IFLNK);
    }

    #[test]
    fn test_set_mtime() {
        let (tmp, fs) = setup();
        let path = tmp.path().join("timed.txt");
        fs.write_file(&path, b"data", None).unwrap();

        fs.set_mtime(&path, 1000000, 0).unwrap();
        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.mtime, 1000000);
    }

    #[test]
    fn test_remove_file() {
        let (tmp, fs) = setup();
        let path = tmp.path().join("remove_me.txt");
        fs.write_file(&path, b"gone", None).unwrap();
        assert!(fs.lexists(&path));

        fs.remove_file(&path).unwrap();
        assert!(!fs.lexists(&path));
    }

    #[test]
    fn test_not_found_error() {
        let fs = UnixFileSystem::new();
        let result = fs.read_file(Path::new("/nonexistent/path/file.txt"));
        assert!(matches!(result, Err(FsError::NotFound { .. })));
    }

    #[test]
    fn test_metadata_to_file_entry() {
        let (tmp, fs) = setup();
        let path = tmp.path().join("entry_test.txt");
        fs.write_file(&path, b"test data", Some(0o644)).unwrap();

        let meta = fs.stat(&path).unwrap();
        let entry = meta.to_file_entry(b"entry_test.txt".to_vec());
        assert_eq!(entry.name, b"entry_test.txt");
        assert_eq!(entry.len, 9);
        assert!(entry.is_file());
    }

    #[test]
    fn test_device_id() {
        let (tmp, fs) = setup();
        let dev = fs.device_id(tmp.path()).unwrap();
        assert!(dev > 0);
    }
}
