//! Unix filesystem implementation.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use ferrosync_types::error::FsError;

use crate::atomic_writer::{unique_tmp_name, AtomicFileWriter};
use crate::metadata::FileMetadata;
use crate::{DirEntry, FileSystem};

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
                source: std::sync::Arc::new(e),
            },
        }
    }

    fn metadata_from_std(m: &std::fs::Metadata) -> FileMetadata {
        FileMetadata {
            len: ferrosync_types::types::FileSize(m.len() as i64),
            mtime: ferrosync_types::types::UnixTimestamp(m.mtime()),
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
        let tmp_name = unique_tmp_name("");
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
        let ft = filetime::FileTime::from_unix_time(mtime, mtime_nsec);
        filetime::set_file_mtime(path, ft).map_err(|e| Self::map_io_err(path, e))
    }

    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| Self::map_io_err(path, e))
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

    fn list_xattrs(&self, path: &Path) -> Result<Vec<Vec<u8>>> {
        use std::os::unix::ffi::OsStrExt;
        match xattr::list(path) {
            Ok(names) => Ok(names.map(|n| n.as_bytes().to_vec()).collect()),
            Err(e) => Err(Self::map_io_err(path, e)),
        }
    }

    fn get_xattr(&self, path: &Path, name: &[u8]) -> Result<Option<Vec<u8>>> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let name = OsStr::from_bytes(name);
        match xattr::get(path, name) {
            Ok(v) => Ok(v),
            Err(e) => Err(Self::map_io_err(path, e)),
        }
    }

    fn set_xattr(&self, path: &Path, name: &[u8], value: &[u8]) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let name = OsStr::from_bytes(name);
        xattr::set(path, name, value).map_err(|e| Self::map_io_err(path, e))
    }

    fn remove_xattr(&self, path: &Path, name: &[u8]) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let name = OsStr::from_bytes(name);
        xattr::remove(path, name).map_err(|e| Self::map_io_err(path, e))
    }

    fn write_file_inplace(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        file.write_all(data)
            .map_err(|e| Self::map_io_err(path, e))?;

        if let Some(m) = mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
                .map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn write_file_sparse(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        const BLOCK_SIZE: usize = 4096;
        let mut offset = 0usize;

        while offset < data.len() {
            let end = (offset + BLOCK_SIZE).min(data.len());
            let block = &data[offset..end];

            if block.iter().all(|&b| b == 0) {
                file.seek(SeekFrom::Current(block.len() as i64))
                    .map_err(|e| Self::map_io_err(path, e))?;
            } else {
                file.write_all(block)
                    .map_err(|e| Self::map_io_err(path, e))?;
            }

            offset = end;
        }

        // If file ends with zeros, the seek left the length short; fix it.
        if !data.is_empty() {
            file.set_len(data.len() as u64)
                .map_err(|e| Self::map_io_err(path, e))?;
        }

        if let Some(m) = mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
                .map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn append_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        file.write_all(data)
            .map_err(|e| Self::map_io_err(path, e))?;

        if let Some(m) = mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
                .map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn hard_link(&self, target: &Path, link_path: &Path) -> Result<()> {
        std::fs::hard_link(target, link_path).map_err(|e| Self::map_io_err(link_path, e))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        std::fs::rename(from, to).map_err(|e| Self::map_io_err(from, e))
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        std::fs::copy(src, dst)
            .map_err(|e| Self::map_io_err(src, e))
            .map(|_| ())
    }

    fn map_file(&self, path: &Path) -> Result<crate::FileData> {
        let meta = std::fs::metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        let len = meta.len() as i64;
        if len == 0 {
            return Ok(crate::FileData::Empty);
        }
        if len < crate::MMAP_THRESHOLD {
            let data = std::fs::read(path).map_err(|e| Self::map_io_err(path, e))?;
            return Ok(crate::FileData::Vec(data));
        }
        let file = std::fs::File::open(path).map_err(|e| Self::map_io_err(path, e))?;
        // SAFETY: The file is not truncated while mapped. In rsync's protocol,
        // the sender reads its own source files (not modified during transfer),
        // and the receiver's basis file is overwritten via temp + atomic rename.
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => Ok(crate::FileData::Mmap(mmap)),
            Err(_) => {
                // Fallback to read if mmap fails (e.g. some FUSE mounts).
                let data = std::fs::read(path).map_err(|e| Self::map_io_err(path, e))?;
                Ok(crate::FileData::Vec(data))
            }
        }
    }

    fn read_file_stream(&self, path: &Path) -> Result<Box<dyn std::io::Read + Send>> {
        let file = std::fs::File::open(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(Box::new(std::io::BufReader::new(file)))
    }

    fn write_file_stream(
        &self,
        path: &Path,
        mode: Option<u32>,
    ) -> Result<Box<dyn std::io::Write + Send>> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let tmp_name = unique_tmp_name(".stream");
        let tmp_path = parent.join(&tmp_name);
        let dest_path = path.to_path_buf();

        let file = std::fs::File::create(&tmp_path).map_err(|e| Self::map_io_err(&tmp_path, e))?;

        fn set_unix_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        }

        Ok(Box::new(AtomicFileWriter::new(
            file,
            tmp_path,
            dest_path,
            mode,
            set_unix_permissions,
        )))
    }

    fn write_file_inplace_stream(
        &self,
        path: &Path,
        mode: Option<u32>,
    ) -> Result<Box<dyn std::io::Write + Send>> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;
        if let Some(m) = mode {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(m));
        }
        Ok(Box::new(std::io::BufWriter::new(file)))
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
        assert_eq!(
            meta.mode & ferrosync_types::mode::S_IFMT,
            ferrosync_types::mode::S_IFLNK
        );
    }

    #[test]
    fn test_set_mtime() {
        let (tmp, fs) = setup();
        let path = tmp.path().join("timed.txt");
        fs.write_file(&path, b"data", None).unwrap();

        fs.set_mtime(&path, 1000000, 0).unwrap();
        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.mtime, ferrosync_types::types::UnixTimestamp(1000000));
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
        assert_eq!(entry.len, ferrosync_types::types::FileSize(9));
        assert!(entry.is_file());
    }

    #[test]
    fn test_device_id() {
        let (tmp, fs) = setup();
        let dev = fs.device_id(tmp.path()).unwrap();
        assert!(dev > 0);
    }

    #[test]
    fn test_read_file_stream() {
        use std::io::Read;
        let (tmp, fs) = setup();
        let path = tmp.path().join("stream_read.txt");
        fs.write_file(&path, b"streamed content", None).unwrap();

        let mut reader = fs.read_file_stream(&path).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"streamed content");
    }

    #[test]
    fn test_write_file_stream() {
        use std::io::Write;
        let (tmp, fs) = setup();
        let path = tmp.path().join("stream_write.txt");

        {
            let mut writer = fs.write_file_stream(&path, Some(0o644)).unwrap();
            writer.write_all(b"hello ").unwrap();
            writer.write_all(b"world").unwrap();
            writer.flush().unwrap();
        }
        // After drop, file should be atomically renamed.
        let data = fs.read_file(&path).unwrap();
        assert_eq!(data, b"hello world");

        let meta = fs.stat(&path).unwrap();
        assert_eq!(meta.mode & 0o777, 0o644);
    }

    #[test]
    fn test_stream_roundtrip() {
        use std::io::{Read, Write};
        let (tmp, fs) = setup();
        let path = tmp.path().join("roundtrip.bin");
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        {
            let mut writer = fs.write_file_stream(&path, None).unwrap();
            writer.write_all(&data).unwrap();
            writer.flush().unwrap();
        }

        let mut reader = fs.read_file_stream(&path).unwrap();
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    }
}
