//! Windows filesystem implementation.

use std::fs::{self, FileTimes, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::FsError;
use crate::filelist::entry::{S_IFDIR, S_IFREG, WIRE_S_IFLNK};

use super::atomic_writer::{unique_tmp_name, AtomicFileWriter};
use super::metadata::FileMetadata;
use super::{DirEntry, FileSystem};

type Result<T> = std::result::Result<T, FsError>;

/// Windows FILETIME ticks per second (100ns intervals).
const WINDOWS_TICK: u64 = 10_000_000;

/// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01).
const SEC_TO_UNIX_EPOCH: i64 = 11_644_473_600;

/// Windows file attribute: read-only.
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;

/// Windows file attribute: directory.
#[cfg(test)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// Windows file attribute: reparse point (symlinks, junctions).
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Standard Windows filesystem implementation.
#[derive(Debug, Default)]
pub struct WindowsFileSystem;

impl WindowsFileSystem {
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

    /// Convert Windows FILETIME (100ns since 1601-01-01) to Unix timestamp.
    fn filetime_to_unix(ft: u64) -> (i64, u32) {
        let total_secs = (ft / WINDOWS_TICK) as i64 - SEC_TO_UNIX_EPOCH;
        let nsec = ((ft % WINDOWS_TICK) * 100) as u32;
        (total_secs, nsec)
    }

    /// Convert Unix timestamp to `SystemTime` for `FileTimes`.
    fn unix_to_system_time(secs: i64, nsec: u32) -> SystemTime {
        if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs as u64, nsec)
        } else {
            UNIX_EPOCH - Duration::new((-secs) as u64, 0) + Duration::new(0, nsec)
        }
    }

    /// Synthesize a Unix-style mode from Windows file attributes.
    ///
    /// Mapping:
    /// - Directory + read-only -> 0o040555
    /// - Directory + writable  -> 0o040755
    /// - File + read-only      -> 0o100444
    /// - File + writable       -> 0o100644
    /// - Symlink (reparse)     -> 0o120777
    fn mode_from_attrs(attrs: u32, is_dir: bool) -> u32 {
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return WIRE_S_IFLNK | 0o777;
        }

        let readonly = attrs & FILE_ATTRIBUTE_READONLY != 0;

        if is_dir {
            S_IFDIR | if readonly { 0o555 } else { 0o755 }
        } else {
            S_IFREG | if readonly { 0o444 } else { 0o644 }
        }
    }

    fn metadata_from_std(m: &fs::Metadata) -> FileMetadata {
        let (mtime, mtime_nsec) = Self::filetime_to_unix(m.last_write_time());
        let attrs = m.file_attributes();
        let is_dir = m.is_dir();

        FileMetadata {
            len: m.len() as i64,
            mtime,
            mtime_nsec,
            mode: Self::mode_from_attrs(attrs, is_dir),
            uid: 0,
            gid: 0,
            rdev: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
        }
    }
}

impl FileSystem for WindowsFileSystem {
    fn lstat(&self, path: &Path) -> Result<FileMetadata> {
        let m = fs::symlink_metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(Self::metadata_from_std(&m))
    }

    fn stat(&self, path: &Path) -> Result<FileMetadata> {
        let m = fs::metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(Self::metadata_from_std(&m))
    }

    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        let target = fs::read_link(path).map_err(|e| Self::map_io_err(path, e))?;
        // Convert OsString to bytes via platform-encoded form (WTF-8 on Windows).
        Ok(target.as_os_str().as_encoded_bytes().to_vec())
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        fs::read(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn write_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let tmp_name = unique_tmp_name("");
        let tmp_path = parent.join(&tmp_name);

        fs::write(&tmp_path, data).map_err(|e| Self::map_io_err(&tmp_path, e))?;

        if let Some(m) = mode {
            let readonly = m & 0o222 == 0;
            let mut perms = fs::metadata(&tmp_path)
                .map_err(|e| Self::map_io_err(&tmp_path, e))?
                .permissions();
            perms.set_readonly(readonly);
            fs::set_permissions(&tmp_path, perms).map_err(|e| Self::map_io_err(&tmp_path, e))?;
        }

        fs::rename(&tmp_path, path).map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn mkdir(&self, path: &Path, mode: u32) -> Result<()> {
        fs::create_dir_all(path).map_err(|e| Self::map_io_err(path, e))?;
        // Apply read-only if no write bits.
        let readonly = mode & 0o222 == 0;
        let mut perms = fs::metadata(path)
            .map_err(|e| Self::map_io_err(path, e))?
            .permissions();
        perms.set_readonly(readonly);
        fs::set_permissions(path, perms).map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn create_symlink(&self, target: &[u8], link_path: &Path) -> Result<()> {
        // Remove existing symlink if present.
        if link_path.symlink_metadata().is_ok() {
            fs::remove_file(link_path).map_err(|e| Self::map_io_err(link_path, e))?;
        }

        // Parse target bytes as UTF-8 (Windows paths should be valid Unicode).
        let target_str = String::from_utf8_lossy(target);
        let target_path = Path::new(target_str.as_ref());

        // Choose file or directory symlink based on target type.
        // If the target doesn't exist or we can't stat it, default to file symlink.
        let is_dir = target_path.metadata().map(|m| m.is_dir()).unwrap_or(false);

        if is_dir {
            std::os::windows::fs::symlink_dir(target_path, link_path)
        } else {
            std::os::windows::fs::symlink_file(target_path, link_path)
        }
        .map_err(|e| Self::map_io_err(link_path, e))?;

        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        let readonly = mode & 0o222 == 0;
        let mut perms = fs::metadata(path)
            .map_err(|e| Self::map_io_err(path, e))?
            .permissions();
        perms.set_readonly(readonly);
        fs::set_permissions(path, perms).map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    fn set_mtime(&self, path: &Path, mtime: i64, mtime_nsec: u32) -> Result<()> {
        let modified = Self::unix_to_system_time(mtime, mtime_nsec);
        let times = FileTimes::new().set_modified(modified);

        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;
        file.set_times(times)
            .map_err(|e| Self::map_io_err(path, e))?;
        Ok(())
    }

    // set_owner is gated behind #[cfg(unix)] in the trait -- not available on Windows.

    fn remove_file(&self, path: &Path) -> Result<()> {
        fs::remove_file(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        fs::remove_dir(path).map_err(|e| Self::map_io_err(path, e))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        let rd = fs::read_dir(path).map_err(|e| Self::map_io_err(path, e))?;

        for entry in rd {
            let entry = entry.map_err(|e| Self::map_io_err(path, e))?;
            let name = entry.file_name().as_encoded_bytes().to_vec();
            let meta = fs::symlink_metadata(entry.path())
                .map_err(|e| Self::map_io_err(&entry.path(), e))?;
            entries.push(DirEntry {
                name,
                metadata: Self::metadata_from_std(&meta),
            });
        }

        Ok(entries)
    }

    fn lexists(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    // device_id is gated behind #[cfg(unix)] in the trait -- not available on Windows.

    fn write_file_inplace(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        file.write_all(data)
            .map_err(|e| Self::map_io_err(path, e))?;

        if let Some(m) = mode {
            let readonly = m & 0o222 == 0;
            let mut perms = fs::metadata(path)
                .map_err(|e| Self::map_io_err(path, e))?
                .permissions();
            perms.set_readonly(readonly);
            fs::set_permissions(path, perms).map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn write_file_sparse(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        // Seek-based sparse optimization. On NTFS this creates gaps but doesn't
        // automatically mark the file as sparse (that requires FSCTL_SET_SPARSE).
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

        if !data.is_empty() {
            file.set_len(data.len() as u64)
                .map_err(|e| Self::map_io_err(path, e))?;
        }

        if let Some(m) = mode {
            let readonly = m & 0o222 == 0;
            let mut perms = fs::metadata(path)
                .map_err(|e| Self::map_io_err(path, e))?
                .permissions();
            perms.set_readonly(readonly);
            fs::set_permissions(path, perms).map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn append_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Self::map_io_err(path, e))?;

        file.write_all(data)
            .map_err(|e| Self::map_io_err(path, e))?;

        if let Some(m) = mode {
            let readonly = m & 0o222 == 0;
            let mut perms = fs::metadata(path)
                .map_err(|e| Self::map_io_err(path, e))?
                .permissions();
            perms.set_readonly(readonly);
            fs::set_permissions(path, perms).map_err(|e| Self::map_io_err(path, e))?;
        }
        Ok(())
    }

    fn hard_link(&self, target: &Path, link_path: &Path) -> Result<()> {
        fs::hard_link(target, link_path).map_err(|e| Self::map_io_err(link_path, e))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        fs::rename(from, to).map_err(|e| Self::map_io_err(from, e))
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        fs::copy(src, dst)
            .map_err(|e| Self::map_io_err(src, e))
            .map(|_| ())
    }

    fn map_file(&self, path: &Path) -> Result<super::FileData> {
        let meta = fs::metadata(path).map_err(|e| Self::map_io_err(path, e))?;
        let len = meta.len() as i64;
        if len == 0 {
            return Ok(super::FileData::Empty);
        }
        if len < super::MMAP_THRESHOLD {
            let data = fs::read(path).map_err(|e| Self::map_io_err(path, e))?;
            return Ok(super::FileData::Vec(data));
        }
        let file = fs::File::open(path).map_err(|e| Self::map_io_err(path, e))?;
        // SAFETY: The file is not truncated while mapped. In rsync's protocol,
        // the sender reads its own source files (not modified during transfer),
        // and the receiver's basis file is overwritten via temp + atomic rename.
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => Ok(super::FileData::Mmap(mmap)),
            Err(_) => {
                let data = fs::read(path).map_err(|e| Self::map_io_err(path, e))?;
                Ok(super::FileData::Vec(data))
            }
        }
    }

    fn read_file_stream(&self, path: &Path) -> Result<Box<dyn std::io::Read + Send>> {
        let file = fs::File::open(path).map_err(|e| Self::map_io_err(path, e))?;
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

        let file = fs::File::create(&tmp_path).map_err(|e| Self::map_io_err(&tmp_path, e))?;

        fn set_windows_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
            let readonly = mode & 0o222 == 0;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_readonly(readonly);
            fs::set_permissions(path, perms)
        }

        Ok(Box::new(AtomicFileWriter::new(
            file,
            tmp_path,
            dest_path,
            mode,
            set_windows_permissions,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_unix_epoch() {
        // Windows FILETIME for Unix epoch (1970-01-01 00:00:00 UTC).
        // = 11644473600 * 10_000_000
        let ft: u64 = 116_444_736_000_000_000;
        let (secs, nsec) = WindowsFileSystem::filetime_to_unix(ft);
        assert_eq!(secs, 0);
        assert_eq!(nsec, 0);
    }

    #[test]
    fn test_filetime_to_unix_with_subseconds() {
        // Unix epoch + 1.5 seconds
        let ft: u64 = 116_444_736_000_000_000 + 15_000_000;
        let (secs, nsec) = WindowsFileSystem::filetime_to_unix(ft);
        assert_eq!(secs, 1);
        assert_eq!(nsec, 500_000_000);
    }

    #[test]
    fn test_filetime_to_unix_2024() {
        // 2024-01-01 00:00:00 UTC = 1704067200 Unix
        // As Windows FILETIME: (1704067200 + 11644473600) * 10_000_000
        let unix_secs: i64 = 1_704_067_200;
        let ft = ((unix_secs + SEC_TO_UNIX_EPOCH) as u64) * WINDOWS_TICK;
        let (secs, nsec) = WindowsFileSystem::filetime_to_unix(ft);
        assert_eq!(secs, unix_secs);
        assert_eq!(nsec, 0);
    }

    #[test]
    fn test_mode_from_attrs_regular_file() {
        let mode = WindowsFileSystem::mode_from_attrs(0, false);
        assert_eq!(mode, S_IFREG | 0o644);
    }

    #[test]
    fn test_mode_from_attrs_readonly_file() {
        let mode = WindowsFileSystem::mode_from_attrs(FILE_ATTRIBUTE_READONLY, false);
        assert_eq!(mode, S_IFREG | 0o444);
    }

    #[test]
    fn test_mode_from_attrs_directory() {
        let mode = WindowsFileSystem::mode_from_attrs(FILE_ATTRIBUTE_DIRECTORY, true);
        assert_eq!(mode, S_IFDIR | 0o755);
    }

    #[test]
    fn test_mode_from_attrs_readonly_directory() {
        let mode = WindowsFileSystem::mode_from_attrs(
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY,
            true,
        );
        assert_eq!(mode, S_IFDIR | 0o555);
    }

    #[test]
    fn test_mode_from_attrs_reparse_point() {
        let mode = WindowsFileSystem::mode_from_attrs(FILE_ATTRIBUTE_REPARSE_POINT, false);
        assert_eq!(mode, WIRE_S_IFLNK | 0o777);
    }

    #[test]
    fn test_unix_to_system_time_positive() {
        let t = WindowsFileSystem::unix_to_system_time(1_000_000, 0);
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 1_000_000);
        assert_eq!(dur.subsec_nanos(), 0);
    }

    #[test]
    fn test_unix_to_system_time_with_nanos() {
        let t = WindowsFileSystem::unix_to_system_time(100, 500_000_000);
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 100);
        assert_eq!(dur.subsec_nanos(), 500_000_000);
    }
}
