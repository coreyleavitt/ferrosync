//! Fake-super filesystem wrapper (`--fake-super`).
//!
//! Stores privileged metadata (uid, gid, mode, device numbers) as the
//! `user.rsync.%stat` extended attribute instead of using real syscalls.
//! This allows non-root users to preserve ownership and special permissions.

use std::io::{Read, Write};
use std::path::Path;

use crate::error::FsError;
use crate::fs::{DirEntry, FileData, FileMetadata, FileSystem};

type Result<T> = std::result::Result<T, FsError>;

/// Name of the extended attribute used to store fake-super metadata.
const FAKE_SUPER_XATTR: &[u8] = b"user.rsync.%stat";

/// `FileSystem` wrapper implementing rsync's `--fake-super` mode.
///
/// Instead of calling real `chown`/`chmod` syscalls (which require root),
/// privileged metadata is stored as the `user.rsync.%stat` extended attribute.
/// The xattr format is: `%o %u:%g %M:%m` where `%o` is the octal file mode,
/// `%u:%g` is uid:gid, and `%M:%m` is device major:minor.
pub struct FakeSuperFs {
    inner: Box<dyn FileSystem>,
}

impl FakeSuperFs {
    /// Wrap an existing filesystem with fake-super behaviour.
    pub fn new(inner: Box<dyn FileSystem>) -> Self {
        Self { inner }
    }

    /// Parse the `user.rsync.%stat` xattr value into (mode, uid, gid, rdev).
    fn parse_stat(value: &[u8]) -> Option<(u32, u32, u32, u64)> {
        let s = std::str::from_utf8(value).ok()?;
        let mut parts = s.split_whitespace();

        let mode = u32::from_str_radix(parts.next()?, 8).ok()?;

        let ug = parts.next()?;
        let (uid_s, gid_s) = ug.split_once(':')?;
        let uid = uid_s.parse::<u32>().ok()?;
        let gid = gid_s.parse::<u32>().ok()?;

        let dev = parts.next().unwrap_or("0:0");
        let (maj_s, min_s) = dev.split_once(':').unwrap_or(("0", "0"));
        let major = maj_s.parse::<u64>().ok()?;
        let minor = min_s.parse::<u64>().ok()?;
        let rdev = (major << 8) | minor;

        Some((mode, uid, gid, rdev))
    }

    /// Format metadata into the `user.rsync.%stat` xattr value.
    fn format_stat(mode: u32, uid: u32, gid: u32, rdev: u64) -> Vec<u8> {
        let major = rdev >> 8;
        let minor = rdev & 0xFF;
        format!("{:o} {uid}:{gid} {major}:{minor}", mode).into_bytes()
    }

    /// Read and parse the fake-super xattr, returning `(mode, uid, gid, rdev)`.
    fn read_fake_stat(&self, path: &Path) -> Option<(u32, u32, u32, u64)> {
        let value = self.inner.get_xattr(path, FAKE_SUPER_XATTR).ok()??;
        Self::parse_stat(&value)
    }

    /// Overlay fake-super metadata onto real metadata when the xattr is present.
    fn overlay_metadata(&self, path: &Path, mut meta: FileMetadata) -> FileMetadata {
        if let Some((mode, uid, gid, rdev)) = self.read_fake_stat(path) {
            meta.mode = mode;
            meta.uid = uid;
            meta.gid = gid;
            meta.rdev = rdev;
        }
        meta
    }

    /// Read the current fake-super stat for a path, falling back to the real
    /// metadata if the xattr does not exist yet.
    fn read_or_init_stat(&self, path: &Path) -> Result<(u32, u32, u32, u64)> {
        if let Some(stat) = self.read_fake_stat(path) {
            Ok(stat)
        } else {
            let meta = self.inner.lstat(path)?;
            Ok((meta.mode, meta.uid, meta.gid, meta.rdev))
        }
    }
}

impl FileSystem for FakeSuperFs {
    fn lstat(&self, path: &Path) -> Result<FileMetadata> {
        let meta = self.inner.lstat(path)?;
        Ok(self.overlay_metadata(path, meta))
    }

    fn stat(&self, path: &Path) -> Result<FileMetadata> {
        let meta = self.inner.stat(path)?;
        Ok(self.overlay_metadata(path, meta))
    }

    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        self.inner.read_link(path)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        self.inner.read_file(path)
    }

    fn write_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.inner.write_file(path, data, mode)
    }

    fn mkdir(&self, path: &Path, mode: u32) -> Result<()> {
        // Create with safe permissions, then store the intended mode in xattr.
        self.inner.mkdir(path, 0o755)?;
        let stat_val = Self::format_stat(mode | 0o040000, 0, 0, 0);
        // Best-effort: if xattr write fails the directory still exists.
        let _ = self.inner.set_xattr(path, FAKE_SUPER_XATTR, &stat_val);
        Ok(())
    }

    fn create_symlink(&self, target: &[u8], link_path: &Path) -> Result<()> {
        self.inner.create_symlink(target, link_path)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        // Read current fake stat (or initialise from real metadata) to
        // preserve uid/gid/rdev while updating the mode.
        let (_, uid, gid, rdev) = self.read_or_init_stat(path)?;

        // Store the intended mode in the xattr.
        let stat_val = Self::format_stat(mode, uid, gid, rdev);
        self.inner.set_xattr(path, FAKE_SUPER_XATTR, &stat_val)?;

        // Apply a safe subset of permissions to the real file.
        // Strip setuid/setgid/sticky bits; keep only rwx for owner/group/other.
        let safe_mode = mode & 0o7777; // permission bits only
        let real_mode = safe_mode & 0o755; // remove setuid/setgid/sticky
        self.inner.set_permissions(path, real_mode)
    }

    fn set_mtime(&self, path: &Path, mtime: i64, mtime_nsec: u32) -> Result<()> {
        self.inner.set_mtime(path, mtime, mtime_nsec)
    }

    #[cfg(unix)]
    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        // Do not call real chown -- store ownership in the xattr instead.
        let (mode, _, _, rdev) = self.read_or_init_stat(path)?;
        let stat_val = Self::format_stat(mode, uid, gid, rdev);
        self.inner.set_xattr(path, FAKE_SUPER_XATTR, &stat_val)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.inner.remove_file(path)
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.inner.remove_dir(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        self.inner.read_dir(path)
    }

    fn lexists(&self, path: &Path) -> bool {
        self.inner.lexists(path)
    }

    #[cfg(unix)]
    fn device_id(&self, path: &Path) -> Result<u64> {
        self.inner.device_id(path)
    }

    #[cfg(unix)]
    fn list_xattrs(&self, path: &Path) -> Result<Vec<Vec<u8>>> {
        let all = self.inner.list_xattrs(path)?;
        // Hide our internal xattr from external callers.
        Ok(all
            .into_iter()
            .filter(|name| name.as_slice() != FAKE_SUPER_XATTR)
            .collect())
    }

    #[cfg(unix)]
    fn get_xattr(&self, path: &Path, name: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.get_xattr(path, name)
    }

    #[cfg(unix)]
    fn set_xattr(&self, path: &Path, name: &[u8], value: &[u8]) -> Result<()> {
        self.inner.set_xattr(path, name, value)
    }

    #[cfg(unix)]
    fn remove_xattr(&self, path: &Path, name: &[u8]) -> Result<()> {
        self.inner.remove_xattr(path, name)
    }

    fn write_file_inplace(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.inner.write_file_inplace(path, data, mode)
    }

    fn write_file_sparse(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.inner.write_file_sparse(path, data, mode)
    }

    fn append_file(&self, path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.inner.append_file(path, data, mode)
    }

    fn hard_link(&self, target: &Path, link_path: &Path) -> Result<()> {
        self.inner.hard_link(target, link_path)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.inner.rename(from, to)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        self.inner.copy_file(src, dst)
    }

    fn map_file(&self, path: &Path) -> Result<FileData> {
        self.inner.map_file(path)
    }

    fn read_file_stream(&self, path: &Path) -> Result<Box<dyn Read + Send>> {
        self.inner.read_file_stream(path)
    }

    fn write_file_stream(&self, path: &Path, mode: Option<u32>) -> Result<Box<dyn Write + Send>> {
        self.inner.write_file_stream(path, mode)
    }

    fn write_file_inplace_stream(
        &self,
        path: &Path,
        mode: Option<u32>,
    ) -> Result<Box<dyn Write + Send>> {
        self.inner.write_file_inplace_stream(path, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stat() {
        let val = b"100644 1000:1000 0:0";
        let (mode, uid, gid, rdev) = FakeSuperFs::parse_stat(val).unwrap();
        assert_eq!(mode, 0o100644);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
        assert_eq!(rdev, 0);
    }

    #[test]
    fn test_parse_stat_no_device() {
        let val = b"100755 0:0";
        let (mode, uid, gid, rdev) = FakeSuperFs::parse_stat(val).unwrap();
        assert_eq!(mode, 0o100755);
        assert_eq!(uid, 0);
        assert_eq!(gid, 0);
        assert_eq!(rdev, 0);
    }

    #[test]
    fn test_format_stat() {
        let val = FakeSuperFs::format_stat(0o100644, 1000, 1000, 0);
        assert_eq!(std::str::from_utf8(&val).unwrap(), "100644 1000:1000 0:0");
    }

    #[test]
    fn test_roundtrip() {
        let mode = 0o100755;
        let uid = 0;
        let gid = 0;
        let rdev = (8u64 << 8) | 1;
        let val = FakeSuperFs::format_stat(mode, uid, gid, rdev);
        let (m, u, g, r) = FakeSuperFs::parse_stat(&val).unwrap();
        assert_eq!(m, mode);
        assert_eq!(u, uid);
        assert_eq!(g, gid);
        assert_eq!(r, rdev);
    }

    #[test]
    fn test_roundtrip_directory_mode() {
        let mode = 0o040755;
        let uid = 1000;
        let gid = 1000;
        let rdev = 0;
        let val = FakeSuperFs::format_stat(mode, uid, gid, rdev);
        let (m, u, g, r) = FakeSuperFs::parse_stat(&val).unwrap();
        assert_eq!(m, mode);
        assert_eq!(u, uid);
        assert_eq!(g, gid);
        assert_eq!(r, rdev);
    }

    #[test]
    fn test_parse_stat_invalid_utf8() {
        let val = &[0xFF, 0xFE, 0xFD];
        assert!(FakeSuperFs::parse_stat(val).is_none());
    }

    #[test]
    fn test_parse_stat_malformed() {
        assert!(FakeSuperFs::parse_stat(b"garbage").is_none());
        assert!(FakeSuperFs::parse_stat(b"").is_none());
        assert!(FakeSuperFs::parse_stat(b"100644").is_none());
        assert!(FakeSuperFs::parse_stat(b"100644 bad").is_none());
    }
}
