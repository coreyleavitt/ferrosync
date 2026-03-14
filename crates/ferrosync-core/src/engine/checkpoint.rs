//! Block-level resume via checkpoint files.
//!
//! When a transfer is interrupted, a checkpoint file records which blocks
//! have been successfully written. On resume, only the remaining blocks
//! need to be transferred.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::FsError;

type Result<T> = std::result::Result<T, FsError>;

/// Magic bytes identifying a ferrosync checkpoint file.
const MAGIC: &[u8; 8] = b"FSCKPT\x00\x01";

/// Current checkpoint format version.
const VERSION: u8 = 1;

/// Metadata for resuming a partially-transferred file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The file being transferred (relative path).
    pub file_path: PathBuf,
    /// Expected total file size in bytes.
    pub file_size: u64,
    /// Block size used for this transfer.
    pub block_size: usize,
    /// Bitmap of which blocks have been successfully written.
    pub completed_blocks: Vec<bool>,
    /// Checksum seed used for this transfer.
    pub checksum_seed: i32,
    /// Unix timestamp when this checkpoint was created.
    pub timestamp: i64,
}

impl Checkpoint {
    /// Compute the total number of blocks for the file.
    pub fn total_blocks(&self) -> usize {
        if self.block_size == 0 {
            return 0;
        }
        (self.file_size as usize).div_ceil(self.block_size)
    }

    /// Create a new checkpoint with no blocks completed.
    pub fn new(
        file_path: PathBuf,
        file_size: u64,
        block_size: usize,
        checksum_seed: i32,
        timestamp: i64,
    ) -> Self {
        let total = if block_size == 0 {
            0
        } else {
            (file_size as usize).div_ceil(block_size)
        };
        Self {
            file_path,
            file_size,
            block_size,
            completed_blocks: vec![false; total],
            checksum_seed,
            timestamp,
        }
    }

    /// Return a `ResumeState` view of this checkpoint.
    pub fn resume_state(&mut self) -> ResumeState<'_> {
        ResumeState {
            completed_blocks: &mut self.completed_blocks,
        }
    }
}

/// Mutable view into a checkpoint's block completion state.
#[derive(Debug)]
pub struct ResumeState<'a> {
    completed_blocks: &'a mut Vec<bool>,
}

impl<'a> ResumeState<'a> {
    /// Number of blocks still remaining.
    pub fn blocks_remaining(&self) -> usize {
        self.completed_blocks.iter().filter(|&&b| !b).count()
    }

    /// Whether the given block index has been completed.
    pub fn is_block_done(&self, idx: usize) -> bool {
        self.completed_blocks.get(idx).copied().unwrap_or(false)
    }

    /// Mark a block as completed.
    pub fn mark_block_done(&mut self, idx: usize) {
        if let Some(slot) = self.completed_blocks.get_mut(idx) {
            *slot = true;
        }
    }

    /// Whether all blocks are done.
    pub fn all_done(&self) -> bool {
        self.completed_blocks.iter().all(|&b| b)
    }
}

/// Manages checkpoint files on disk.
pub struct CheckpointFile;

impl CheckpointFile {
    /// Derive the checkpoint filename for a given transfer file.
    fn ckpt_path(dir: &Path, filename: &str) -> PathBuf {
        dir.join(format!(".ferrosync.ckpt.{}", filename))
    }

    /// Serialize a checkpoint to bytes.
    fn serialize(checkpoint: &Checkpoint) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic + version
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);

        // file_path as UTF-8 bytes (length-prefixed)
        let path_bytes = checkpoint
            .file_path
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&path_bytes);

        // file_size
        buf.extend_from_slice(&checkpoint.file_size.to_le_bytes());

        // block_size
        buf.extend_from_slice(&(checkpoint.block_size as u64).to_le_bytes());

        // checksum_seed
        buf.extend_from_slice(&checkpoint.checksum_seed.to_le_bytes());

        // timestamp
        buf.extend_from_slice(&checkpoint.timestamp.to_le_bytes());

        // completed_blocks: count then packed bits
        let count = checkpoint.completed_blocks.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        // Pack bools into bytes (8 per byte)
        let byte_count = (count as usize).div_ceil(8);
        for byte_idx in 0..byte_count {
            let mut byte = 0u8;
            for bit in 0..8 {
                let idx = byte_idx * 8 + bit;
                if idx < count as usize && checkpoint.completed_blocks[idx] {
                    byte |= 1 << bit;
                }
            }
            buf.push(byte);
        }

        buf
    }

    /// Deserialize a checkpoint from bytes.
    fn deserialize(data: &[u8]) -> Result<Checkpoint> {
        let err = || FsError::Io {
            path: PathBuf::from("<checkpoint>"),
            source: Arc::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt checkpoint file",
            )),
        };

        if data.len() < MAGIC.len() + 1 {
            return Err(err());
        }

        let mut pos = 0;

        // Magic
        if &data[pos..pos + MAGIC.len()] != MAGIC.as_slice() {
            return Err(err());
        }
        pos += MAGIC.len();

        // Version
        let version = data[pos];
        if version != VERSION {
            return Err(err());
        }
        pos += 1;

        // file_path
        if pos + 4 > data.len() {
            return Err(err());
        }
        let path_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + path_len > data.len() {
            return Err(err());
        }
        let file_path = PathBuf::from(
            String::from_utf8(data[pos..pos + path_len].to_vec()).map_err(|_| err())?,
        );
        pos += path_len;

        // file_size
        if pos + 8 > data.len() {
            return Err(err());
        }
        let file_size = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // block_size
        if pos + 8 > data.len() {
            return Err(err());
        }
        let block_size = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        // checksum_seed
        if pos + 4 > data.len() {
            return Err(err());
        }
        let checksum_seed = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // timestamp
        if pos + 8 > data.len() {
            return Err(err());
        }
        let timestamp = i64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // completed_blocks
        if pos + 4 > data.len() {
            return Err(err());
        }
        let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        let byte_count = count.div_ceil(8);
        if pos + byte_count > data.len() {
            return Err(err());
        }

        let mut completed_blocks = Vec::with_capacity(count);
        for i in 0..count {
            let byte_idx = i / 8;
            let bit = i % 8;
            let done = (data[pos + byte_idx] >> bit) & 1 == 1;
            completed_blocks.push(done);
        }

        Ok(Checkpoint {
            file_path,
            file_size,
            block_size,
            completed_blocks,
            checksum_seed,
            timestamp,
        })
    }

    /// Save a checkpoint to the given directory.
    pub fn save(dir: &Path, checkpoint: &Checkpoint) -> Result<()> {
        let filename = checkpoint
            .file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());
        let path = Self::ckpt_path(dir, &filename);
        let data = Self::serialize(checkpoint);
        std::fs::write(&path, &data).map_err(|e| FsError::Io {
            path: path.clone(),
            source: Arc::new(e),
        })
    }

    /// Load a checkpoint from the given directory, if it exists.
    pub fn load(dir: &Path, filename: &str) -> Result<Option<Checkpoint>> {
        let path = Self::ckpt_path(dir, filename);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(Self::deserialize(&data)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(FsError::Io {
                path,
                source: Arc::new(e),
            }),
        }
    }

    /// Remove a checkpoint file after successful transfer.
    pub fn remove(dir: &Path, filename: &str) -> Result<()> {
        let path = Self::ckpt_path(dir, filename);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // already gone
            Err(e) => Err(FsError::Io {
                path,
                source: Arc::new(e),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut ckpt = Checkpoint::new(
            PathBuf::from("test_file.dat"),
            1048576, // 1 MiB
            8192,    // 8 KiB blocks
            42,
            1700000000,
        );
        assert_eq!(ckpt.total_blocks(), 128);

        // Mark some blocks done.
        {
            let mut state = ckpt.resume_state();
            state.mark_block_done(0);
            state.mark_block_done(5);
            state.mark_block_done(127);
        }

        CheckpointFile::save(dir.path(), &ckpt).unwrap();

        let loaded = CheckpointFile::load(dir.path(), "test_file.dat")
            .unwrap()
            .expect("checkpoint should exist");

        assert_eq!(loaded, ckpt);
        assert_eq!(loaded.file_path, PathBuf::from("test_file.dat"));
        assert_eq!(loaded.file_size, 1048576);
        assert_eq!(loaded.block_size, 8192);
        assert_eq!(loaded.checksum_seed, 42);
        assert_eq!(loaded.timestamp, 1700000000);
        assert!(loaded.completed_blocks[0]);
        assert!(!loaded.completed_blocks[1]);
        assert!(loaded.completed_blocks[5]);
        assert!(loaded.completed_blocks[127]);
    }

    #[test]
    fn test_partial_completion_tracking() {
        let mut ckpt = Checkpoint::new(PathBuf::from("data.bin"), 40000, 10000, 0, 0);
        assert_eq!(ckpt.total_blocks(), 4);

        {
            let mut state = ckpt.resume_state();
            assert_eq!(state.blocks_remaining(), 4);
            assert!(!state.all_done());

            state.mark_block_done(0);
            state.mark_block_done(2);
            assert_eq!(state.blocks_remaining(), 2);
            assert!(state.is_block_done(0));
            assert!(!state.is_block_done(1));
            assert!(state.is_block_done(2));
            assert!(!state.is_block_done(3));
            assert!(!state.all_done());

            state.mark_block_done(1);
            state.mark_block_done(3);
            assert_eq!(state.blocks_remaining(), 0);
            assert!(state.all_done());
        }
    }

    #[test]
    fn test_cleanup_after_success() {
        let dir = tempfile::tempdir().unwrap();
        let ckpt = Checkpoint::new(PathBuf::from("done.txt"), 100, 50, 0, 0);

        CheckpointFile::save(dir.path(), &ckpt).unwrap();
        assert!(CheckpointFile::load(dir.path(), "done.txt")
            .unwrap()
            .is_some());

        CheckpointFile::remove(dir.path(), "done.txt").unwrap();
        assert!(CheckpointFile::load(dir.path(), "done.txt")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_remove_nonexistent_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        // Removing a checkpoint that doesn't exist should succeed.
        CheckpointFile::remove(dir.path(), "no_such_file.txt").unwrap();
    }

    #[test]
    fn test_load_missing_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let result = CheckpointFile::load(dir.path(), "missing.dat").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_corrupt_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".ferrosync.ckpt.bad.dat");
        std::fs::write(&path, b"not a checkpoint").unwrap();

        let result = CheckpointFile::load(dir.path(), "bad.dat");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_checkpoint() {
        let dir = tempfile::tempdir().unwrap();

        // Write valid magic but truncated data.
        let path = dir.path().join(".ferrosync.ckpt.trunc.dat");
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(VERSION);
        // No more data -- should fail during deserialization.
        std::fs::write(&path, &data).unwrap();

        let result = CheckpointFile::load(dir.path(), "trunc.dat");
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_size_file_checkpoint() {
        let ckpt = Checkpoint::new(PathBuf::from("empty.txt"), 0, 8192, 0, 0);
        assert_eq!(ckpt.total_blocks(), 0);
        assert!(ckpt.completed_blocks.is_empty());

        let dir = tempfile::tempdir().unwrap();
        CheckpointFile::save(dir.path(), &ckpt).unwrap();
        let loaded = CheckpointFile::load(dir.path(), "empty.txt")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, ckpt);
    }

    #[test]
    fn test_zero_block_size() {
        let ckpt = Checkpoint::new(PathBuf::from("zero_bs.txt"), 1000, 0, 0, 0);
        assert_eq!(ckpt.total_blocks(), 0);
    }

    #[test]
    fn test_resume_state_out_of_bounds() {
        let mut ckpt = Checkpoint::new(PathBuf::from("small.txt"), 100, 100, 0, 0);
        assert_eq!(ckpt.total_blocks(), 1);

        {
            let mut state = ckpt.resume_state();
            // Out-of-bounds mark is a no-op.
            state.mark_block_done(999);
            assert!(!state.is_block_done(999));
            assert_eq!(state.blocks_remaining(), 1);
        }
    }

    #[test]
    fn test_large_block_bitmap_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        // 10 GiB file with 4 KiB blocks = ~2.6M blocks
        // Use a smaller but still substantial count for test speed.
        let mut ckpt = Checkpoint::new(
            PathBuf::from("big.img"),
            10 * 1024 * 1024, // 10 MiB
            4096,
            -1,
            1700000000,
        );
        let total = ckpt.total_blocks();
        assert_eq!(total, 2560);

        // Mark every other block done.
        {
            let mut state = ckpt.resume_state();
            for i in (0..total).step_by(2) {
                state.mark_block_done(i);
            }
            assert_eq!(state.blocks_remaining(), total / 2);
        }

        CheckpointFile::save(dir.path(), &ckpt).unwrap();
        let loaded = CheckpointFile::load(dir.path(), "big.img")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, ckpt);
    }
}
