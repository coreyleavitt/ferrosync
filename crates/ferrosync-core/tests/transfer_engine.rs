//! Transfer integration tests using the direct transfer engine.
//!
//! These tests verify file synchronization correctness by running
//! ferrosync's `execute_transfer()` engine directly (local-to-local).
//!
//! Requires a Unix environment (Unix filesystem semantics, PermissionsExt,
//! MetadataExt).
#![cfg(unix)]

mod common;

use std::path::Path;

use ferrosync_core::delta::ProtocolContext;
use ferrosync_core::engine::progress::ProgressTracker;
use ferrosync_core::engine::transfer::execute_transfer;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::protocol::handshake::ChecksumType;

use crate::common::assertions::assert_trees_equal;
use crate::common::env::{set_mtime, test_filesystem, TestEnv};

/// Create a temp source directory with known test files.
fn create_test_tree(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("hello.txt"), "Hello, world!\n").unwrap();
    std::fs::write(dir.join("data.bin"), vec![0xAA; 4096]).unwrap();
    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    std::fs::write(dir.join("subdir/nested.txt"), "nested file content\n").unwrap();
    std::fs::write(
        dir.join("subdir/large.dat"),
        vec![0x42; 32 * 1024], // 32 KiB
    )
    .unwrap();
}

/// Run a transfer from source to dest using the direct engine.
async fn run_transfer(opts: &TransferOptions) -> ferrosync_core::Result<()> {
    let fs = test_filesystem();
    let mut progress = ProgressTracker::new();
    let ctx = ProtocolContext {
        seed: 0,
        checksum_type: ChecksumType::Blake3,
        char_offset: 0,
        proper_seed_order: true,
    };
    execute_transfer(&*fs, opts, &ctx, &mut progress).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Single file tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_transfer_single_file() {
    let env = TestEnv::builder()
        .with_src_file("test.txt", b"pull test content\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dest_content = std::fs::read(env.dst().join("test.txt")).unwrap();
    assert_eq!(dest_content, b"pull test content\n");
}

#[tokio::test]
async fn test_transfer_directory_recursive() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    run_transfer(&options).await.unwrap();

    assert_trees_equal(&src, &dst);
}

#[tokio::test]
async fn test_transfer_preserves_times() {
    let env = TestEnv::builder()
        .with_src_file("timed.txt", b"time-test content\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let src_meta = std::fs::metadata(env.src().join("timed.txt")).unwrap();
    let dst_meta = std::fs::metadata(env.dst().join("timed.txt")).unwrap();

    use std::os::unix::fs::MetadataExt;
    // Allow 2 seconds of slop for filesystem timestamp granularity.
    let src_mtime = src_meta.mtime();
    let dst_mtime = dst_meta.mtime();
    assert!(
        (src_mtime - dst_mtime).abs() <= 2,
        "mtime mismatch: src={src_mtime}, dst={dst_mtime}",
    );
}

#[tokio::test]
async fn test_transfer_preserves_permissions() {
    let env = TestEnv::builder().build();

    let file_path = env.src().join("exec.sh");
    std::fs::write(&file_path, "#!/bin/sh\necho hello\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_perms(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dst_meta = std::fs::metadata(env.dst().join("exec.sh")).unwrap();
    let mode = dst_meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "expected 0o755, got {mode:#o}");
}

#[tokio::test]
async fn test_transfer_with_exclude() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .excludes(vec!["*.bin".to_string()])
        .source(src.clone())
        .dest(dst.clone())
        .build();

    run_transfer(&options).await.unwrap();

    // data.bin should be excluded.
    assert!(
        !dst.join("data.bin").exists(),
        "data.bin should have been excluded"
    );
    // But other files should be present.
    assert!(dst.join("hello.txt").exists());
}

#[tokio::test]
async fn test_transfer_delta() {
    let env = TestEnv::builder().build();

    // Create a basis file in the destination.
    let mut basis_data = vec![0u8; 10_000];
    for (i, b) in basis_data.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    std::fs::write(env.dst().join("delta.dat"), &basis_data).unwrap();

    // Create a slightly modified version in the source.
    let mut source_data = basis_data.clone();
    source_data[5000] = 0xFF;
    source_data[5001] = 0xFF;
    std::fs::write(env.src().join("delta.dat"), &source_data).unwrap();

    // Use checksum mode to force re-transfer even if mtime/size look the same.
    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .checksum_mode(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let result = std::fs::read(env.dst().join("delta.dat")).unwrap();
    assert_eq!(result, source_data);
}

#[tokio::test]
async fn test_transfer_whole_file() {
    let env = TestEnv::builder()
        .with_src_file("whole.txt", b"whole file content\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .whole_file(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dest_content = std::fs::read(env.dst().join("whole.txt")).unwrap();
    assert_eq!(dest_content, b"whole file content\n");
}

#[tokio::test]
async fn test_transfer_checksum_mode() {
    let env = TestEnv::builder()
        .with_src_file("check.txt", b"checksum mode content\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .checksum_mode(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dest_content = std::fs::read(env.dst().join("check.txt")).unwrap();
    assert_eq!(dest_content, b"checksum mode content\n");
}

#[tokio::test]
async fn test_transfer_empty_directory() {
    let env = TestEnv::builder().with_src_dir("empty_subdir").build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert!(
        env.dst().join("empty_subdir").is_dir(),
        "empty subdirectory should be created"
    );
}

#[tokio::test]
async fn test_transfer_large_file() {
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let env = TestEnv::builder()
        .with_src_file("big.dat", &data, None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dest_content = std::fs::read(env.dst().join("big.dat")).unwrap();
    assert_eq!(dest_content.len(), data.len());
    assert_eq!(dest_content, data);
}

#[tokio::test]
async fn test_transfer_dry_run() {
    let env = TestEnv::builder()
        .with_src_file("dryrun.txt", b"should not be written\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .dry_run(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert!(
        !env.dst().join("dryrun.txt").exists(),
        "dry run should not write files"
    );
}

#[tokio::test]
async fn test_transfer_archive_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .archive()
        .source(src.clone())
        .dest(dst.clone())
        .build();

    run_transfer(&options).await.unwrap();

    assert_trees_equal(&src, &dst);
}

#[tokio::test]
async fn test_transfer_multiple_files_flat() {
    let env = TestEnv::builder()
        .with_src_file("a.txt", b"aaa\n", None)
        .with_src_file("b.txt", b"bbb\n", None)
        .with_src_file("c.txt", b"ccc\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert_eq!(std::fs::read(env.dst().join("a.txt")).unwrap(), b"aaa\n");
    assert_eq!(std::fs::read(env.dst().join("b.txt")).unwrap(), b"bbb\n");
    assert_eq!(std::fs::read(env.dst().join("c.txt")).unwrap(), b"ccc\n");
}

#[tokio::test]
async fn test_transfer_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    // First transfer.
    run_transfer(&options).await.unwrap();
    assert_trees_equal(&src, &dst);

    // Second transfer (should be a no-op since files are identical).
    run_transfer(&options).await.unwrap();
    assert_trees_equal(&src, &dst);
}

#[tokio::test]
async fn test_transfer_empty_file() {
    let env = TestEnv::builder()
        .with_src_file("empty.txt", b"", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let dest_content = std::fs::read(env.dst().join("empty.txt")).unwrap();
    assert!(dest_content.is_empty(), "empty file should remain empty");
}

#[tokio::test]
async fn test_transfer_symlink() {
    let env = TestEnv::builder()
        .with_src_file("target.txt", b"symlink target content\n", None)
        .build();

    std::os::unix::fs::symlink("target.txt", env.src().join("link.txt")).unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .preserve_links(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert!(env.dst().join("target.txt").exists());
    let link_path = env.dst().join("link.txt");
    let link_meta = std::fs::symlink_metadata(&link_path).unwrap();
    assert!(
        link_meta.file_type().is_symlink(),
        "expected symlink at link.txt"
    );
    let link_target = std::fs::read_link(&link_path).unwrap();
    assert_eq!(
        link_target.to_string_lossy(),
        "target.txt",
        "symlink target mismatch"
    );
}

#[tokio::test]
async fn test_transfer_many_small_files() {
    let env = TestEnv::builder().build();

    // Create 100 small files.
    for i in 0..100 {
        let content = format!("file number {i}\n");
        std::fs::write(env.src().join(format!("f_{i:03}.txt")), content.as_bytes()).unwrap();
    }

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    for i in 0..100 {
        let expected = format!("file number {i}\n");
        let actual = std::fs::read(env.dst().join(format!("f_{i:03}.txt"))).unwrap();
        assert_eq!(actual, expected.as_bytes(), "mismatch for f_{i:03}.txt");
    }
}

#[tokio::test]
async fn test_transfer_many_files_delta() {
    let env = TestEnv::builder().build();

    // Create basis files at dest and modified versions at source.
    for i in 0..30 {
        let mut basis = vec![0u8; 4096];
        for (j, b) in basis.iter_mut().enumerate() {
            *b = ((i * 7 + j) % 256) as u8;
        }
        std::fs::write(env.dst().join(format!("d_{i:02}.bin")), &basis).unwrap();

        let mut modified = basis;
        modified[1024] = 0xFF;
        modified[1025] = 0xFE;
        std::fs::write(env.src().join(format!("d_{i:02}.bin")), &modified).unwrap();
    }

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .checksum_mode(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    for i in 0..30 {
        let mut expected = vec![0u8; 4096];
        for (j, b) in expected.iter_mut().enumerate() {
            *b = ((i * 7 + j) % 256) as u8;
        }
        expected[1024] = 0xFF;
        expected[1025] = 0xFE;
        let actual = std::fs::read(env.dst().join(format!("d_{i:02}.bin"))).unwrap();
        assert_eq!(actual, expected, "mismatch for d_{i:02}.bin");
    }
}

#[tokio::test]
async fn test_transfer_special_characters_in_filenames() {
    let env = TestEnv::builder()
        .with_src_file("file with spaces.txt", b"spaces\n", None)
        .with_src_file("file-with-dashes.txt", b"dashes\n", None)
        .with_src_file("file_with_underscores.txt", b"underscores\n", None)
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert_eq!(
        std::fs::read(env.dst().join("file with spaces.txt")).unwrap(),
        b"spaces\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file-with-dashes.txt")).unwrap(),
        b"dashes\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_with_underscores.txt")).unwrap(),
        b"underscores\n"
    );
}

// ---------------------------------------------------------------------------
// New flag tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_transfer_ignore_times() {
    let env = TestEnv::builder()
        .with_src_file("file.txt", b"new content\n", Some(1_700_000_000))
        .build();

    // Same size+mtime on dest would normally skip. --ignore-times forces transfer.
    std::fs::write(env.dst().join("file.txt"), b"old content\n").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1_700_000_000);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .ignore_times(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"new content\n");
}

#[tokio::test]
async fn test_transfer_size_only() {
    let env = TestEnv::builder()
        .with_src_file("file.txt", b"src data\n", Some(1_700_000_000))
        .build();

    // Same length, different mtime and content. --size-only should skip.
    std::fs::write(env.dst().join("file.txt"), b"dst data\n").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1_600_000_000);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .size_only(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"dst data\n",
        "size-only should skip when sizes match"
    );
}

#[tokio::test]
async fn test_transfer_existing() {
    let env = TestEnv::builder()
        .with_src_file("present.txt", b"updated\n", None)
        .with_src_file("absent.txt", b"new file\n", None)
        .build();

    std::fs::write(env.dst().join("present.txt"), b"old\n").unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .existing(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert_eq!(
        std::fs::read(env.dst().join("present.txt")).unwrap(),
        b"updated\n",
    );
    assert!(
        !env.dst().join("absent.txt").exists(),
        "--existing should skip files not on dest"
    );
}

#[tokio::test]
async fn test_transfer_ignore_existing() {
    let env = TestEnv::builder()
        .with_src_file("present.txt", b"updated\n", None)
        .with_src_file("absent.txt", b"new file\n", None)
        .build();

    std::fs::write(env.dst().join("present.txt"), b"original\n").unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .ignore_existing(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert_eq!(
        std::fs::read(env.dst().join("present.txt")).unwrap(),
        b"original\n",
        "--ignore-existing should not overwrite"
    );
    assert_eq!(
        std::fs::read(env.dst().join("absent.txt")).unwrap(),
        b"new file\n",
    );
}

#[tokio::test]
async fn test_transfer_max_delete() {
    use ferrosync_core::options::DeleteMode;

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep\n", None)
        .build();

    std::fs::write(env.dst().join("keep.txt"), b"keep\n").unwrap();
    std::fs::write(env.dst().join("extra1.txt"), b"del\n").unwrap();
    std::fs::write(env.dst().join("extra2.txt"), b"del\n").unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .delete(DeleteMode::Before)
        .max_delete(1)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    let extra1 = env.dst().join("extra1.txt").exists();
    let extra2 = env.dst().join("extra2.txt").exists();
    let remaining = (extra1 as u32) + (extra2 as u32);
    assert_eq!(remaining, 1, "max-delete=1 should leave one extra file");
}

#[tokio::test]
async fn test_transfer_prune_empty_dirs() {
    let env = TestEnv::builder()
        .with_src_file("a/file.txt", b"content\n", None)
        .with_src_dir("a/empty_child")
        .with_src_dir("empty_top")
        .build();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .prune_empty_dirs(true)
        .source(env.src())
        .dest(env.dst())
        .build();

    run_transfer(&options).await.unwrap();

    assert!(env.dst().join("a/file.txt").exists());
    assert!(
        !env.dst().join("a/empty_child").exists(),
        "empty child dir should be pruned"
    );
    assert!(
        !env.dst().join("empty_top").exists(),
        "empty top-level dir should be pruned"
    );
    assert!(env.dst().join("a").exists(), "non-empty dir should remain");
}
