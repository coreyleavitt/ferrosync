//! Push tests: ferrosync client -> rsync server over SSH.

use crate::common::assertions::*;
use crate::common::env::{set_mtime, TestEnv};
use crate::common::ssh::*;
use crate::skip_if_no_ssh;

#[tokio::test]
async fn test_interop_push_single_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("hello.txt", b"hello via SSH\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&env.src(), &remote_dir, 30).await;
    assert!(result.stats.files_transferred >= 1);

    let content = remote_cat(&format!("{remote_dir}/hello.txt")).await;
    assert_eq!(content, "hello via SSH\n");
    assert_remote_exists(&format!("{remote_dir}/hello.txt")).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_directory_recursive() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("top.txt", b"top\n", None)
        .with_src_file("a/mid.txt", b"mid\n", None)
        .with_src_file("a/b/deep.txt", b"deep\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    assert_eq!(remote_cat(&format!("{remote_dir}/top.txt")).await, "top\n");
    assert_eq!(
        remote_cat(&format!("{remote_dir}/a/mid.txt")).await,
        "mid\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/a/b/deep.txt")).await,
        "deep\n"
    );

    // Verify subdirectories exist as directories on remote.
    let is_dir_a = ssh_cmd(&["test", "-d", &format!("{remote_dir}/a"), "&&", "echo", "yes"]).await;
    assert_eq!(is_dir_a.trim(), "yes", "a/ should exist as a directory");
    let is_dir_ab =
        ssh_cmd(&["test", "-d", &format!("{remote_dir}/a/b"), "&&", "echo", "yes"]).await;
    assert_eq!(is_dir_ab.trim(), "yes", "a/b/ should exist as a directory");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_many_small_files() {
    skip_if_no_ssh!();

    let env = TestEnv::builder().build();
    for i in 0..50 {
        std::fs::write(
            env.src().join(format!("file_{i:03}.txt")),
            format!("content {i}\n"),
        )
        .unwrap();
    }

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&env.src(), &remote_dir, 60).await;
    assert_eq!(result.stats.files_transferred, 50);

    // Verify ALL 50 files have correct content.
    for i in 0..50 {
        let actual = remote_cat(&format!("{remote_dir}/file_{i:03}.txt")).await;
        assert_eq!(
            actual,
            format!("content {i}\n"),
            "file_{i:03}.txt content mismatch"
        );
    }

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_large_file() {
    skip_if_no_ssh!();

    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let env = TestEnv::builder()
        .with_src_file("big.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&env.src(), &remote_dir, 60).await;
    assert_eq!(result.stats.files_transferred, 1);

    let size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/big.dat")]).await;
    assert_eq!(size.trim(), "1048576");

    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "16",
        &format!("{remote_dir}/big.dat"),
    ])
    .await;
    let head_hex: String = head.split_whitespace().collect();
    let expected_head: String = data[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(head_hex, expected_head, "large file head mismatch");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_very_large_file() {
    skip_if_no_ssh!();

    let size = 16 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let env = TestEnv::builder()
        .with_src_file("huge.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&env.src(), &remote_dir, 120).await;
    assert_eq!(result.stats.files_transferred, 1);

    let remote_size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/huge.dat")]).await;
    assert_eq!(
        remote_size.trim(),
        size.to_string(),
        "remote file size mismatch"
    );

    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "4096",
        &format!("{remote_dir}/huge.dat"),
    ])
    .await;
    let head_hex: String = head.split_whitespace().collect();
    let expected_head: String = data[..4096].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(head_hex, expected_head, "16MB file head mismatch");

    let tail = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-j",
        &format!("{}", size - 4096),
        "-N",
        "4096",
        &format!("{remote_dir}/huge.dat"),
    ])
    .await;
    let tail_hex: String = tail.split_whitespace().collect();
    let expected_tail: String = data[size - 4096..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tail_hex, expected_tail, "16MB file tail mismatch");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_mixed_directory() {
    skip_if_no_ssh!();

    let env = TestEnv::builder().build();
    std::fs::create_dir_all(env.src().join("sub")).unwrap();

    for i in 0..20 {
        std::fs::write(
            env.src().join(format!("small_{i:02}.txt")),
            format!("data {i}\n"),
        )
        .unwrap();
    }
    for i in 0..10 {
        std::fs::write(
            env.src().join(format!("sub/nested_{i:02}.txt")),
            format!("nested {i}\n"),
        )
        .unwrap();
    }
    let big_data: Vec<u8> = (0..524_288).map(|i| (i % 199) as u8).collect();
    std::fs::write(env.src().join("medium.bin"), &big_data).unwrap();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&env.src(), &remote_dir, 120).await;
    assert_eq!(result.stats.files_transferred, 31);

    assert_eq!(
        remote_cat(&format!("{remote_dir}/small_00.txt")).await,
        "data 0\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/sub/nested_09.txt")).await,
        "nested 9\n"
    );
    assert!(remote_exists(&format!("{remote_dir}/medium.bin")).await);

    // Verify directory structure exists
    let is_dir = ssh_cmd(&["test", "-d", &format!("{remote_dir}/sub"), "&&", "echo", "yes"]).await;
    assert_eq!(is_dir.trim(), "yes", "sub/ should exist as a directory");

    // Verify more files at different depths
    assert_eq!(
        remote_cat(&format!("{remote_dir}/small_10.txt")).await,
        "data 10\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/small_19.txt")).await,
        "data 19\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/sub/nested_00.txt")).await,
        "nested 0\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/sub/nested_05.txt")).await,
        "nested 5\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_preserves_mtime() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("timed.txt", b"check mtime\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let stat_output = ssh_cmd(&["stat", "-c", "%Y", &format!("{remote_dir}/timed.txt")]).await;
    let remote_mtime: i64 = stat_output.trim().parse().unwrap();
    assert_eq!(remote_mtime, 1_700_000_000, "mtime should be preserved");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_idempotent() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("stable.txt", b"no change\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    push_archive(&env.src(), &remote_dir, 30).await;
    let result2 = push_archive(&env.src(), &remote_dir, 30).await;
    assert_eq!(
        result2.stats.files_transferred, 0,
        "idempotent push should transfer zero files"
    );

    let content = remote_cat(&format!("{remote_dir}/stable.txt")).await;
    assert_eq!(content, "no change\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_archive_mode() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("archive.txt", b"archive mode push\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let content = remote_cat(&format!("{remote_dir}/archive.txt")).await;
    assert_eq!(content, "archive mode push\n");

    // Archive mode preserves mtime: verify remote mtime matches local.
    let local_mtime = std::fs::metadata(env.src().join("archive.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let remote_mtime_str =
        ssh_cmd(&["stat", "-c", "%Y", &format!("{remote_dir}/archive.txt")]).await;
    let remote_mtime: u64 = remote_mtime_str.trim().parse().unwrap();
    assert_eq!(
        remote_mtime, local_mtime,
        "archive mode should preserve mtime"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_ignore_times() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"new content\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;

    // First push to populate remote.
    push_archive(&env.src(), &remote_dir, 30).await;

    // Overwrite local with different content but same size+mtime.
    std::fs::write(env.src().join("file.txt"), b"alt content\n").unwrap();
    set_mtime(&env.src().join("file.txt"), 1_700_000_000);

    // Push with --ignore-times: should transfer despite same size+mtime.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .ignore_times(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    let content = remote_cat(&format!("{remote_dir}/file.txt")).await;
    assert_eq!(content, "alt content\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_checksum() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"aaa\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Overwrite local with different content but same mtime.
    std::fs::write(env.src().join("file.txt"), b"bbb\n").unwrap();
    set_mtime(&env.src().join("file.txt"), 1_700_000_000);

    // Push with --checksum: should detect content change despite same size+mtime.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    let content = remote_cat(&format!("{remote_dir}/file.txt")).await;
    assert_eq!(
        content, "bbb\n",
        "checksum push should detect content change"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_whole_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"whole file push\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .whole_file(true)
        .source(env.src())
        .build();
    let result = push_with_opts(opts, &remote_dir, 30).await;

    let content = remote_cat(&format!("{remote_dir}/file.txt")).await;
    assert_eq!(content, "whole file push\n");
    assert_eq!(
        result.stats.matched_data, 0,
        "whole-file should not use delta matching"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_compress() {
    skip_if_no_ssh!();

    let data = vec![b'A'; 65536];
    let env = TestEnv::builder()
        .with_src_file("repeated.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .compress(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    let size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/repeated.dat")]).await;
    assert_eq!(
        size.trim(),
        "65536",
        "compressed transfer should produce correct file size on remote"
    );

    // Verify remote file content matches local (all 'A' bytes).
    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "16",
        &format!("{remote_dir}/repeated.dat"),
    ])
    .await;
    let head_hex: String = head.split_whitespace().collect();
    let expected: String = std::iter::repeat("41").take(16).collect();
    assert_eq!(
        head_hex, expected,
        "compressed transfer should produce correct file content"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_numeric_ids() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"numeric ids\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .numeric_ids(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    let content = remote_cat(&format!("{remote_dir}/file.txt")).await;
    assert_eq!(content, "numeric ids\n");

    // We run as root in Docker, so uid:gid should be 0:0.
    let ownership = ssh_cmd(&["stat", "-c", "%u:%g", &format!("{remote_dir}/file.txt")]).await;
    assert_eq!(
        ownership.trim(),
        "0:0",
        "numeric-ids should preserve uid:gid as 0:0"
    );

    // Verify uid and gid are numeric values individually.
    let uid = ssh_cmd(&["stat", "-c", "%u", &format!("{remote_dir}/file.txt")]).await;
    let gid = ssh_cmd(&["stat", "-c", "%g", &format!("{remote_dir}/file.txt")]).await;
    let uid_val: u32 = uid.trim().parse().expect("uid should be a numeric value");
    let gid_val: u32 = gid.trim().parse().expect("gid should be a numeric value");
    assert_eq!(uid_val, 0, "uid should be preserved numerically as 0");
    assert_eq!(gid_val, 0, "gid should be preserved numerically as 0");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_exclude() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep me\n", None)
        .with_src_file("skip.log", b"skip me\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .exclude("*.log")
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    assert!(
        remote_exists(&format!("{remote_dir}/keep.txt")).await,
        "keep.txt should exist on remote"
    );
    assert!(
        !remote_exists(&format!("{remote_dir}/skip.log")).await,
        "skip.log should be excluded"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_push_dry_run() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"dry run test\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .dry_run(true)
        .source(env.src())
        .build();
    let result = push_with_opts(opts, &remote_dir, 30).await;

    assert!(
        !remote_exists(&format!("{remote_dir}/file.txt")).await,
        "dry-run should not create file on remote"
    );
    assert!(
        result.stats.files_transferred >= 1,
        "dry-run should still report files that would transfer"
    );

    remote_cleanup(&remote_dir).await;
}

/// The remote rsync receiver handles hardlink creation.
#[tokio::test]
async fn test_interop_push_hardlinks() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Create a file and hardlink it locally.
    std::fs::write(src.join("original.txt"), b"push_hardlink\n").unwrap();
    std::fs::hard_link(src.join("original.txt"), src.join("linked.txt")).unwrap();

    let remote_dir = remote_tmpdir().await;
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .preserve_hard_links(true)
        .source(src)
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // Both files should exist on remote with correct content.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/original.txt")).await,
        "push_hardlink\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/linked.txt")).await,
        "push_hardlink\n"
    );

    // Verify they share an inode on remote.
    let inode_a = ssh_cmd(&["stat", "-c", "%i", &format!("{remote_dir}/original.txt")]).await;
    let inode_b = ssh_cmd(&["stat", "-c", "%i", &format!("{remote_dir}/linked.txt")]).await;
    assert_eq!(
        inode_a.trim(),
        inode_b.trim(),
        "pushed hardlinked files should share an inode on remote"
    );

    remote_cleanup(&remote_dir).await;
}
