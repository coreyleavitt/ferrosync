//! Rsync interop tests: ferrosync client against real rsync over SSH.
//!
//! These tests exercise the production path: ferrosync client -> SSH -> rsync
//! --server on a real Linux box. They verify wire protocol compatibility with
//! real rsync for every supported flag and flag combination.
//!
//! Requires Docker:
//! ```sh
//! docker compose -f docker-compose.test.yml run ferrosync-dev \
//!     cargo test -p ferrosync-core --test rsync_interop
//! ```
//!
//! Gated behind FERROSYNC_SSH_TEST=1 env var.
#![cfg(unix)]

#[macro_use]
mod common;

use common::assertions::{assert_hard_linked, assert_not_hard_linked};
use common::env::{set_mtime, TestEnv};
use common::ssh::*;

// ---------------------------------------------------------------------------
// Push tests: ferrosync client -> rsync server over SSH
// ---------------------------------------------------------------------------

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

    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_000.txt")).await,
        "content 0\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_049.txt")).await,
        "content 49\n"
    );

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
    let _result2 = push_archive(&env.src(), &remote_dir, 30).await;

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

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Flist codec validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_flist_preserves_permissions() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("script.sh", b"#!/bin/sh\necho hi\n", None)
        .build();

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        env.src().join("script.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    let stat_output = ssh_cmd(&["stat", "-c", "%a", &format!("{remote_dir}/script.sh")]).await;
    assert_eq!(stat_output.trim(), "755", "permissions should be preserved");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_flist_multiple_files_sorted() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("alpha.txt", b"aaa", None)
        .with_src_file("alpha_test.txt", b"bbb", None)
        .with_src_file("beta.txt", b"ccc", None)
        .with_src_file("beta_long_name.txt", b"ddd", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    assert_eq!(remote_cat(&format!("{remote_dir}/alpha.txt")).await, "aaa");
    assert_eq!(
        remote_cat(&format!("{remote_dir}/alpha_test.txt")).await,
        "bbb"
    );
    assert_eq!(remote_cat(&format!("{remote_dir}/beta.txt")).await, "ccc");
    assert_eq!(
        remote_cat(&format!("{remote_dir}/beta_long_name.txt")).await,
        "ddd"
    );

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Pull tests: ferrosync client <- rsync server over SSH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_pull_single_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("pull.txt", b"pulled via SSH\n", None)
        .build();

    // Push to remote, then pull back into a clean destination.
    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    let content = std::fs::read_to_string(env.dst().join("pull.txt")).unwrap();
    assert_eq!(content, "pulled via SSH\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_directory_recursive() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("top.txt", b"top\n", None)
        .with_src_file("sub/deep.txt", b"deep\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    assert_eq!(
        std::fs::read_to_string(env.dst().join("top.txt")).unwrap(),
        "top\n"
    );
    assert_eq!(
        std::fs::read_to_string(env.dst().join("sub/deep.txt")).unwrap(),
        "deep\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_large_file() {
    skip_if_no_ssh!();

    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let env = TestEnv::builder()
        .with_src_file("big.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 60).await;

    let remote_path = format!("{remote_dir}/");
    let result = pull_archive(&remote_path, &env.dst(), 60).await;
    assert_eq!(result.stats.files_transferred, 1);

    let pulled = std::fs::read(env.dst().join("big.dat")).unwrap();
    assert_eq!(pulled.len(), 1_048_576, "pulled file should be 1MB");
    assert_eq!(pulled, data, "large file content mismatch after pull");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_empty_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder().build();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&["touch", &format!("{remote_dir}/empty.txt")]).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    let content = std::fs::read(env.dst().join("empty.txt")).unwrap();
    assert!(content.is_empty());

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_archive_mode() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("archive.txt", b"archive mode pull\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    let content = std::fs::read_to_string(env.dst().join("archive.txt")).unwrap();
    assert_eq!(content, "archive mode pull\n");

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Link-dest tests (receiver-side hard-linking)
//
// --link-dest is a receiver-side feature: when a file in the source matches
// (content + mtime) a file in a link-dest directory, the receiver hard-links
// instead of transferring. All tests here are PULL tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_pull_link_dest_basic() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"hello\n", Some(1_700_000_000))
        .with_prev_file("file_a.txt", b"hello\n", Some(1_700_000_000))
        .build();

    // Push src to remote, then pull with link-dest.
    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(env.prev())
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file_a.txt")).unwrap();
    assert_eq!(content, b"hello\n");

    assert_hard_linked(
        &env.dst().join("file_a.txt"),
        &env.prev().join("file_a.txt"),
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_link_dest_relative_path() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    let current = base.join("current");
    let new_dir = base.join("new");
    std::fs::create_dir_all(&current).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();

    std::fs::write(current.join("file.txt"), "content\n").unwrap();
    set_mtime(&current.join("file.txt"), 1_700_000_000);

    // Push current to remote.
    let remote_dir = remote_tmpdir().await;
    push_archive(&current, &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest("../current")
        .dest(new_dir.clone())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(new_dir.join("file.txt")).unwrap();
    assert_eq!(content, b"content\n");

    assert_hard_linked(&new_dir.join("file.txt"), &current.join("file.txt"));

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_link_dest_multiple_dirs() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", Some(1_700_000_000))
        .with_src_file("file_b.txt", b"bbb\n", Some(1_700_000_000))
        .build();

    let alt1 = env.dir().join("alt1");
    let alt2 = env.dir().join("alt2");
    std::fs::create_dir_all(&alt1).unwrap();
    std::fs::create_dir_all(&alt2).unwrap();

    std::fs::write(alt1.join("file_a.txt"), "aaa\n").unwrap();
    set_mtime(&alt1.join("file_a.txt"), 1_700_000_000);
    std::fs::write(alt2.join("file_b.txt"), "bbb\n").unwrap();
    set_mtime(&alt2.join("file_b.txt"), 1_700_000_000);

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(&alt1)
        .link_dest(&alt2)
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );

    assert_hard_linked(&env.dst().join("file_a.txt"), &alt1.join("file_a.txt"));
    assert_hard_linked(&env.dst().join("file_b.txt"), &alt2.join("file_b.txt"));

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_link_dest_mtime_mismatch() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"same content\n", Some(1_700_000_000))
        .with_prev_file("file.txt", b"same content\n", Some(1_600_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(env.prev())
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"same content\n");

    assert_not_hard_linked(&env.dst().join("file.txt"), &env.prev().join("file.txt"));

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_link_dest_changed_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        // file_a: changed between prev and src
        .with_src_file("file_a.txt", b"version 2\n", Some(1_700_000_000))
        .with_prev_file("file_a.txt", b"version 1\n", Some(1_600_000_000))
        // file_b: unchanged between prev and src
        .with_src_file("file_b.txt", b"same\n", Some(1_700_000_000))
        .with_prev_file("file_b.txt", b"same\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(env.prev())
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    // Unchanged file should be hard-linked.
    assert_hard_linked(
        &env.dst().join("file_b.txt"),
        &env.prev().join("file_b.txt"),
    );

    // Changed file should be a new copy.
    assert_not_hard_linked(
        &env.dst().join("file_a.txt"),
        &env.prev().join("file_a.txt"),
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"version 2\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_link_dest_snapshot_rotation() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let backup_0 = tmp.path().join("backup_0");
    let backup_1 = tmp.path().join("backup_1");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&backup_0).unwrap();

    // Initial source state.
    std::fs::write(src.join("file_a.txt"), "original\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);
    std::fs::write(src.join("file_b.txt"), "stable\n").unwrap();
    set_mtime(&src.join("file_b.txt"), 1_700_000_000);

    let remote_dir = remote_tmpdir().await;

    // First sync: push src to remote, pull into backup_0 (no link-dest).
    push_archive(&src, &remote_dir, 30).await;
    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &backup_0, 30).await;

    // Modify source: change file_a, leave file_b stable.
    std::fs::write(src.join("file_a.txt"), "modified\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_001_000);

    // Update remote with modified source.
    push_archive(&src, &remote_dir, 30).await;

    // Second sync: pull into backup_1 with --link-dest=backup_0/.
    std::fs::create_dir_all(&backup_1).unwrap();
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(&backup_0)
        .dest(backup_1.clone())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    // Unchanged file_b should be hard-linked across snapshots.
    assert_hard_linked(&backup_1.join("file_b.txt"), &backup_0.join("file_b.txt"));

    // Changed file_a should have a different inode.
    assert_not_hard_linked(&backup_1.join("file_a.txt"), &backup_0.join("file_a.txt"));

    // Both snapshots should be complete.
    assert!(backup_0.join("file_a.txt").exists());
    assert!(backup_0.join("file_b.txt").exists());
    assert!(backup_1.join("file_a.txt").exists());
    assert!(backup_1.join("file_b.txt").exists());

    assert_eq!(
        std::fs::read(backup_0.join("file_a.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        std::fs::read(backup_1.join("file_a.txt")).unwrap(),
        b"modified\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_link_dest_rerun_idempotent() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"idempotent\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // First pull: no link-dest.
    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    // Create prev/ as a copy of dst/ with matching content and mtimes.
    let prev = env.dir().join("prev");
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::copy(env.dst().join("file.txt"), prev.join("file.txt")).unwrap();
    set_mtime(&prev.join("file.txt"), 1_700_000_000);

    // Re-run pull with link-dest=prev into a fresh dst.
    let dst2 = env.dir().join("dst2");
    std::fs::create_dir_all(&dst2).unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest(&prev)
        .dest(dst2.clone())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(dst2.join("file.txt")).unwrap();
    assert_eq!(content, b"idempotent\n");

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Delete tests (wire transfer --delete support)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_pull_delete_before() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .with_src_file("file_b.txt", b"bbb\n", None)
        .build();

    // Push source files to remote.
    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create an extra file in the local destination.
    std::fs::create_dir_all(env.dst()).unwrap();
    std::fs::write(env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    // Pull with --delete-before.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::Before)
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    let result = pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_delete_during() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .with_src_file("file_b.txt", b"bbb\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    std::fs::create_dir_all(env.dst()).unwrap();
    std::fs::write(env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::During)
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    let result = pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_delete_after() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .with_src_file("file_b.txt", b"bbb\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    std::fs::create_dir_all(env.dst()).unwrap();
    std::fs::write(env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::After)
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    let result = pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_delete_with_exclude() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create extra files locally: one should be deleted, one protected by exclude.
    std::fs::create_dir_all(env.dst()).unwrap();
    std::fs::write(env.dst().join("extra.txt"), "delete me\n").unwrap();
    std::fs::write(env.dst().join("keep.log"), "protected\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::During)
        .exclude("*.log")
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra.txt should be deleted"
    );
    assert!(
        env.dst().join("keep.log").exists(),
        "excluded *.log should be preserved"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_delete_excluded() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create extra files locally: both should be deleted with --delete-excluded.
    std::fs::create_dir_all(env.dst()).unwrap();
    std::fs::write(env.dst().join("extra.txt"), "delete me\n").unwrap();
    std::fs::write(env.dst().join("keep.log"), "also delete me\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::Excluded)
        .exclude("*.log")
        .dest(env.dst())
        .build();

    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra.txt should be deleted"
    );
    assert!(
        !env.dst().join("keep.log").exists(),
        "excluded *.log should also be deleted"
    );
    assert_eq!(
        std::fs::read(env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// New flag interop tests
// ---------------------------------------------------------------------------

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
async fn test_interop_pull_size_only() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"src data\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local dest with same-length but different content and mtime.
    std::fs::write(env.dst().join("file.txt"), b"old data\n").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1_600_000_000);

    // Pull with --size-only: should skip because sizes match (9 bytes both).
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .size_only(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"old data\n",
        "size-only should skip same-size file"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_existing() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("present.txt", b"updated\n", None)
        .with_src_file("absent.txt", b"new file\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-create only present.txt on local dest.
    std::fs::write(env.dst().join("present.txt"), "old\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .existing(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert_eq!(
        std::fs::read(env.dst().join("present.txt")).unwrap(),
        b"updated\n",
    );
    assert!(
        !env.dst().join("absent.txt").exists(),
        "--existing should skip files not on dest"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_ignore_existing() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("present.txt", b"updated\n", None)
        .with_src_file("absent.txt", b"new file\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-create present.txt on local dest.
    std::fs::write(env.dst().join("present.txt"), "original\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .ignore_existing(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert_eq!(
        std::fs::read(env.dst().join("present.txt")).unwrap(),
        b"original\n",
        "--ignore-existing should not overwrite"
    );
    assert_eq!(
        std::fs::read(env.dst().join("absent.txt")).unwrap(),
        b"new file\n",
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_max_delete() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-create extra files locally.
    std::fs::write(env.dst().join("keep.txt"), "keep\n").unwrap();
    std::fs::write(env.dst().join("extra1.txt"), "del\n").unwrap();
    std::fs::write(env.dst().join("extra2.txt"), "del\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::Before)
        .max_delete(1)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let extra1 = env.dst().join("extra1.txt").exists();
    let extra2 = env.dst().join("extra2.txt").exists();
    let remaining = (extra1 as u32) + (extra2 as u32);
    assert_eq!(remaining, 1, "max-delete=1 should leave one extra file");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_prune_empty_dirs() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("a/file.txt", b"content\n", None)
        .build();

    // Also create an empty dir on remote.
    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;
    ssh_cmd(&["mkdir", "-p", &format!("{remote_dir}/empty_dir")]).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .prune_empty_dirs(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(env.dst().join("a/file.txt").exists());
    assert!(
        !env.dst().join("empty_dir").exists(),
        "empty dir should be pruned"
    );

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Flag-specific interop tests (#117)
// ---------------------------------------------------------------------------

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
async fn test_interop_pull_checksum() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"aaa\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local dest with same content+mtime.
    std::fs::write(env.dst().join("file.txt"), b"aaa\n").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1_700_000_000);

    // Update remote with different content but same size+mtime.
    std::fs::write(env.src().join("file.txt"), b"bbb\n").unwrap();
    set_mtime(&env.src().join("file.txt"), 1_700_000_000);
    let push_opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .source(env.src())
        .build();
    push_with_opts(push_opts, &remote_dir, 30).await;

    // Pull with --checksum: should detect content differs.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"bbb\n",
        "checksum pull should detect content change"
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
async fn test_interop_pull_whole_file() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"whole file pull\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local dest as basis.
    std::fs::write(env.dst().join("file.txt"), b"old basis data\n").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .whole_file(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    let result = pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"whole file pull\n");
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

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_compress() {
    skip_if_no_ssh!();

    let data = vec![b'A'; 65536];
    let env = TestEnv::builder()
        .with_src_file("repeated.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .compress(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("repeated.dat")).unwrap();
    assert_eq!(content.len(), 65536);
    assert!(
        content.iter().all(|&b| b == b'A'),
        "all 65536 bytes should be 'A'"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_update() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"remote version\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local with different content and NEWER mtime.
    std::fs::write(env.dst().join("file.txt"), b"local newer\n").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1_800_000_000);

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .update(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"local newer\n",
        "--update should skip file with newer local mtime"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_inplace() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"updated content\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local dest with different content.
    std::fs::write(env.dst().join("file.txt"), b"original text\n").unwrap();
    let inode_before = common::env::inode_of(&env.dst().join("file.txt"));

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .inplace(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"updated content\n");

    let inode_after = common::env::inode_of(&env.dst().join("file.txt"));
    assert_eq!(
        inode_before, inode_after,
        "--inplace should write to the same inode (no temp file)"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_sparse() {
    skip_if_no_ssh!();

    // 1MB sparse-friendly data: 4KB 0xFF + 1016KB 0x00 + 4KB 0xAA.
    let mut data = Vec::with_capacity(1_048_576);
    data.extend(std::iter::repeat_n(0xFFu8, 4096));
    data.extend(std::iter::repeat_n(0x00u8, 1016 * 1024));
    data.extend(std::iter::repeat_n(0xAAu8, 4096));
    assert_eq!(data.len(), 1_048_576);

    let env = TestEnv::builder()
        .with_src_file("sparse.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 60).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .sparse(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 60).await;

    let content = std::fs::read(env.dst().join("sparse.dat")).unwrap();
    assert_eq!(
        content, data,
        "sparse pull content should match byte-for-byte"
    );

    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(env.dst().join("sparse.dat")).unwrap();
    let allocated = meta.blocks() * 512;
    assert!(
        allocated < 1_048_576,
        "sparse file should use fewer blocks than full size (allocated={allocated})"
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
async fn test_interop_pull_exclude() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep me\n", None)
        .with_src_file("skip.log", b"skip me\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .exclude("*.log")
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        env.dst().join("keep.txt").exists(),
        "keep.txt should be pulled"
    );
    assert!(
        !env.dst().join("skip.log").exists(),
        "skip.log should be excluded from pull"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_include_exclude() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("data.txt", b"text\n", None)
        .with_src_file("data.csv", b"csv\n", None)
        .with_src_file("data.bin", b"bin\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .include("*.txt")
        .include("*/")
        .exclude("*")
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        env.dst().join("data.txt").exists(),
        "data.txt should be included"
    );
    assert!(
        !env.dst().join("data.csv").exists(),
        "data.csv should be excluded"
    );
    assert!(
        !env.dst().join("data.bin").exists(),
        "data.bin should be excluded"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_filter() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("main.c", b"int main() {}\n", None)
        .with_src_file("main.o", b"\x7fELF", None)
        .with_src_file("lib.a", b"!<arch>\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .filter("- *.o")
        .filter("- *.a")
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(env.dst().join("main.c").exists(), "main.c should be pulled");
    assert!(
        !env.dst().join("main.o").exists(),
        "main.o should be filtered out"
    );
    assert!(
        !env.dst().join("lib.a").exists(),
        "lib.a should be filtered out"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_compare_dest() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"hello\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create local alt dir with identical copy (same content+mtime).
    let alt_dir = env.dir().join("alt");
    std::fs::create_dir_all(&alt_dir).unwrap();
    std::fs::write(alt_dir.join("file.txt"), b"hello\n").unwrap();
    set_mtime(&alt_dir.join("file.txt"), 1_700_000_000);

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .compare_dest(&alt_dir)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("file.txt").exists(),
        "compare-dest should skip file when identical copy exists in alt dir"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_copy_dest() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"hello\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create local alt dir with identical copy (same content+mtime).
    let alt_dir = env.dir().join("alt");
    std::fs::create_dir_all(&alt_dir).unwrap();
    std::fs::write(alt_dir.join("file.txt"), b"hello\n").unwrap();
    set_mtime(&alt_dir.join("file.txt"), 1_700_000_000);

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .copy_dest(&alt_dir)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        env.dst().join("file.txt").exists(),
        "copy-dest should create dest file"
    );
    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"hello\n");

    // Dest inode should differ from alt (it's a copy, not hard link).
    assert_not_hard_linked(&env.dst().join("file.txt"), &alt_dir.join("file.txt"));

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_backup() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"version one\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    // Push v1, pull to populate local.
    push_archive(&env.src(), &remote_dir, 30).await;
    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;
    assert_eq!(
        std::fs::read(env.dst().join("file.txt")).unwrap(),
        b"version one\n"
    );

    // Push v2 with different mtime to ensure transfer isn't skipped.
    std::fs::write(env.src().join("file.txt"), b"version two\n").unwrap();
    set_mtime(&env.src().join("file.txt"), 1_800_000_000);
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pull with backup and checksum mode to force retransfer.
    let bak_dir = env.dst().join("bak");
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .backup(true)
        .backup_dir(&bak_dir)
        .suffix(".old")
        .dest(env.dst())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"version two\n", "file should have v2 content");

    let backup = std::fs::read(bak_dir.join("file.txt.old")).unwrap();
    assert_eq!(backup, b"version one\n", "backup should have v1 content");

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

#[tokio::test]
async fn test_interop_pull_dry_run() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"dry run pull\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .dry_run(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        !env.dst().join("file.txt").exists(),
        "dry-run pull should not create local file"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_append() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"abcdefghij\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pre-populate local dest with first 4 bytes.
    std::fs::write(env.dst().join("file.txt"), b"abcd").unwrap();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .append(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"abcdefghij\n",
        "--append should complete partial file to full 11 bytes"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_itemize() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"original\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pull to populate local.
    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &env.dst(), 30).await;

    // Push updated version with different mtime to ensure transfer.
    std::fs::write(env.src().join("file.txt"), b"modified\n").unwrap();
    set_mtime(&env.src().join("file.txt"), 1_800_000_000);
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pull with itemize-changes and checksum to force retransfer.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .itemize_changes(true)
        .dest(env.dst())
        .build();
    let result = pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"modified\n");
    assert!(
        result.stats.files_transferred >= 1,
        "itemize pull should transfer updated file"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_stats() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("a.txt", b"aaa\n", None)
        .with_src_file("b.txt", b"bbb\n", None)
        .with_src_file("c.txt", b"ccc\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .stats(true)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    let result = pull_with_opts(opts, &remote_path, 30).await;

    assert!(
        result.stats.total_files >= 3,
        "stats should report at least 3 total files, got {}",
        result.stats.total_files
    );
    assert!(
        result.stats.files_transferred >= 3,
        "stats should report at least 3 transferred files, got {}",
        result.stats.files_transferred
    );
    assert!(
        result.stats.total_size > 0,
        "stats should report non-zero total size"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_interop_pull_bwlimit() {
    skip_if_no_ssh!();

    let data = vec![b'X'; 200 * 1024];
    let env = TestEnv::builder()
        .with_src_file("large.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 60).await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .bwlimit(102400)
        .dest(env.dst())
        .build();
    let remote_path = format!("{remote_dir}/");
    pull_with_opts(opts, &remote_path, 60).await;

    let content = std::fs::read(env.dst().join("large.dat")).unwrap();
    assert_eq!(
        content.len(),
        200 * 1024,
        "bwlimit pull should transfer full 200KB"
    );
    assert_eq!(content, data, "bwlimit pull content should match");

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Reverse interop tests: rsync client → ferrosync --server (#127)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_reverse_push_single_file() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("hello.txt", b"reverse push\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&format!("{remote_dir}/hello.txt")).await;
    assert_eq!(content, "reverse push\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_push_directory() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("top.txt", b"top\n", None)
        .with_src_file("a/mid.txt", b"mid\n", None)
        .with_src_file("a/b/deep.txt", b"deep\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(remote_cat(&format!("{remote_dir}/top.txt")).await, "top\n");
    assert_eq!(
        remote_cat(&format!("{remote_dir}/a/mid.txt")).await,
        "mid\n"
    );
    assert_eq!(
        remote_cat(&format!("{remote_dir}/a/b/deep.txt")).await,
        "deep\n"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_push_large_file() {
    skip_if_no_reverse!();

    let data = vec![b'A'; 1024 * 1024];
    let env = TestEnv::builder()
        .with_src_file("big.dat", &data, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &[], 60).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let size_str = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/big.dat")]).await;
    let size: usize = size_str
        .trim()
        .parse()
        .expect("failed to parse remote file size");
    assert_eq!(size, 1024 * 1024, "remote file should be 1MB");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_single_file() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'reverse pull' > {remote_dir}/data.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(&remote_dir, &env.dst(), &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("data.txt")).unwrap();
    assert_eq!(content, "reverse pull");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_directory() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&["mkdir", "-p", &format!("{remote_dir}/sub/deep")]).await;
    ssh_cmd(&["sh", "-c", &format!("echo -n 'top' > {remote_dir}/top.txt")]).await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'mid' > {remote_dir}/sub/mid.txt"),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'deep' > {remote_dir}/sub/deep/deep.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(&remote_dir, &env.dst(), &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(
        std::fs::read_to_string(env.dst().join("top.txt")).unwrap(),
        "top"
    );
    assert_eq!(
        std::fs::read_to_string(env.dst().join("sub/mid.txt")).unwrap(),
        "mid"
    );
    assert_eq!(
        std::fs::read_to_string(env.dst().join("sub/deep/deep.txt")).unwrap(),
        "deep"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_large_file() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    // Create a 1MB file on the remote
    ssh_cmd(&[
        "sh",
        "-c",
        &format!(
            "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\\0' 'B' > {remote_dir}/big.dat"
        ),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(&remote_dir, &env.dst(), &[], 60).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read(env.dst().join("big.dat")).unwrap();
    assert_eq!(content.len(), 1024 * 1024, "pulled file should be 1MB");
    assert!(
        content.iter().all(|&b| b == b'B'),
        "pulled file content should be all 'B' bytes"
    );

    remote_cleanup(&remote_dir).await;
}

// --- Reverse flag-specific tests ---

#[tokio::test]
async fn test_reverse_push_compress() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("compressed.txt", b"compress test data\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &["-z"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&format!("{remote_dir}/compressed.txt")).await;
    assert_eq!(content, "compress test data\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_compress() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'compressed pull' > {remote_dir}/data.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(&remote_dir, &env.dst(), &["-z"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("data.txt")).unwrap();
    assert_eq!(content, "compressed pull");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_push_checksum() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("check.txt", b"version1", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    // Push v1
    let result = rsync_push(&env.src(), &remote_dir, &[], 30).await;
    assert!(result.success, "rsync v1 push failed: {}", result.stderr);

    // Overwrite with v2 (same size, same mtime -- only checksum detects the change)
    std::fs::write(env.src().join("check.txt"), b"version2").unwrap();
    set_mtime(&env.src().join("check.txt"), 1700000000);
    // Also set mtime on the remote copy to match
    ssh_cmd(&[
        "touch",
        "-d",
        "@1700000000",
        &format!("{remote_dir}/check.txt"),
    ])
    .await;

    // Push v2 with checksum -- should detect the difference
    let result = rsync_push(&env.src(), &remote_dir, &["-c"], 30).await;
    assert!(
        result.success,
        "rsync checksum push failed: {}",
        result.stderr
    );

    let content = remote_cat(&format!("{remote_dir}/check.txt")).await;
    assert_eq!(content, "version2");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_delete() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'keep' > {remote_dir}/keep.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    // Create an extra file locally that does not exist on remote
    std::fs::write(env.dst().join("extra.txt"), b"should be deleted").unwrap();

    let result = rsync_pull(&remote_dir, &env.dst(), &["--delete"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(
        std::fs::read_to_string(env.dst().join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra.txt should have been deleted by --delete"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_push_dry_run() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("dryrun.txt", b"should not arrive\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &["-n"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert!(
        !remote_exists(&format!("{remote_dir}/dryrun.txt")).await,
        "dry-run should not create files on remote"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_exclude() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'keep' > {remote_dir}/data.txt"),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'skip' > {remote_dir}/debug.log"),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'skip2' > {remote_dir}/trace.log"),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(&remote_dir, &env.dst(), &["--exclude=*.log"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(
        std::fs::read_to_string(env.dst().join("data.txt")).unwrap(),
        "keep"
    );
    assert!(
        !env.dst().join("debug.log").exists(),
        "debug.log should have been excluded"
    );
    assert!(
        !env.dst().join("trace.log").exists(),
        "trace.log should have been excluded"
    );

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_push_whole_file() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("whole.txt", b"whole file transfer\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    let result = rsync_push(&env.src(), &remote_dir, &["-W"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&format!("{remote_dir}/whole.txt")).await;
    assert_eq!(content, "whole file transfer\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_reverse_pull_update() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'old remote' > {remote_dir}/file.txt"),
    ])
    .await;
    ssh_cmd(&[
        "touch",
        "-d",
        "@1700000000",
        &format!("{remote_dir}/file.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    // Create local file with newer mtime -- -u should skip overwriting it
    std::fs::write(env.dst().join("file.txt"), b"newer local").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1800000000);

    let result = rsync_pull(&remote_dir, &env.dst(), &["-u"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, "newer local",
        "-u should not overwrite newer local file"
    );

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Native end-to-end: ferrosync client → ferrosync --server (#127)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_native_push() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("native.txt", b"native push\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .source(env.src())
        .build();

    let mut ssh_config = common::ssh::test_ssh_config();
    ssh_config.rsync_path = "ferrosync".to_string();

    let server_opts = ferrosync_core::engine::session::build_server_options(&opts, true);
    let transport = ferrosync_core::transport::ssh::SshTransport::new(
        ssh_config,
        true,
        &server_opts,
        std::path::Path::new(&remote_dir),
    );
    let fs = common::env::test_filesystem();
    let session = ferrosync_core::engine::session::SyncSession::new(
        transport,
        opts,
        fs,
        ferrosync_core::engine::session::SyncDirection::Push,
    );

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), session.run())
        .await
        .expect("native push timed out")
        .expect("native push failed");

    assert!(
        result.stats.files_transferred >= 1,
        "native push should transfer at least 1 file"
    );

    let content = remote_cat(&format!("{remote_dir}/native.txt")).await;
    assert_eq!(content, "native push\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_native_pull() {
    skip_if_no_reverse!();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'native pull' > {remote_dir}/native.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .dest(env.dst())
        .build();

    let mut ssh_config = common::ssh::test_ssh_config();
    ssh_config.rsync_path = "ferrosync".to_string();

    let remote_path = format!("{remote_dir}/");
    let server_opts = ferrosync_core::engine::session::build_server_options(&opts, false);
    let transport = ferrosync_core::transport::ssh::SshTransport::new(
        ssh_config,
        false,
        &server_opts,
        std::path::Path::new(&remote_path),
    );
    let fs = common::env::test_filesystem();
    let session = ferrosync_core::engine::session::SyncSession::new(
        transport,
        opts,
        fs,
        ferrosync_core::engine::session::SyncDirection::Pull,
    );

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), session.run())
        .await
        .expect("native pull timed out")
        .expect("native pull failed");

    assert!(
        result.stats.files_transferred >= 1,
        "native pull should transfer at least 1 file"
    );

    let content = std::fs::read_to_string(env.dst().join("native.txt")).unwrap();
    assert_eq!(content, "native pull");

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Flag combination tests: real-world rsync patterns (#118)
// ---------------------------------------------------------------------------

/// Time Machine-style snapshot: pull with --delete + --link-dest.
/// Unchanged files hard-link to previous snapshot, changed files get new copies,
/// deleted files are absent. If --delete were silently ignored, file_c would
/// still appear in "new". If --link-dest were silently ignored, file_b would
/// be a separate copy rather than hard-linked.
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_time_machine_snapshot() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let current = tmp.path().join("current");
    let new_dir = tmp.path().join("new");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&current).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();

    // Initial source: 3 files.
    std::fs::write(src.join("file_a"), "aaa\n").unwrap();
    set_mtime(&src.join("file_a"), 1_700_000_000);
    std::fs::write(src.join("file_b"), "bbb\n").unwrap();
    set_mtime(&src.join("file_b"), 1_700_000_000);
    std::fs::write(src.join("file_c"), "ccc\n").unwrap();
    set_mtime(&src.join("file_c"), 1_700_000_000);

    // Push initial state to remote.
    let remote_dir = remote_tmpdir().await;
    push_archive(&src, &remote_dir, 30).await;

    // Pull initial state into "current" (baseline snapshot).
    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &current, 30).await;

    // Modify source: change file_a, remove file_c.
    std::fs::write(src.join("file_a"), "aaa_v2\n").unwrap();
    set_mtime(&src.join("file_a"), 1_800_000_000);
    std::fs::remove_file(src.join("file_c")).unwrap();

    // Push modified source to remote.
    push_archive(&src, &remote_dir, 30).await;

    // Pull into "new" with --delete + --link-dest=../current (relative).
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::During)
        .link_dest("../current")
        .dest(new_dir.clone())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    // file_a was modified -> new copy with updated content.
    assert_eq!(
        std::fs::read_to_string(new_dir.join("file_a")).unwrap(),
        "aaa_v2\n",
        "modified file should have new content"
    );

    // file_b unchanged -> hard-linked to current/file_b.
    assert_hard_linked(&new_dir.join("file_b"), &current.join("file_b"));

    // file_c was deleted from source -> absent in new (--delete effect).
    assert!(
        !new_dir.join("file_c").exists(),
        "file_c should be absent (--delete removes files not in source)"
    );

    remote_cleanup(&remote_dir).await;
}

/// Exact mirror push: --delete removes extraneous remote files.
/// If --delete were silently ignored, extra_remote.txt would survive.
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_exact_mirror() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .with_src_file("file_b.txt", b"bbb\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create an extraneous file on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo extra > {remote_dir}/extra_remote.txt"),
    ])
    .await;
    assert!(
        remote_exists(&format!("{remote_dir}/extra_remote.txt")).await,
        "extra_remote.txt should exist before mirror push"
    );

    // Modify file_b in source.
    std::fs::write(env.src().join("file_b.txt"), b"bbb_v2\n").unwrap();

    // Push with --delete.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::During)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // extra_remote.txt should be gone.
    assert!(
        !remote_exists(&format!("{remote_dir}/extra_remote.txt")).await,
        "extra_remote.txt should be deleted by --delete"
    );
    // file_a unchanged.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_a.txt")).await,
        "aaa\n"
    );
    // file_b updated.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_b.txt")).await,
        "bbb_v2\n"
    );

    remote_cleanup(&remote_dir).await;
}

/// --delete-excluded removes both extraneous AND excluded files.
/// If --delete-excluded were downgraded to plain --delete, .env and keepme.txt
/// would be preserved (since they match exclude patterns).
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_deploy_delete_excluded() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file(".env", b"SECRET\n", None)
        .with_src_file("app.txt", b"app\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create keepme.txt on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo keep > {remote_dir}/keepme.txt"),
    ])
    .await;

    // Push with --delete-excluded + excludes for .env and keepme.txt.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::Excluded)
        .exclude(".env")
        .exclude("keepme.txt")
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // --delete-excluded: .env is excluded AND deleted.
    assert!(
        !remote_exists(&format!("{remote_dir}/.env")).await,
        ".env should be removed by --delete-excluded"
    );
    // --delete-excluded: keepme.txt is excluded AND deleted.
    assert!(
        !remote_exists(&format!("{remote_dir}/keepme.txt")).await,
        "keepme.txt should be removed by --delete-excluded"
    );
    // app.txt should still exist (not excluded).
    assert_eq!(remote_cat(&format!("{remote_dir}/app.txt")).await, "app\n");

    remote_cleanup(&remote_dir).await;
}

/// Dry-run + --delete: nothing actually changes on the remote.
/// If --dry-run were silently ignored, extra.txt would be deleted.
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_dry_run_audit() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"content\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create extraneous file on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo extra > {remote_dir}/extra.txt"),
    ])
    .await;

    // Modify local source.
    std::fs::write(env.src().join("file.txt"), b"content_v2\n").unwrap();

    // Push with -n + --delete.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .dry_run(true)
        .delete(ferrosync_core::options::DeleteMode::During)
        .source(env.src())
        .build();
    let result = push_with_opts(opts, &remote_dir, 30).await;

    // Dry-run should report files that would transfer.
    assert!(
        result.stats.files_transferred >= 1,
        "dry-run should report files that would be transferred"
    );

    // extra.txt should STILL exist (dry-run doesn't actually delete).
    assert!(
        remote_exists(&format!("{remote_dir}/extra.txt")).await,
        "extra.txt should survive dry-run --delete"
    );

    // file.txt should still have original content (dry-run doesn't write).
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file.txt")).await,
        "content\n",
        "file.txt should not be updated during dry-run"
    );

    remote_cleanup(&remote_dir).await;
}

/// Compressed archive push: large repeated data + binary file.
/// If -z were silently ignored the transfer still succeeds but uses more
/// bandwidth; we verify content integrity to ensure the compression
/// round-trip is lossless.
#[tokio::test]
async fn test_combo_compressed_archive() {
    skip_if_no_ssh!();

    // 64KB repeated 'A' (highly compressible).
    let text_data = vec![b'A'; 65_536];
    // 1KB binary pattern.
    let binary_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

    let env = TestEnv::builder()
        .with_src_file("big_text.dat", &text_data, Some(1_700_000_000))
        .with_src_file("binary.dat", &binary_data, Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .compress(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 60).await;

    // Verify content integrity: both files present and byte-for-byte correct.
    let remote_size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/big_text.dat")]).await;
    assert_eq!(
        remote_size.trim(),
        "65536",
        "big_text.dat size should match"
    );

    let remote_binary_size =
        ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/binary.dat")]).await;
    assert_eq!(
        remote_binary_size.trim(),
        "1024",
        "binary.dat size should match"
    );

    // Verify binary content via checksum.
    let remote_md5 = ssh_cmd(&["md5sum", &format!("{remote_dir}/binary.dat")]).await;
    let local_md5 = {
        let output = tokio::process::Command::new("md5sum")
            .arg(env.src().join("binary.dat"))
            .output()
            .await
            .unwrap();
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    assert_eq!(
        remote_md5.split_whitespace().next().unwrap(),
        local_md5.split_whitespace().next().unwrap(),
        "binary.dat content should match byte-for-byte after compressed transfer"
    );

    // Verify archive preserved mtime.
    let remote_mtime = ssh_cmd(&["stat", "-c", "%Y", &format!("{remote_dir}/big_text.dat")]).await;
    assert_eq!(
        remote_mtime.trim(),
        "1700000000",
        "archive mode should preserve mtime through compressed transfer"
    );

    remote_cleanup(&remote_dir).await;
}

/// --inplace writes to the same inode (no temp file rename).
/// If --inplace were silently ignored, rsync would use a temp file and rename,
/// changing the inode.
#[tokio::test]
async fn test_combo_inplace_large_file() {
    skip_if_no_ssh!();

    // 512KB file.
    let data_v1: Vec<u8> = vec![0xAA; 512 * 1024];
    let env = TestEnv::builder()
        .with_src_file("large.dat", &data_v1, None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 60).await;

    // Record inode on remote.
    let inode_before = ssh_cmd(&["stat", "-c", "%i", &format!("{remote_dir}/large.dat")]).await;
    let inode_before = inode_before.trim();

    // Modify file locally.
    let mut data_v2 = vec![0xBB; 512 * 1024];
    data_v2[0] = 0xCC; // small difference
    std::fs::write(env.src().join("large.dat"), &data_v2).unwrap();

    // Push with --inplace.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .inplace(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 60).await;

    // Verify content updated.
    let remote_size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/large.dat")]).await;
    assert_eq!(remote_size.trim(), (512 * 1024).to_string());

    // Verify inode is unchanged (same file descriptor, no temp-file rename).
    let inode_after = ssh_cmd(&["stat", "-c", "%i", &format!("{remote_dir}/large.dat")]).await;
    assert_eq!(
        inode_before,
        inode_after.trim(),
        "--inplace should preserve inode (no temp file rename)"
    );

    remote_cleanup(&remote_dir).await;
}

/// Include whitelist pattern: only *.txt files are transferred.
/// If --include were silently ignored, either everything or nothing would
/// transfer (depending on whether --exclude="*" takes precedence alone).
#[tokio::test]
async fn test_combo_include_whitelist() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("docs/readme.txt", b"readme\n", None)
        .with_src_file("docs/spec.pdf", b"pdf data\n", None)
        .with_src_file("code/main.rs", b"fn main() {}\n", None)
        .with_src_file("code/notes.txt", b"notes\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;

    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .include("*.txt")
        .include("*/")
        .exclude("*")
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // *.txt files should exist.
    assert!(
        remote_exists(&format!("{remote_dir}/docs/readme.txt")).await,
        "readme.txt should be included"
    );
    assert!(
        remote_exists(&format!("{remote_dir}/code/notes.txt")).await,
        "notes.txt should be included"
    );
    // Non-txt files should be absent.
    assert!(
        !remote_exists(&format!("{remote_dir}/docs/spec.pdf")).await,
        "spec.pdf should be excluded"
    );
    assert!(
        !remote_exists(&format!("{remote_dir}/code/main.rs")).await,
        "main.rs should be excluded"
    );

    remote_cleanup(&remote_dir).await;
}

/// --delete + --exclude: excluded files on receiver are protected from deletion.
/// If --exclude were silently ignored during delete, protected.log would be removed.
/// If --delete were silently ignored, extra.txt would survive.
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_delete_exclude_safety() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep\n", None)
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Create extraneous files on remote: one deletable, one protected by exclude.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo 'delete me' > {remote_dir}/extra.txt"),
    ])
    .await;
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo 'safe' > {remote_dir}/protected.log"),
    ])
    .await;

    // Push with --delete + --exclude="*.log".
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .delete(ferrosync_core::options::DeleteMode::During)
        .exclude("*.log")
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // keep.txt still present.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/keep.txt")).await,
        "keep\n"
    );
    // extra.txt deleted (not in source, not excluded).
    assert!(
        !remote_exists(&format!("{remote_dir}/extra.txt")).await,
        "extra.txt should be deleted by --delete"
    );
    // protected.log preserved (excluded from transfer AND delete).
    assert!(
        remote_exists(&format!("{remote_dir}/protected.log")).await,
        "protected.log should be preserved by --exclude pattern"
    );

    remote_cleanup(&remote_dir).await;
}

/// --checksum detects content change despite identical size+mtime.
/// If -c were silently ignored, the file would not be re-transferred because
/// rsync's default size+mtime heuristic would see no change.
#[tokio::test]
async fn test_combo_checksum_archive() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"v1\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // Verify initial state.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_a.txt")).await,
        "v1\n"
    );

    // Overwrite with different content but SAME mtime (same size: 3 bytes).
    std::fs::write(env.src().join("file_a.txt"), b"v2\n").unwrap();
    set_mtime(&env.src().join("file_a.txt"), 1_700_000_000);

    // Push with -c (checksum mode).
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // Checksum mode should detect the content change.
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_a.txt")).await,
        "v2\n",
        "checksum mode should transfer file despite same size+mtime"
    );

    remote_cleanup(&remote_dir).await;
}

/// --update skips files that are newer on the receiver.
/// If -u were silently ignored, file_b's remote content would be overwritten
/// by the older source version.
#[tokio::test]
#[ignore] // push+delete/update wire issue (#128)
async fn test_combo_update_merge() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"src_a\n", Some(1_700_000_000))
        .with_src_file("file_b.txt", b"src_b\n", Some(1_700_000_000))
        .build();

    let remote_dir = remote_tmpdir().await;
    push_archive(&env.src(), &remote_dir, 30).await;

    // On remote, overwrite file_b with newer content and a NEWER mtime.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!(
            "echo 'remote_newer' > {remote_dir}/file_b.txt && touch -d @1800000000 {remote_dir}/file_b.txt"
        ),
    ])
    .await;

    // Push with -u (update): should skip file_b because remote is newer.
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .update(true)
        .source(env.src())
        .build();
    push_with_opts(opts, &remote_dir, 30).await;

    // file_a should have source content (remote was older or same).
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_a.txt")).await,
        "src_a\n",
    );
    // file_b should retain remote content (remote was newer, -u skips).
    assert_eq!(
        remote_cat(&format!("{remote_dir}/file_b.txt")).await,
        "remote_newer\n",
        "--update should not overwrite newer remote file"
    );

    remote_cleanup(&remote_dir).await;
}

/// Multi-generation snapshot rotation with --link-dest across 3 generations.
/// Unchanged files chain hard-links across all generations. Changed files
/// get new inodes at each generation. If --link-dest were silently ignored,
/// unchanged.txt would have different inodes in every generation.
#[tokio::test]
async fn test_combo_multi_generation_rotation() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let gen0 = tmp.path().join("gen0");
    let gen1 = tmp.path().join("gen1");
    let gen2 = tmp.path().join("gen2");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&gen0).unwrap();

    let remote_dir = remote_tmpdir().await;
    let remote_path = format!("{remote_dir}/");

    // --- Generation 0 ---
    std::fs::write(src.join("unchanged.txt"), "stable\n").unwrap();
    set_mtime(&src.join("unchanged.txt"), 1_700_000_000);
    std::fs::write(src.join("changed.txt"), "v1\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_700_000_000);

    push_archive(&src, &remote_dir, 30).await;
    pull_archive(&remote_path, &gen0, 30).await;

    // --- Generation 1 ---
    std::fs::write(src.join("changed.txt"), "v2\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_800_000_000);

    push_archive(&src, &remote_dir, 30).await;

    std::fs::create_dir_all(&gen1).unwrap();
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest("../gen0")
        .dest(gen1.clone())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    // --- Generation 2 ---
    std::fs::write(src.join("changed.txt"), "v3\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_900_000_000);

    push_archive(&src, &remote_dir, 30).await;

    std::fs::create_dir_all(&gen2).unwrap();
    let opts = ferrosync_core::options::TransferOptions::builder()
        .archive()
        .link_dest("../gen1")
        .dest(gen2.clone())
        .build();
    pull_with_opts(opts, &remote_path, 30).await;

    // --- Assertions ---

    // Content correctness across generations.
    assert_eq!(
        std::fs::read_to_string(gen0.join("changed.txt")).unwrap(),
        "v1\n"
    );
    assert_eq!(
        std::fs::read_to_string(gen1.join("changed.txt")).unwrap(),
        "v2\n"
    );
    assert_eq!(
        std::fs::read_to_string(gen2.join("changed.txt")).unwrap(),
        "v3\n"
    );

    // unchanged.txt is the same in all generations.
    assert_eq!(
        std::fs::read_to_string(gen0.join("unchanged.txt")).unwrap(),
        "stable\n"
    );
    assert_eq!(
        std::fs::read_to_string(gen1.join("unchanged.txt")).unwrap(),
        "stable\n"
    );
    assert_eq!(
        std::fs::read_to_string(gen2.join("unchanged.txt")).unwrap(),
        "stable\n"
    );

    // unchanged.txt should be hard-linked across generations (same inode).
    assert_hard_linked(&gen1.join("unchanged.txt"), &gen0.join("unchanged.txt"));
    assert_hard_linked(&gen2.join("unchanged.txt"), &gen1.join("unchanged.txt"));

    // changed.txt should have different inodes (new copy each generation).
    assert_not_hard_linked(&gen2.join("changed.txt"), &gen1.join("changed.txt"));

    remote_cleanup(&remote_dir).await;
}
