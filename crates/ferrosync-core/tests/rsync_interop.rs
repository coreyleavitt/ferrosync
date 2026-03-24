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
