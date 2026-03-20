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
