//! Pull tests: ferrosync client <- rsync server over SSH.

use crate::common::assertions::*;
use crate::common::env::{set_mtime, TestEnv};
use crate::common::ssh::*;
use crate::common::TransferOptions;
use crate::skip_if_no_ssh;

#[tokio::test]
async fn test_interop_pull_single_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("pull.txt", b"pulled via SSH\n", None)
            .build(),
    )
    .await;

    ctx.push_then_pull(30).await;

    let content = std::fs::read_to_string(ctx.env.dst().join("pull.txt")).unwrap();
    assert_eq!(content, "pulled via SSH\n");

    let meta = std::fs::metadata(ctx.env.dst().join("pull.txt")).unwrap();
    assert_eq!(meta.len(), 15, "pulled file should be 15 bytes");
}

#[tokio::test]
async fn test_interop_pull_directory_recursive() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("top.txt", b"top\n", None)
            .with_src_file("sub/deep.txt", b"deep\n", None)
            .build(),
    )
    .await;

    ctx.push_then_pull(30).await;

    assert_eq!(
        std::fs::read_to_string(ctx.env.dst().join("top.txt")).unwrap(),
        "top\n"
    );
    assert_eq!(
        std::fs::read_to_string(ctx.env.dst().join("sub/deep.txt")).unwrap(),
        "deep\n"
    );
    assert!(
        ctx.env.dst().join("sub").is_dir(),
        "sub/ should be a directory"
    );
}

#[tokio::test]
async fn test_interop_pull_large_file() {
    skip_if_no_ssh!();

    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("big.dat", &data, None)
            .build(),
    )
    .await;

    let result = ctx.push_then_pull(60).await;
    assert_eq!(result.stats.files_transferred, 1);

    let pulled = std::fs::read(ctx.env.dst().join("big.dat")).unwrap();
    assert_eq!(pulled.len(), 1_048_576, "pulled file should be 1MB");
    assert_eq!(pulled, data, "large file content mismatch after pull");
}

#[tokio::test]
async fn test_interop_pull_empty_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    ssh_cmd(&["touch", &ctx.remote.join("empty.txt")]).await;

    ctx.pull(30).await;

    assert!(
        ctx.env.dst().join("empty.txt").exists(),
        "empty file should exist"
    );
    let content = std::fs::read(ctx.env.dst().join("empty.txt")).unwrap();
    assert!(content.is_empty());
    assert_eq!(content.len(), 0);
}

#[tokio::test]
async fn test_interop_pull_archive_mode() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("archive.txt", b"archive mode pull\n", None)
            .build(),
    )
    .await;

    ctx.push_then_pull(30).await;

    let content = std::fs::read_to_string(ctx.env.dst().join("archive.txt")).unwrap();
    assert_eq!(content, "archive mode pull\n");

    // Archive mode preserves mtime from the source file.
    let src_mtime = std::fs::metadata(ctx.env.src().join("archive.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_mtime(&ctx.env.dst().join("archive.txt"), src_mtime, 1);
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

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"hello\n", Some(1_700_000_000))
            .with_prev_file("file_a.txt", b"hello\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .link_dest(ctx.env.prev())
        .build();

    ctx.push_then_pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap();
    assert_eq!(content, b"hello\n");

    assert_hard_linked(
        &ctx.env.dst().join("file_a.txt"),
        &ctx.env.prev().join("file_a.txt"),
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_relative_path() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    let base = ctx.env.dir().join("base");
    let current = base.join("current");
    let new_dir = base.join("new");
    std::fs::create_dir_all(&current).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();

    std::fs::write(current.join("file.txt"), "content\n").unwrap();
    set_mtime(&current.join("file.txt"), 1_700_000_000);

    // Push current to remote.
    push_archive(&current, ctx.remote.path(), 30).await;

    let opts = TransferOptions::builder()
        .archive()
        .link_dest("../current")
        .dest(new_dir.clone())
        .build();

    let remote_path = ctx.remote.path_slash();
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(new_dir.join("file.txt")).unwrap();
    assert_eq!(content, b"content\n");

    assert_hard_linked(&new_dir.join("file.txt"), &current.join("file.txt"));
}

#[tokio::test]
async fn test_interop_pull_link_dest_multiple_dirs() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", Some(1_700_000_000))
            .with_src_file("file_b.txt", b"bbb\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    let alt1 = ctx.env.dir().join("alt1");
    let alt2 = ctx.env.dir().join("alt2");
    std::fs::create_dir_all(&alt1).unwrap();
    std::fs::create_dir_all(&alt2).unwrap();

    std::fs::write(alt1.join("file_a.txt"), "aaa\n").unwrap();
    set_mtime(&alt1.join("file_a.txt"), 1_700_000_000);
    std::fs::write(alt2.join("file_b.txt"), "bbb\n").unwrap();
    set_mtime(&alt2.join("file_b.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .archive()
        .link_dest(&alt1)
        .link_dest(&alt2)
        .build();

    ctx.push_then_pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );

    assert_hard_linked(&ctx.env.dst().join("file_a.txt"), &alt1.join("file_a.txt"));
    assert_hard_linked(&ctx.env.dst().join("file_b.txt"), &alt2.join("file_b.txt"));
}

#[tokio::test]
async fn test_interop_pull_link_dest_mtime_mismatch() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"same content\n", Some(1_700_000_000))
            .with_prev_file("file.txt", b"same content\n", Some(1_600_000_000))
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .link_dest(ctx.env.prev())
        .build();

    ctx.push_then_pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"same content\n");

    assert_not_hard_linked(
        &ctx.env.dst().join("file.txt"),
        &ctx.env.prev().join("file.txt"),
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_changed_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            // file_a: changed between prev and src
            .with_src_file("file_a.txt", b"version 2\n", Some(1_700_000_000))
            .with_prev_file("file_a.txt", b"version 1\n", Some(1_600_000_000))
            // file_b: unchanged between prev and src
            .with_src_file("file_b.txt", b"same\n", Some(1_700_000_000))
            .with_prev_file("file_b.txt", b"same\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .link_dest(ctx.env.prev())
        .build();

    ctx.push_then_pull_opts(opts, 30).await;

    // Unchanged file should be hard-linked.
    assert_hard_linked(
        &ctx.env.dst().join("file_b.txt"),
        &ctx.env.prev().join("file_b.txt"),
    );

    // Changed file should be a new copy.
    assert_not_hard_linked(
        &ctx.env.dst().join("file_a.txt"),
        &ctx.env.prev().join("file_a.txt"),
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"version 2\n"
    );
}

#[tokio::test]
async fn test_interop_link_dest_snapshot_rotation() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    let src = ctx.env.dir().join("rotation_src");
    let backup_0 = ctx.env.dir().join("backup_0");
    let backup_1 = ctx.env.dir().join("backup_1");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&backup_0).unwrap();

    // Initial source state.
    std::fs::write(src.join("file_a.txt"), "original\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);
    std::fs::write(src.join("file_b.txt"), "stable\n").unwrap();
    set_mtime(&src.join("file_b.txt"), 1_700_000_000);

    // First sync: push src to remote, pull into backup_0 (no link-dest).
    push_archive(&src, ctx.remote.path(), 30).await;
    let remote_path = ctx.remote.path_slash();
    pull_archive(&remote_path, &backup_0, 30).await;

    // Modify source: change file_a, leave file_b stable.
    std::fs::write(src.join("file_a.txt"), "modified\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_001_000);

    // Update remote with modified source.
    push_archive(&src, ctx.remote.path(), 30).await;

    // Second sync: pull into backup_1 with --link-dest=backup_0/.
    std::fs::create_dir_all(&backup_1).unwrap();
    let opts = TransferOptions::builder()
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
}

#[tokio::test]
async fn test_interop_link_dest_rerun_idempotent() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"idempotent\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    // First pull: no link-dest.
    ctx.push_then_pull(30).await;

    // Create prev/ as a copy of dst/ with matching content and mtimes.
    let prev = ctx.env.dir().join("prev");
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::copy(ctx.env.dst().join("file.txt"), prev.join("file.txt")).unwrap();
    set_mtime(&prev.join("file.txt"), 1_700_000_000);

    // Re-run pull with link-dest=prev into a fresh dst.
    let dst2 = ctx.env.dir().join("dst2");
    std::fs::create_dir_all(&dst2).unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .link_dest(&prev)
        .dest(dst2.clone())
        .build();
    let remote_path = ctx.remote.path_slash();
    pull_with_opts(opts, &remote_path, 30).await;

    let content = std::fs::read(dst2.join("file.txt")).unwrap();
    assert_eq!(content, b"idempotent\n");

    // Idempotent re-run with link-dest should hard-link to prev snapshot.
    assert_hard_linked(&dst2.join("file.txt"), &prev.join("file.txt"));
}

// ---------------------------------------------------------------------------
// Delete tests (wire transfer --delete support)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_pull_delete_before() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .with_src_file("file_b.txt", b"bbb\n", None)
            .build(),
    )
    .await;

    // Push source files to remote.
    ctx.push(30).await;

    // Create an extra file in the local destination.
    std::fs::create_dir_all(ctx.env.dst()).unwrap();
    std::fs::write(ctx.env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    // Pull with --delete-before.
    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::Before)
        .build();

    let result = ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);
}

#[tokio::test]
async fn test_interop_pull_delete_during() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .with_src_file("file_b.txt", b"bbb\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    std::fs::create_dir_all(ctx.env.dst()).unwrap();
    std::fs::write(ctx.env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::During)
        .build();

    let result = ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);
}

#[tokio::test]
async fn test_interop_pull_delete_after() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .with_src_file("file_b.txt", b"bbb\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    std::fs::create_dir_all(ctx.env.dst()).unwrap();
    std::fs::write(ctx.env.dst().join("extra.txt"), "should be deleted\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::After)
        .build();

    let result = ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("extra.txt").exists(),
        "extra file should be deleted"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_b.txt")).unwrap(),
        b"bbb\n"
    );
    assert!(result.stats.files_deleted >= 1);
}

#[tokio::test]
async fn test_interop_pull_delete_with_exclude() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Create extra files locally: one should be deleted, one protected by exclude.
    std::fs::create_dir_all(ctx.env.dst()).unwrap();
    std::fs::write(ctx.env.dst().join("extra.txt"), "delete me\n").unwrap();
    std::fs::write(ctx.env.dst().join("keep.log"), "protected\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::During)
        .exclude("*.log")
        .build();

    ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("extra.txt").exists(),
        "extra.txt should be deleted"
    );
    assert!(
        ctx.env.dst().join("keep.log").exists(),
        "excluded *.log should be preserved"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
}

#[tokio::test]
async fn test_interop_pull_delete_excluded() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Create extra files locally: both should be deleted with --delete-excluded.
    std::fs::create_dir_all(ctx.env.dst()).unwrap();
    std::fs::write(ctx.env.dst().join("extra.txt"), "delete me\n").unwrap();
    std::fs::write(ctx.env.dst().join("keep.log"), "also delete me\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::Excluded)
        .exclude("*.log")
        .build();

    ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("extra.txt").exists(),
        "extra.txt should be deleted"
    );
    assert!(
        !ctx.env.dst().join("keep.log").exists(),
        "excluded *.log should also be deleted"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file_a.txt")).unwrap(),
        b"aaa\n"
    );
}

#[tokio::test]
async fn test_interop_pull_size_only() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"src data\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local dest with same-length but different content and mtime.
    std::fs::write(ctx.env.dst().join("file.txt"), b"old data\n").unwrap();
    set_mtime(&ctx.env.dst().join("file.txt"), 1_600_000_000);

    // Pull with --size-only: should skip because sizes match (9 bytes both).
    let opts = TransferOptions::builder().archive().size_only(true).build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"old data\n",
        "size-only should skip same-size file"
    );
}

#[tokio::test]
async fn test_interop_pull_existing() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("present.txt", b"updated\n", None)
            .with_src_file("absent.txt", b"new file\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-create only present.txt on local dest.
    std::fs::write(ctx.env.dst().join("present.txt"), "old\n").unwrap();

    let opts = TransferOptions::builder().archive().existing(true).build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("present.txt")).unwrap(),
        b"updated\n",
    );
    assert!(
        !ctx.env.dst().join("absent.txt").exists(),
        "--existing should skip files not on dest"
    );
}

#[tokio::test]
async fn test_interop_pull_ignore_existing() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("present.txt", b"updated\n", None)
            .with_src_file("absent.txt", b"new file\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-create present.txt on local dest.
    std::fs::write(ctx.env.dst().join("present.txt"), "original\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .ignore_existing(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("present.txt")).unwrap(),
        b"original\n",
        "--ignore-existing should not overwrite"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("absent.txt")).unwrap(),
        b"new file\n",
    );
}

#[tokio::test]
async fn test_interop_pull_max_delete() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("keep.txt", b"keep\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-create extra files locally.
    std::fs::write(ctx.env.dst().join("keep.txt"), "keep\n").unwrap();
    std::fs::write(ctx.env.dst().join("extra1.txt"), "del\n").unwrap();
    std::fs::write(ctx.env.dst().join("extra2.txt"), "del\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .delete(crate::common::DeleteMode::Before)
        .max_delete(1)
        .build();
    ctx.pull_opts(opts, 30).await;

    let extra1 = ctx.env.dst().join("extra1.txt").exists();
    let extra2 = ctx.env.dst().join("extra2.txt").exists();
    let remaining = (extra1 as u32) + (extra2 as u32);
    assert_eq!(remaining, 1, "max-delete=1 should leave one extra file");

    // Verify keep.txt survived (it is in the source, should never be deleted).
    assert!(
        ctx.env.dst().join("keep.txt").exists(),
        "source file keep.txt must survive"
    );
    assert_eq!(
        std::fs::read(ctx.env.dst().join("keep.txt")).unwrap(),
        b"keep\n"
    );
}

#[tokio::test]
async fn test_interop_pull_prune_empty_dirs() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("a/file.txt", b"content\n", None)
            .build(),
    )
    .await;

    // Also create an empty dir on remote.
    ctx.push(30).await;
    ssh_cmd(&["mkdir", "-p", &ctx.remote.join("empty_dir")]).await;

    let opts = TransferOptions::builder()
        .archive()
        .prune_empty_dirs(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert!(ctx.env.dst().join("a/file.txt").exists());
    assert!(
        !ctx.env.dst().join("empty_dir").exists(),
        "empty dir should be pruned"
    );
}

#[tokio::test]
async fn test_interop_pull_checksum() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"aaa\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local dest with same content+mtime.
    std::fs::write(ctx.env.dst().join("file.txt"), b"aaa\n").unwrap();
    set_mtime(&ctx.env.dst().join("file.txt"), 1_700_000_000);

    // Update remote with different content but same size+mtime.
    std::fs::write(ctx.env.src().join("file.txt"), b"bbb\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_700_000_000);
    let push_opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .source(ctx.env.src())
        .build();
    push_with_opts(push_opts, ctx.remote.path(), 30).await;

    // Pull with --checksum: should detect content differs.
    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"bbb\n",
        "checksum pull should detect content change"
    );
}

#[tokio::test]
async fn test_interop_pull_whole_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"whole file pull\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local dest as basis.
    std::fs::write(ctx.env.dst().join("file.txt"), b"old basis data\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .whole_file(true)
        .build();
    let result = ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"whole file pull\n");
    assert_eq!(
        result.stats.matched_data, 0,
        "whole-file should not use delta matching"
    );
}

#[tokio::test]
async fn test_interop_pull_compress() {
    skip_if_no_ssh!();

    let data = vec![b'A'; 65536];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("repeated.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder().archive().compress(true).build();
    ctx.push_then_pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("repeated.dat")).unwrap();
    assert_eq!(content.len(), 65536);
    assert!(
        content.iter().all(|&b| b == b'A'),
        "all 65536 bytes should be 'A'"
    );
    assert_eq!(
        content, data,
        "compressed transfer content must match source byte-for-byte"
    );
}

#[tokio::test]
async fn test_interop_pull_update() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"remote version\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local with different content and NEWER mtime.
    std::fs::write(ctx.env.dst().join("file.txt"), b"local newer\n").unwrap();
    set_mtime(&ctx.env.dst().join("file.txt"), 1_800_000_000);

    let opts = TransferOptions::builder().archive().update(true).build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"local newer\n",
        "--update should skip file with newer local mtime"
    );
}

#[tokio::test]
async fn test_interop_pull_inplace() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"updated content\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local dest with different content.
    std::fs::write(ctx.env.dst().join("file.txt"), b"original text\n").unwrap();
    let inode_before = crate::common::env::inode_of(&ctx.env.dst().join("file.txt"));

    let opts = TransferOptions::builder().archive().inplace(true).build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"updated content\n");

    let inode_after = crate::common::env::inode_of(&ctx.env.dst().join("file.txt"));
    assert_eq!(
        inode_before, inode_after,
        "--inplace should write to the same inode (no temp file)"
    );
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

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("sparse.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder().archive().sparse(true).build();
    ctx.push_then_pull_opts(opts, 60).await;

    let content = std::fs::read(ctx.env.dst().join("sparse.dat")).unwrap();
    assert_eq!(
        content, data,
        "sparse pull content should match byte-for-byte"
    );

    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(ctx.env.dst().join("sparse.dat")).unwrap();
    let allocated = meta.blocks() * 512;
    assert!(
        allocated < 1_048_576,
        "sparse file should use fewer blocks than full size (allocated={allocated})"
    );
}

#[tokio::test]
async fn test_interop_pull_exclude() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("keep.txt", b"keep me\n", None)
            .with_src_file("skip.log", b"skip me\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .exclude("*.log")
        .build();
    ctx.push_then_pull_opts(opts, 30).await;

    assert!(
        ctx.env.dst().join("keep.txt").exists(),
        "keep.txt should be pulled"
    );
    assert!(
        !ctx.env.dst().join("skip.log").exists(),
        "skip.log should be excluded from pull"
    );
}

#[tokio::test]
async fn test_interop_pull_include_exclude() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("data.txt", b"text\n", None)
            .with_src_file("data.csv", b"csv\n", None)
            .with_src_file("data.bin", b"bin\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .include("*.txt")
        .include("*/")
        .exclude("*")
        .build();
    ctx.push_then_pull_opts(opts, 30).await;

    assert!(
        ctx.env.dst().join("data.txt").exists(),
        "data.txt should be included"
    );
    assert!(
        !ctx.env.dst().join("data.csv").exists(),
        "data.csv should be excluded"
    );
    assert!(
        !ctx.env.dst().join("data.bin").exists(),
        "data.bin should be excluded"
    );
}

#[tokio::test]
async fn test_interop_pull_filter() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("main.c", b"int main() {}\n", None)
            .with_src_file("main.o", b"\x7fELF", None)
            .with_src_file("lib.a", b"!<arch>\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .filter("- *.o")
        .filter("- *.a")
        .build();
    ctx.push_then_pull_opts(opts, 30).await;

    assert!(
        ctx.env.dst().join("main.c").exists(),
        "main.c should be pulled"
    );
    assert!(
        !ctx.env.dst().join("main.o").exists(),
        "main.o should be filtered out"
    );
    assert!(
        !ctx.env.dst().join("lib.a").exists(),
        "lib.a should be filtered out"
    );
}

#[tokio::test]
async fn test_interop_pull_compare_dest() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"hello\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Create local alt dir with identical copy (same content+mtime).
    let alt_dir = ctx.env.dir().join("alt");
    std::fs::create_dir_all(&alt_dir).unwrap();
    std::fs::write(alt_dir.join("file.txt"), b"hello\n").unwrap();
    set_mtime(&alt_dir.join("file.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .archive()
        .compare_dest(&alt_dir)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("file.txt").exists(),
        "compare-dest should skip file when identical copy exists in alt dir"
    );
}

#[tokio::test]
async fn test_interop_pull_copy_dest() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"hello\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Create local alt dir with identical copy (same content+mtime).
    let alt_dir = ctx.env.dir().join("alt");
    std::fs::create_dir_all(&alt_dir).unwrap();
    std::fs::write(alt_dir.join("file.txt"), b"hello\n").unwrap();
    set_mtime(&alt_dir.join("file.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .archive()
        .copy_dest(&alt_dir)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert!(
        ctx.env.dst().join("file.txt").exists(),
        "copy-dest should create dest file"
    );
    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"hello\n");

    // Dest inode should differ from alt (it's a copy, not hard link).
    assert_not_hard_linked(&ctx.env.dst().join("file.txt"), &alt_dir.join("file.txt"));
}

#[tokio::test]
async fn test_interop_pull_backup() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"version one\n", None)
            .build(),
    )
    .await;

    // Push v1, pull to populate local.
    ctx.push_then_pull(30).await;
    assert_eq!(
        std::fs::read(ctx.env.dst().join("file.txt")).unwrap(),
        b"version one\n"
    );

    // Push v2 with different mtime to ensure transfer isn't skipped.
    std::fs::write(ctx.env.src().join("file.txt"), b"version two\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_800_000_000);
    ctx.push(30).await;

    // Pull with backup and checksum mode to force retransfer.
    let bak_dir = ctx.env.dst().join("bak");
    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .backup(true)
        .backup_dir(&bak_dir)
        .suffix(".old")
        .build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(content, b"version two\n", "file should have v2 content");

    let backup = std::fs::read(bak_dir.join("file.txt.old")).unwrap();
    assert_eq!(backup, b"version one\n", "backup should have v1 content");
}

#[tokio::test]
async fn test_interop_pull_dry_run() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"dry run pull\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder().archive().dry_run(true).build();
    ctx.push_then_pull_opts(opts, 30).await;

    assert!(
        !ctx.env.dst().join("file.txt").exists(),
        "dry-run pull should not create local file"
    );
}

#[tokio::test]
async fn test_interop_pull_append() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"abcdefghij\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-populate local dest with first 4 bytes.
    std::fs::write(ctx.env.dst().join("file.txt"), b"abcd").unwrap();

    let opts = TransferOptions::builder().archive().append(true).build();
    ctx.pull_opts(opts, 30).await;

    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"abcdefghij\n",
        "--append should complete partial file to full 11 bytes"
    );
}

#[tokio::test]
async fn test_interop_pull_itemize() {
    skip_if_no_ssh!();

    // Itemize changes (-i) tells the remote rsync generator to include
    // iflags in the wire protocol. This test verifies:
    // 1. The flag is correctly negotiated (transfer completes, not rejected)
    // 2. File content and metadata are correctly applied with itemize enabled
    // 3. The modified file was actually retransferred (not skipped)
    //
    // Note: FileItemized progress events are only emitted by the local engine
    // (engine tests cover this). Over SSH, the remote rsync generates iflags
    // and our receiver reads them from the wire but doesn't re-emit them as
    // progress events.

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"original\n", None)
            .build(),
    )
    .await;

    // Push and pull to populate local.
    ctx.push_then_pull(30).await;

    // Push updated version with different mtime to ensure transfer.
    std::fs::write(ctx.env.src().join("file.txt"), b"modified\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_800_000_000);
    ctx.push(30).await;

    // Pull with itemize-changes and checksum to force retransfer.
    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .itemize_changes(true)
        .build();
    let result = ctx.pull_opts(opts, 30).await;

    // Verify the file was retransferred with correct content.
    let content = std::fs::read(ctx.env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, b"modified\n",
        "file should be updated to modified content"
    );

    // The file must have been transferred (not skipped) since content changed.
    assert_eq!(
        result.stats.files_transferred, 1,
        "itemize+checksum pull should retransfer the modified file"
    );

    // Verify mtime was preserved (archive mode).
    let mtime = std::fs::metadata(ctx.env.dst().join("file.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        mtime, 1_800_000_000,
        "mtime should be preserved with -a and -i"
    );
}

#[tokio::test]
async fn test_interop_pull_stats() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("a.txt", b"aaa\n", None)
            .with_src_file("b.txt", b"bbb\n", None)
            .with_src_file("c.txt", b"ccc\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder().archive().stats(true).build();
    let result = ctx.push_then_pull_opts(opts, 30).await;

    // Verify exact expected stats for a known 3-file, 12-byte input.
    // These would be wrong if stats collection or the wire stats exchange failed.
    assert_eq!(
        result.stats.files_transferred, 3,
        "should transfer exactly 3 files"
    );
    assert_eq!(
        result.stats.total_size, 12,
        "total size should be 12 bytes (3 files x 4 bytes)"
    );
    assert_eq!(
        result.stats.literal_data, 12,
        "all data should be literal (no delta matching for new files)"
    );
    assert_eq!(
        result.stats.files_skipped, 0,
        "no files should be skipped (all are new)"
    );
    assert!(
        result.stats.bytes_received > 0,
        "should have received wire bytes"
    );
    assert!(
        result.stats.elapsed > std::time::Duration::ZERO,
        "elapsed time should be non-zero"
    );
}

#[tokio::test]
async fn test_interop_pull_bwlimit() {
    skip_if_no_ssh!();

    // Bandwidth limiting for SSH pulls is handled by the remote rsync
    // (--bwlimit is sent as a server option). This test verifies:
    // 1. The --bwlimit flag is accepted and correctly passed to remote rsync
    // 2. The transfer completes with correct content
    // 3. Wire stats are populated (bytes were actually transferred)
    //
    // Note: Timing-based throttling assertions are unreliable over Docker
    // localhost SSH. The local engine bwlimit is tested in engine tests.

    let data = vec![b'X'; 200 * 1024];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("large.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder().archive().bwlimit(102400).build();
    let result = ctx.push_then_pull_opts(opts, 60).await;

    let content = std::fs::read(ctx.env.dst().join("large.dat")).unwrap();
    assert_eq!(
        content.len(),
        200 * 1024,
        "bwlimit pull should transfer full 200KB"
    );
    assert_eq!(content, data, "bwlimit pull content should match");

    // Verify the file was actually transferred (not skipped).
    assert_eq!(
        result.stats.files_transferred, 1,
        "should transfer exactly 1 file"
    );
    assert!(
        result.stats.bytes_received > 0,
        "should receive wire bytes for the transfer"
    );
}

// ---------------------------------------------------------------------------
// Hardlink preservation (-H) tests
// ---------------------------------------------------------------------------

/// Pull with -aH preserves hardlink relationships: two files that are
/// hardlinked on the remote should share an inode locally after pull.
#[tokio::test]
async fn test_interop_pull_hardlinks_basic() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    // Create two files on remote, then hardlink them.
    ssh_cmd(&[&format!(
        "echo shared_content > {}/original.txt && \
         ln {}/original.txt {}/linked.txt",
        ctx.remote.path(),
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_hard_links(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    // Both files should exist with correct content.
    let content_a = std::fs::read(ctx.env.dst().join("original.txt")).unwrap();
    let content_b = std::fs::read(ctx.env.dst().join("linked.txt")).unwrap();
    assert_eq!(content_a, b"shared_content\n", "original.txt content wrong");
    assert_eq!(content_b, b"shared_content\n", "linked.txt content wrong");

    // They should share an inode (hardlinked).
    assert_hard_linked(
        &ctx.env.dst().join("original.txt"),
        &ctx.env.dst().join("linked.txt"),
    );
}

/// Pull with -aH preserves multiple independent hardlink groups.
/// Files within each group share inodes; files across groups do not.
#[tokio::test]
async fn test_interop_pull_hardlinks_multiple_groups() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    // Group A: two hardlinked files.
    ssh_cmd(&[&format!(
        "echo group_a > {}/a1.txt && \
         ln {}/a1.txt {}/a2.txt",
        ctx.remote.path(),
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;
    // Group B: two hardlinked files with different content.
    ssh_cmd(&[&format!(
        "echo group_b > {}/b1.txt && \
         ln {}/b1.txt {}/b2.txt",
        ctx.remote.path(),
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_hard_links(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    // Within group A: hardlinked.
    assert_hard_linked(&ctx.env.dst().join("a1.txt"), &ctx.env.dst().join("a2.txt"));
    // Within group B: hardlinked.
    assert_hard_linked(&ctx.env.dst().join("b1.txt"), &ctx.env.dst().join("b2.txt"));
    // Across groups: NOT hardlinked.
    assert_not_hard_linked(&ctx.env.dst().join("a1.txt"), &ctx.env.dst().join("b1.txt"));
}

#[tokio::test]
#[ignore = "#178 remove-source-files not working on pull"]
async fn test_interop_pull_remove_source_files() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("vanish.txt", b"pull and remove\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;
    assert!(remote_exists(&ctx.remote.join("vanish.txt")).await);

    let opts = TransferOptions::builder()
        .archive()
        .remove_source_files(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("vanish.txt")).unwrap(),
        b"pull and remove\n"
    );
    assert!(
        !remote_exists(&ctx.remote.join("vanish.txt")).await,
        "remove-source-files should delete remote file after pull"
    );
}

#[tokio::test]
async fn test_interop_pull_write_read_batch() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("alpha.txt", b"alpha content\n", None)
            .with_src_file("beta.txt", b"beta content\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    let dest_1 = ctx.env.dir().join("dest_1");
    std::fs::create_dir_all(&dest_1).unwrap();
    let batch_path = ctx.env.dir().join("the.batch");

    let opts = TransferOptions::builder()
        .archive()
        .write_batch(&batch_path)
        .dest(dest_1.clone())
        .build();
    pull_with_opts(opts, &ctx.remote.path_slash(), 30).await;

    assert_eq!(
        std::fs::read(dest_1.join("alpha.txt")).unwrap(),
        b"alpha content\n"
    );
    assert_eq!(
        std::fs::read(dest_1.join("beta.txt")).unwrap(),
        b"beta content\n"
    );
    assert!(
        batch_path.exists(),
        "write-batch should create a batch file"
    );

    let dest_2 = ctx.env.dir().join("dest_2");
    std::fs::create_dir_all(&dest_2).unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .read_batch(&batch_path)
        .dest(dest_2.clone())
        .build();
    pull_with_opts(opts, &ctx.remote.path_slash(), 30).await;

    assert_eq!(
        std::fs::read(dest_2.join("alpha.txt")).unwrap(),
        b"alpha content\n"
    );
    assert_eq!(
        std::fs::read(dest_2.join("beta.txt")).unwrap(),
        b"beta content\n"
    );
}

/// Interrupted pull should leave partial file in --partial-dir.
#[tokio::test]
async fn test_interop_pull_partial_dir() {
    skip_if_no_ssh!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[&format!(
        "dd if=/dev/urandom of={}/bigfile.dat bs=1024 count=1024 2>/dev/null",
        remote.path()
    )])
    .await;

    let env = TestEnv::builder().build();
    let partial_dir = env.dst().join(".rsync-partial");

    let opts = TransferOptions::builder()
        .archive()
        .partial_dir(&partial_dir)
        .bwlimit(8192)
        .dest(env.dst())
        .build();
    let pull_fut = start_pull(opts, &remote.path_slash());

    tokio::select! {
        result = pull_fut => {
            match result {
                Ok(_) => {
                    eprintln!("SKIP: transfer completed before cancellation");
                    return;
                }
                Err(e) => {
                    eprintln!("transfer errored (expected during cancellation): {e}");
                }
            }
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
    }

    let partial_file = partial_dir.join("bigfile.dat");
    assert!(partial_dir.exists(), "--partial-dir should be created");
    assert!(
        partial_file.exists(),
        "partial file should exist in --partial-dir"
    );

    let partial_size = std::fs::metadata(&partial_file).unwrap().len();
    assert!(
        partial_size > 0 && partial_size < 1024 * 1024,
        "partial file should be between 0 and 1MB, got {partial_size}"
    );
}

#[tokio::test]
async fn test_interop_pull_xattr() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    ssh_cmd(&[&format!(
        "echo -n 'xattr pull test' > {}/xfile.txt && \
         setfattr -n user.color -v blue {}/xfile.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_xattrs(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("xfile.txt")).unwrap(),
        b"xattr pull test"
    );

    let output = std::process::Command::new("getfattr")
        .args([
            "--only-values",
            "-n",
            "user.color",
            ctx.env.dst().join("xfile.txt").to_str().unwrap(),
        ])
        .output()
        .expect("getfattr failed");
    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(val, "blue", "xattr user.color should be 'blue' after pull");
}

#[tokio::test]
async fn test_interop_pull_acl() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    ssh_cmd(&[&format!(
        "echo -n 'acl pull test' > {}/afile.txt && \
         setfacl -m u:1000:rw {}/afile.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_acls(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("afile.txt")).unwrap(),
        b"acl pull test"
    );

    let output = std::process::Command::new("getfacl")
        .args([
            "--omit-header",
            ctx.env.dst().join("afile.txt").to_str().unwrap(),
        ])
        .output()
        .expect("getfacl failed");
    let acl = String::from_utf8_lossy(&output.stdout);
    assert!(
        acl.contains("user:1000:rw-"),
        "ACL should contain user:1000:rw- after pull, got: {acl}"
    );
}

/// Proves -A actually matters: without the flag, ACLs should NOT be preserved.
#[tokio::test]
async fn test_interop_pull_acl_absent_without_flag() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    ssh_cmd(&[&format!(
        "echo -n 'no acl flag' > {}/noflg.txt && \
         setfacl -m u:1000:rw {}/noflg.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder().archive().build();
    ctx.pull_opts(opts, 30).await;

    assert_eq!(
        std::fs::read(ctx.env.dst().join("noflg.txt")).unwrap(),
        b"no acl flag"
    );

    let output = std::process::Command::new("getfacl")
        .args([
            "--omit-header",
            ctx.env.dst().join("noflg.txt").to_str().unwrap(),
        ])
        .output()
        .expect("getfacl failed");
    let acl = String::from_utf8_lossy(&output.stdout);
    assert!(
        !acl.contains("user:1000:rw-"),
        "without -A flag, ACL should NOT contain user:1000:rw-, got: {acl}"
    );
}

/// With --keep-dirlinks, a symlinked directory on the receiver is treated as a real
/// directory rather than being replaced. Without the flag, rsync would delete the
/// symlink and create a real directory.
#[tokio::test]
async fn test_interop_pull_keep_dirlinks() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("mydir/file.txt", b"inside dir\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Pre-create a symlink on the local dest pointing to a real directory.
    let real_dir = ctx.env.dir().join("real_target");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::create_dir_all(ctx.env.dst()).unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, ctx.env.dst().join("mydir")).unwrap();
    #[cfg(not(unix))]
    {
        eprintln!("SKIP: symlinks not supported");
        return;
    }

    let opts = TransferOptions::builder()
        .archive()
        .keep_dirlinks(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    // The symlink should still be a symlink (not replaced with a real dir).
    let meta = std::fs::symlink_metadata(ctx.env.dst().join("mydir")).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "--keep-dirlinks should preserve the symlink"
    );

    // But the file should have been written through the symlink into the real dir.
    assert_eq!(
        std::fs::read(real_dir.join("file.txt")).unwrap(),
        b"inside dir\n",
        "file should be written through the symlinked directory"
    );
}

#[tokio::test]
#[ignore = "#186 FakeSuperFs doesn't read back xattr after pull"]
async fn test_interop_pull_fake_super() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(TestEnv::builder().build()).await;

    // Create a file on remote with a fake-super xattr in rsync format.
    ssh_cmd(&[&format!(
        "echo -n 'fake super test' > {}/fsfile.txt && \
         chmod 600 {}/fsfile.txt && \
         setfattr -n user.rsync.%stat -v '100755 0,0 1000:1000' {}/fsfile.txt",
        ctx.remote.path(),
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_xattrs(true)
        .fake_super(true)
        .build();
    ctx.pull_opts(opts, 30).await;

    // Content should arrive.
    assert_eq!(
        std::fs::read(ctx.env.dst().join("fsfile.txt")).unwrap(),
        b"fake super test"
    );

    // Real local mode should be 0600 (fake-super safe mode).
    use std::os::unix::fs::PermissionsExt;
    let real_mode = std::fs::metadata(ctx.env.dst().join("fsfile.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        real_mode, 0o600,
        "fake-super should set real local mode to 0600, got {real_mode:04o}"
    );

    // Read back through FakeSuperFs -- should see the intended mode from xattr.
    let reader_fs = crate::common::env::test_filesystem_fake_super();
    let meta = reader_fs.lstat(&ctx.env.dst().join("fsfile.txt")).unwrap();
    assert_eq!(
        meta.mode & 0o777,
        0o755,
        "FakeSuperFs::lstat should report mode 0755 from xattr, got {:04o}",
        meta.mode & 0o777
    );
    assert_eq!(
        meta.uid, 1000,
        "FakeSuperFs::lstat should report uid 1000 from xattr"
    );
    assert_eq!(
        meta.gid, 1000,
        "FakeSuperFs::lstat should report gid 1000 from xattr"
    );
}
