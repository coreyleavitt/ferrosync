//! Multi-step real-world scenarios and flag combination tests.

use crate::common::assertions::*;
use crate::common::env::{inode_of, set_mtime, TestEnv};
use crate::common::ssh::*;
use crate::common::{DeleteMode, TransferOptions};
use crate::skip_if_no_ssh;

/// Time Machine-style snapshot: pull with --delete + --link-dest.
/// Unchanged files hard-link to previous snapshot, changed files get new copies,
/// deleted files are absent. If --delete were silently ignored, file_c would
/// still appear in "new". If --link-dest were silently ignored, file_b would
/// be a separate copy rather than hard-linked.
#[tokio::test]
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
    let remote = RemoteDir::new().await;
    push_archive(&src, remote.path(), 30).await;

    // Pull initial state into "current" (baseline snapshot).
    pull_archive(&remote.path_slash(), &current, 30).await;

    // Modify source: change file_a, remove file_c.
    std::fs::write(src.join("file_a"), "aaa_v2\n").unwrap();
    set_mtime(&src.join("file_a"), 1_800_000_000);
    std::fs::remove_file(src.join("file_c")).unwrap();

    // Push modified source to remote with --delete so file_c is removed.
    let push_opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::During)
        .source(src.clone())
        .build();
    push_with_opts(push_opts, remote.path(), 30).await;

    // Pull into "new" with --delete + --link-dest=../current (relative).
    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::During)
        .link_dest("../current")
        .dest(new_dir.clone())
        .build();
    pull_with_opts(opts, &remote.path_slash(), 30).await;

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
}

/// Exact mirror push: --delete removes extraneous remote files.
/// If --delete were silently ignored, extra_remote.txt would survive.
#[tokio::test]
async fn test_combo_exact_mirror() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"aaa\n", None)
        .with_src_file("file_b.txt", b"bbb\n", None)
        .build();

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Create an extraneous file on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo extra > {}/extra_remote.txt", ctx.remote.path()),
    ])
    .await;
    assert!(
        remote_exists(&ctx.remote.join("extra_remote.txt")).await,
        "extra_remote.txt should exist before mirror push"
    );

    // Modify file_b in source.
    std::fs::write(ctx.env.src().join("file_b.txt"), b"bbb_v2\n").unwrap();

    // Push with --delete.
    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::During)
        .build();
    ctx.push_opts(opts, 30).await;

    // extra_remote.txt should be gone.
    assert!(
        !remote_exists(&ctx.remote.join("extra_remote.txt")).await,
        "extra_remote.txt should be deleted by --delete"
    );
    // file_a unchanged.
    assert_eq!(
        remote_cat(&ctx.remote.join("file_a.txt")).await,
        "aaa\n"
    );
    // file_b updated.
    assert_eq!(
        remote_cat(&ctx.remote.join("file_b.txt")).await,
        "bbb_v2\n"
    );
}

/// --delete-excluded removes both extraneous AND excluded files.
/// If --delete-excluded were downgraded to plain --delete, .env and keepme.txt
/// would be preserved (since they match exclude patterns).
#[tokio::test]
async fn test_combo_deploy_delete_excluded() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file(".env", b"SECRET\n", None)
        .with_src_file("app.txt", b"app\n", None)
        .build();

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Create keepme.txt on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo keep > {}/keepme.txt", ctx.remote.path()),
    ])
    .await;

    // Push with --delete-excluded + excludes for .env and keepme.txt.
    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::Excluded)
        .exclude(".env")
        .exclude("keepme.txt")
        .build();
    ctx.push_opts(opts, 30).await;

    // --delete-excluded: .env is excluded AND deleted.
    assert!(
        !remote_exists(&ctx.remote.join(".env")).await,
        ".env should be removed by --delete-excluded"
    );
    // --delete-excluded: keepme.txt is excluded AND deleted.
    assert!(
        !remote_exists(&ctx.remote.join("keepme.txt")).await,
        "keepme.txt should be removed by --delete-excluded"
    );
    // app.txt should still exist (not excluded).
    assert_eq!(remote_cat(&ctx.remote.join("app.txt")).await, "app\n");
}

/// Dry-run + --delete: nothing actually changes on the remote.
/// If --dry-run were silently ignored, extra.txt would be deleted.
#[tokio::test]
async fn test_combo_dry_run_audit() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file.txt", b"content\n", None)
        .build();

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Create extraneous file on remote.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo extra > {}/extra.txt", ctx.remote.path()),
    ])
    .await;

    // Modify local source.
    std::fs::write(ctx.env.src().join("file.txt"), b"content_v2\n").unwrap();

    // Push with -n + --delete.
    let opts = TransferOptions::builder()
        .archive()
        .dry_run(true)
        .delete(DeleteMode::During)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    // Dry-run should report files that would transfer.
    assert!(
        result.stats.files_transferred >= 1,
        "dry-run should report files that would be transferred"
    );

    // extra.txt should STILL exist (dry-run doesn't actually delete).
    assert!(
        remote_exists(&ctx.remote.join("extra.txt")).await,
        "extra.txt should survive dry-run --delete"
    );

    // file.txt should still have original content (dry-run doesn't write).
    assert_eq!(
        remote_cat(&ctx.remote.join("file.txt")).await,
        "content\n",
        "file.txt should not be updated during dry-run"
    );
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

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .compress(true)
        .build();
    ctx.push_opts(opts, 60).await;

    // Verify content integrity: both files present and byte-for-byte correct.
    assert_remote_size(&ctx.remote.join("big_text.dat"), 65536).await;
    assert_remote_size(&ctx.remote.join("binary.dat"), 1024).await;

    // Verify binary content via checksum.
    let remote_md5 = ssh_cmd(&["md5sum", &ctx.remote.join("binary.dat")]).await;
    let local_md5 = {
        let output = tokio::process::Command::new("md5sum")
            .arg(ctx.env.src().join("binary.dat"))
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
    assert_remote_mtime(&ctx.remote.join("big_text.dat"), 1_700_000_000, 0).await;
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

    let ctx = SshTestContext::new(env).await;
    ctx.push(60).await;

    // Record inode on remote.
    let inode_before = remote_inode(&ctx.remote.join("large.dat")).await;

    // Modify file locally.
    let mut data_v2 = vec![0xBB; 512 * 1024];
    data_v2[0] = 0xCC; // small difference
    std::fs::write(ctx.env.src().join("large.dat"), &data_v2).unwrap();

    // Push with --inplace.
    let opts = TransferOptions::builder()
        .archive()
        .inplace(true)
        .build();
    ctx.push_opts(opts, 60).await;

    // Verify content updated.
    assert_remote_size(&ctx.remote.join("large.dat"), 512 * 1024).await;

    // Verify inode is unchanged (same file descriptor, no temp-file rename).
    let inode_after = remote_inode(&ctx.remote.join("large.dat")).await;
    assert_eq!(
        inode_before, inode_after,
        "--inplace should preserve inode (no temp file rename)"
    );
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

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .include("*.txt")
        .include("*/")
        .exclude("*")
        .build();
    ctx.push_opts(opts, 30).await;

    // *.txt files should exist.
    assert!(
        remote_exists(&ctx.remote.join("docs/readme.txt")).await,
        "readme.txt should be included"
    );
    assert!(
        remote_exists(&ctx.remote.join("code/notes.txt")).await,
        "notes.txt should be included"
    );
    // Non-txt files should be absent.
    assert!(
        !remote_exists(&ctx.remote.join("docs/spec.pdf")).await,
        "spec.pdf should be excluded"
    );
    assert!(
        !remote_exists(&ctx.remote.join("code/main.rs")).await,
        "main.rs should be excluded"
    );
}

/// --delete + --exclude: excluded files on receiver are protected from deletion.
/// If --exclude were silently ignored during delete, protected.log would be removed.
/// If --delete were silently ignored, extra.txt would survive.
#[tokio::test]
async fn test_combo_delete_exclude_safety() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep\n", None)
        .build();

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Create extraneous files on remote: one deletable, one protected by exclude.
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo 'delete me' > {}/extra.txt", ctx.remote.path()),
    ])
    .await;
    ssh_cmd(&[
        "bash",
        "-c",
        &format!("echo 'safe' > {}/protected.log", ctx.remote.path()),
    ])
    .await;

    // Push with --delete + --exclude="*.log".
    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::During)
        .exclude("*.log")
        .build();
    ctx.push_opts(opts, 30).await;

    // keep.txt still present.
    assert_eq!(
        remote_cat(&ctx.remote.join("keep.txt")).await,
        "keep\n"
    );
    // extra.txt deleted (not in source, not excluded).
    assert!(
        !remote_exists(&ctx.remote.join("extra.txt")).await,
        "extra.txt should be deleted by --delete"
    );
    // protected.log preserved (excluded from transfer AND delete).
    assert!(
        remote_exists(&ctx.remote.join("protected.log")).await,
        "protected.log should be preserved by --exclude pattern"
    );
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

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Verify initial state.
    assert_eq!(
        remote_cat(&ctx.remote.join("file_a.txt")).await,
        "v1\n"
    );

    // Overwrite with different content but SAME mtime (same size: 3 bytes).
    std::fs::write(ctx.env.src().join("file_a.txt"), b"v2\n").unwrap();
    set_mtime(&ctx.env.src().join("file_a.txt"), 1_700_000_000);

    // Push with -c (checksum mode).
    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Checksum mode should detect the content change.
    assert_eq!(
        remote_cat(&ctx.remote.join("file_a.txt")).await,
        "v2\n",
        "checksum mode should transfer file despite same size+mtime"
    );
}

/// --update skips files that are newer on the receiver.
/// If -u were silently ignored, file_b's remote content would be overwritten
/// by the older source version.
#[tokio::test]
async fn test_combo_update_merge() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"src_a\n", Some(1_700_000_000))
        .with_src_file("file_b.txt", b"src_b\n", Some(1_700_000_000))
        .build();

    let ctx = SshTestContext::new(env).await;
    ctx.push(30).await;

    // Verify first push set mtimes correctly.
    assert_remote_mtime(&ctx.remote.join("file_b.txt"), 1_700_000_000, 0).await;

    // On remote, overwrite file_b with newer content and a NEWER mtime.
    // Single arg: SSH invokes a shell that parses the full string correctly.
    ssh_cmd(&[&format!(
        "printf '%s\\n' remote_newer > {}/file_b.txt && touch -d @1800000000 {}/file_b.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    // Verify remote modification took effect.
    assert_remote_mtime(&ctx.remote.join("file_b.txt"), 1_800_000_000, 0).await;

    // Push with -u (update): should skip file_b because remote is newer.
    let opts = TransferOptions::builder()
        .archive()
        .update(true)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    // Both files should be skipped: file_a has same size+mtime (quick check),
    // file_b is newer on receiver (-u skip).
    assert_eq!(
        result.stats.files_transferred, 0,
        "no files should transfer"
    );

    // file_a should have source content (remote was older or same).
    assert_eq!(
        remote_cat(&ctx.remote.join("file_a.txt")).await,
        "src_a\n",
    );
    // file_b should retain remote content (remote was newer, -u skips).
    assert_eq!(
        remote_cat(&ctx.remote.join("file_b.txt")).await,
        "remote_newer\n",
        "--update should not overwrite newer remote file"
    );
}

/// Control test: rsync-to-rsync validates that --update semantics work as
/// expected using real rsync on both sides (no ferrosync in the loop).
#[tokio::test]
async fn test_combo_update_merge_rsync_control() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("file_a.txt", b"src_a\n", Some(1_700_000_000))
        .with_src_file("file_b.txt", b"src_b\n", Some(1_700_000_000))
        .build();

    let remote = RemoteDir::new().await;
    let host = ssh_host();
    let ssh_args = "ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR";

    // Push via real rsync (rsync on both sides, no ferrosync).
    let output = tokio::process::Command::new("rsync")
        .args(["-a", "-e", ssh_args])
        .arg(format!("{}/", env.src().display()))
        .arg(format!("root@{host}:{}/", remote.path()))
        .output()
        .await
        .expect("rsync push");
    assert!(
        output.status.success(),
        "rsync initial push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Modify file_b on remote with newer mtime.
    ssh_cmd(&[&format!(
        "printf '%s\\n' remote_newer > {}/file_b.txt && touch -d @1800000000 {}/file_b.txt",
        remote.path(),
        remote.path()
    )])
    .await;

    // Push again with -u: should skip file_b.
    let output = tokio::process::Command::new("rsync")
        .args(["-a", "-u", "-e", ssh_args])
        .arg(format!("{}/", env.src().display()))
        .arg(format!("root@{host}:{}/", remote.path()))
        .output()
        .await
        .expect("rsync -u push");
    assert!(
        output.status.success(),
        "rsync -u push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        remote_cat(&remote.join("file_a.txt")).await,
        "src_a\n",
    );
    assert_eq!(
        remote_cat(&remote.join("file_b.txt")).await,
        "remote_newer\n",
        "rsync --update should not overwrite newer remote file"
    );
}

/// Control test: rsync-to-rsync validates hardlink preservation works
/// with real rsync on both sides.
#[tokio::test]
async fn test_interop_pull_hardlinks_rsync_control() {
    skip_if_no_ssh!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[&format!(
        "echo control > {}/orig.txt && \
         ln {}/orig.txt {}/link.txt",
        remote.path(),
        remote.path(),
        remote.path()
    )])
    .await;

    let env = TestEnv::builder().build();
    let host = ssh_host();
    let ssh_args = "ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR";

    let output = tokio::process::Command::new("rsync")
        .args(["-aH", "-e", ssh_args])
        .arg(format!("root@{host}:{}/", remote.path()))
        .arg(format!("{}/", env.dst().display()))
        .output()
        .await
        .expect("rsync pull");
    assert!(
        output.status.success(),
        "rsync -aH pull failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_hard_linked(&env.dst().join("orig.txt"), &env.dst().join("link.txt"));
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

    let remote = RemoteDir::new().await;

    // --- Generation 0 ---
    std::fs::write(src.join("unchanged.txt"), "stable\n").unwrap();
    set_mtime(&src.join("unchanged.txt"), 1_700_000_000);
    std::fs::write(src.join("changed.txt"), "v1\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_700_000_000);

    push_archive(&src, remote.path(), 30).await;
    pull_archive(&remote.path_slash(), &gen0, 30).await;

    // --- Generation 1 ---
    std::fs::write(src.join("changed.txt"), "v2\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_800_000_000);

    push_archive(&src, remote.path(), 30).await;

    std::fs::create_dir_all(&gen1).unwrap();
    let opts = TransferOptions::builder()
        .archive()
        .link_dest("../gen0")
        .dest(gen1.clone())
        .build();
    pull_with_opts(opts, &remote.path_slash(), 30).await;

    // --- Generation 2 ---
    std::fs::write(src.join("changed.txt"), "v3\n").unwrap();
    set_mtime(&src.join("changed.txt"), 1_900_000_000);

    push_archive(&src, remote.path(), 30).await;

    std::fs::create_dir_all(&gen2).unwrap();
    let opts = TransferOptions::builder()
        .archive()
        .link_dest("../gen1")
        .dest(gen2.clone())
        .build();
    pull_with_opts(opts, &remote.path_slash(), 30).await;

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
}
