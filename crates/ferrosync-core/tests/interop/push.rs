//! Push tests: ferrosync client -> rsync server over SSH.

use crate::common::assertions::*;
use crate::common::env::{set_mtime, TestEnv};
use crate::common::ssh::*;
use crate::common::{DeleteMode, TransferOptions};
use crate::skip_if_no_ssh;

#[tokio::test]
async fn test_interop_push_single_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("hello.txt", b"hello via SSH\n", None)
            .build(),
    )
    .await;

    let result = ctx.push(30).await;
    assert!(result.stats.files_transferred >= 1);

    let content = remote_cat(&ctx.remote.join("hello.txt")).await;
    assert_eq!(content, "hello via SSH\n");
    assert_remote_exists(&ctx.remote.join("hello.txt")).await;
}

#[tokio::test]
async fn test_interop_push_directory_recursive() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("top.txt", b"top\n", None)
            .with_src_file("a/mid.txt", b"mid\n", None)
            .with_src_file("a/b/deep.txt", b"deep\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    assert_eq!(remote_cat(&ctx.remote.join("top.txt")).await, "top\n");
    assert_eq!(
        remote_cat(&ctx.remote.join("a/mid.txt")).await,
        "mid\n"
    );
    assert_eq!(
        remote_cat(&ctx.remote.join("a/b/deep.txt")).await,
        "deep\n"
    );

    // Verify subdirectories exist as directories on remote.
    assert_remote_is_dir(&ctx.remote.join("a")).await;
    assert_remote_is_dir(&ctx.remote.join("a/b")).await;
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

    let ctx = SshTestContext::new(env).await;
    let result = ctx.push(60).await;
    assert_eq!(result.stats.files_transferred, 50);

    // Verify ALL 50 files have correct content.
    for i in 0..50 {
        let actual = remote_cat(&ctx.remote.join(&format!("file_{i:03}.txt"))).await;
        assert_eq!(
            actual,
            format!("content {i}\n"),
            "file_{i:03}.txt content mismatch"
        );
    }
}

#[tokio::test]
async fn test_interop_push_large_file() {
    skip_if_no_ssh!();

    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("big.dat", &data, None)
            .build(),
    )
    .await;

    let result = ctx.push(60).await;
    assert_eq!(result.stats.files_transferred, 1);

    assert_remote_size(&ctx.remote.join("big.dat"), 1048576).await;

    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "16",
        &ctx.remote.join("big.dat"),
    ])
    .await;
    let head_hex: String = head.split_whitespace().collect();
    let expected_head: String = data[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(head_hex, expected_head, "large file head mismatch");
}

#[tokio::test]
async fn test_interop_push_very_large_file() {
    skip_if_no_ssh!();

    let size = 16 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("huge.dat", &data, None)
            .build(),
    )
    .await;

    let result = ctx.push(120).await;
    assert_eq!(result.stats.files_transferred, 1);

    assert_remote_size(&ctx.remote.join("huge.dat"), size as u64).await;

    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "4096",
        &ctx.remote.join("huge.dat"),
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
        &ctx.remote.join("huge.dat"),
    ])
    .await;
    let tail_hex: String = tail.split_whitespace().collect();
    let expected_tail: String = data[size - 4096..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tail_hex, expected_tail, "16MB file tail mismatch");
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

    let ctx = SshTestContext::new(env).await;
    let result = ctx.push(120).await;
    assert_eq!(result.stats.files_transferred, 31);

    assert_eq!(
        remote_cat(&ctx.remote.join("small_00.txt")).await,
        "data 0\n"
    );
    assert_eq!(
        remote_cat(&ctx.remote.join("sub/nested_09.txt")).await,
        "nested 9\n"
    );
    assert_remote_exists(&ctx.remote.join("medium.bin")).await;

    // Verify directory structure exists
    assert_remote_is_dir(&ctx.remote.join("sub")).await;

    // Verify more files at different depths
    assert_eq!(
        remote_cat(&ctx.remote.join("small_10.txt")).await,
        "data 10\n"
    );
    assert_eq!(
        remote_cat(&ctx.remote.join("small_19.txt")).await,
        "data 19\n"
    );
    assert_eq!(
        remote_cat(&ctx.remote.join("sub/nested_00.txt")).await,
        "nested 0\n"
    );
    assert_eq!(
        remote_cat(&ctx.remote.join("sub/nested_05.txt")).await,
        "nested 5\n"
    );
}

#[tokio::test]
async fn test_interop_push_preserves_mtime() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("timed.txt", b"check mtime\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    assert_remote_mtime(&ctx.remote.join("timed.txt"), 1_700_000_000, 0).await;
}

#[tokio::test]
async fn test_interop_push_idempotent() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("stable.txt", b"no change\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;
    let result2 = ctx.push(30).await;
    assert_eq!(
        result2.stats.files_transferred, 0,
        "idempotent push should transfer zero files"
    );

    let content = remote_cat(&ctx.remote.join("stable.txt")).await;
    assert_eq!(content, "no change\n");
}

#[tokio::test]
async fn test_interop_push_archive_mode() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("archive.txt", b"archive mode push\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    let content = remote_cat(&ctx.remote.join("archive.txt")).await;
    assert_eq!(content, "archive mode push\n");

    // Archive mode preserves mtime: verify remote mtime matches local.
    let local_mtime = std::fs::metadata(ctx.env.src().join("archive.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_remote_mtime(&ctx.remote.join("archive.txt"), local_mtime, 0).await;
}

#[tokio::test]
async fn test_interop_push_ignore_times() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"new content\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    // First push to populate remote.
    ctx.push(30).await;

    // Overwrite local with different content but same size+mtime.
    std::fs::write(ctx.env.src().join("file.txt"), b"alt content\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_700_000_000);

    // Push with --ignore-times: should transfer despite same size+mtime.
    let opts = TransferOptions::builder()
        .archive()
        .ignore_times(true)
        .build();
    ctx.push_opts(opts, 30).await;

    let content = remote_cat(&ctx.remote.join("file.txt")).await;
    assert_eq!(content, "alt content\n");
}

#[tokio::test]
async fn test_interop_push_checksum() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"aaa\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    ctx.push(30).await;

    // Overwrite local with different content but same mtime.
    std::fs::write(ctx.env.src().join("file.txt"), b"bbb\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_700_000_000);

    // Push with --checksum: should detect content change despite same size+mtime.
    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .build();
    ctx.push_opts(opts, 30).await;

    let content = remote_cat(&ctx.remote.join("file.txt")).await;
    assert_eq!(
        content, "bbb\n",
        "checksum push should detect content change"
    );
}

#[tokio::test]
async fn test_interop_push_whole_file() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"whole file push\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .whole_file(true)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    let content = remote_cat(&ctx.remote.join("file.txt")).await;
    assert_eq!(content, "whole file push\n");
    assert_eq!(
        result.stats.matched_data, 0,
        "whole-file should not use delta matching"
    );
}

#[tokio::test]
async fn test_interop_push_compress() {
    skip_if_no_ssh!();

    let data = vec![b'A'; 65536];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("repeated.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .compress(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_size(&ctx.remote.join("repeated.dat"), 65536).await;

    // Verify remote file content matches local (all 'A' bytes).
    let head = ssh_cmd(&[
        "od",
        "-A",
        "n",
        "-t",
        "x1",
        "-N",
        "16",
        &ctx.remote.join("repeated.dat"),
    ])
    .await;
    let head_hex: String = head.split_whitespace().collect();
    let expected: String = "41".repeat(16);
    assert_eq!(
        head_hex, expected,
        "compressed transfer should produce correct file content"
    );
}

#[tokio::test]
async fn test_interop_push_numeric_ids() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"numeric ids\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .numeric_ids(true)
        .build();
    ctx.push_opts(opts, 30).await;

    let content = remote_cat(&ctx.remote.join("file.txt")).await;
    assert_eq!(content, "numeric ids\n");

    // We run as root in Docker, so uid:gid should be 0:0.
    assert_remote_ownership(&ctx.remote.join("file.txt"), 0, 0).await;
}

#[tokio::test]
async fn test_interop_push_exclude() {
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
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("keep.txt")).await;
    assert_remote_absent(&ctx.remote.join("skip.log")).await;
}

#[tokio::test]
async fn test_interop_push_dry_run() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"dry run test\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .dry_run(true)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    assert_remote_absent(&ctx.remote.join("file.txt")).await;
    assert!(
        result.stats.files_transferred >= 1,
        "dry-run should still report files that would transfer"
    );
}

/// The remote rsync receiver handles hardlink creation.
#[tokio::test]
async fn test_interop_push_hardlinks() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("original.txt", b"push_hardlink\n", None)
        .build();

    // Create a hardlink locally.
    std::fs::hard_link(env.src().join("original.txt"), env.src().join("linked.txt")).unwrap();

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_hard_links(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Both files should exist on remote with correct content.
    assert_remote_content(&ctx.remote.join("original.txt"), "push_hardlink\n").await;
    assert_remote_content(&ctx.remote.join("linked.txt"), "push_hardlink\n").await;

    // Verify they share an inode on remote.
    assert_remote_hard_linked(
        &ctx.remote.join("original.txt"),
        &ctx.remote.join("linked.txt"),
    )
    .await;
}

#[tokio::test]
async fn test_interop_push_remove_source_files() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("vanish.txt", b"goodbye\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .remove_source_files(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("vanish.txt"), "goodbye\n").await;
    assert!(
        !ctx.env.src().join("vanish.txt").exists(),
        "remove-source-files should delete local file after push"
    );
}

#[tokio::test]
async fn test_interop_push_max_size() {
    skip_if_no_ssh!();

    let small_data = vec![b'x'; 100];
    let big_data = vec![b'y'; 10_000];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("small.txt", &small_data, None)
            .with_src_file("big.txt", &big_data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .max_size(5000)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("small.txt")).await;
    assert_remote_absent(&ctx.remote.join("big.txt")).await;
}

#[tokio::test]
async fn test_interop_push_min_size() {
    skip_if_no_ssh!();

    let tiny_data = vec![b'a'; 10];
    let normal_data = vec![b'b'; 5000];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("tiny.txt", &tiny_data, None)
            .with_src_file("normal.txt", &normal_data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .min_size(100)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("normal.txt")).await;
    assert_remote_absent(&ctx.remote.join("tiny.txt")).await;
}

#[tokio::test]
async fn test_interop_push_append_verify() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("append.txt", b"hello\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;
    assert_remote_content(&ctx.remote.join("append.txt"), "hello\n").await;

    std::fs::write(ctx.env.src().join("append.txt"), b"hello world\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .append_verify(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("append.txt"), "hello world\n").await;
}

#[tokio::test]
async fn test_interop_push_compress_level() {
    skip_if_no_ssh!();

    let data = vec![b'A'; 65536];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("compressible.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .compress(true)
        .compress_level(1)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_size(&ctx.remote.join("compressible.dat"), 65536).await;
}

#[tokio::test]
async fn test_interop_push_compress_choice() {
    skip_if_no_ssh!();

    let data = vec![b'Z'; 65536];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("zlib.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .compress(true)
        .compress_choice("zlib")
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_size(&ctx.remote.join("zlib.dat"), 65536).await;
}

#[tokio::test]
async fn test_interop_push_exclude_from() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("keep.txt", b"keep me\n", None)
        .with_src_file("debug.log", b"log output\n", None)
        .with_src_file("tmp/data.txt", b"temp data\n", None)
        .build();

    let exclude_file = env.dir().join("excludes.txt");
    std::fs::write(&exclude_file, "*.log\ntmp/\n").unwrap();

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .exclude_from(&exclude_file)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("keep.txt")).await;
    assert_remote_absent(&ctx.remote.join("debug.log")).await;
    assert_remote_absent(&ctx.remote.join("tmp/data.txt")).await;
}

#[tokio::test]
async fn test_interop_push_cvs_exclude() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("main.rs", b"fn main() {}\n", None)
            .with_src_file(".git/config", b"[core]\n", None)
            .with_src_file("build.o", b"\x7fELF\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .cvs_exclude(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("main.rs")).await;
    assert_remote_absent(&ctx.remote.join(".git/config")).await;
    assert_remote_absent(&ctx.remote.join("build.o")).await;
}

#[tokio::test]
async fn test_interop_push_filter_merge() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file(".rsync-filter", b"- *.tmp\n", None)
            .with_src_file("keep.txt", b"keep me\n", None)
            .with_src_file("junk.tmp", b"junk\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .filter_merge_files(1)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("keep.txt")).await;
    assert_remote_absent(&ctx.remote.join("junk.tmp")).await;
}

#[tokio::test]
async fn test_interop_push_files_from() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("a.txt", b"file a\n", None)
        .with_src_file("b.txt", b"file b\n", None)
        .with_src_file("c.txt", b"file c\n", None)
        .build();

    let list_file = env.dir().join("filelist.txt");
    std::fs::write(&list_file, "a.txt\nc.txt\n").unwrap();

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .files_from(&list_file)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("a.txt")).await;
    assert_remote_absent(&ctx.remote.join("b.txt")).await;
    assert_remote_exists(&ctx.remote.join("c.txt")).await;
}

#[tokio::test]
async fn test_interop_push_max_min_size_combo() {
    skip_if_no_ssh!();

    let tiny = vec![b'x'; 10];
    let medium = vec![b'y'; 5000];
    let huge = vec![b'z'; 50000];

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("tiny.txt", &tiny, None)
            .with_src_file("medium.txt", &medium, None)
            .with_src_file("huge.txt", &huge, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .max_size(10000)
        .min_size(100)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_absent(&ctx.remote.join("tiny.txt")).await;
    assert_remote_exists(&ctx.remote.join("medium.txt")).await;
    assert_remote_absent(&ctx.remote.join("huge.txt")).await;
}

#[tokio::test]
async fn test_interop_push_one_file_system() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("local")).unwrap();
    std::fs::write(src.join("local/on_root.txt"), b"root fs\n").unwrap();

    let mounted = src.join("mounted");
    std::fs::create_dir_all(&mounted).unwrap();
    let mount_status = std::process::Command::new("mount")
        .args(["-t", "tmpfs", "tmpfs", mounted.to_str().unwrap()])
        .status();
    match mount_status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: mount -t tmpfs failed (needs SYS_ADMIN capability)");
            return;
        }
    }

    std::fs::write(mounted.join("other_fs.txt"), b"other fs\n").unwrap();

    let remote = RemoteDir::new().await;

    let opts = TransferOptions::builder()
        .archive()
        .one_file_system(true)
        .source(src.clone())
        .build();
    push_with_opts(opts, remote.path(), 30).await;

    assert_remote_exists(&remote.join("local/on_root.txt")).await;
    assert_remote_absent(&remote.join("mounted/other_fs.txt")).await;

    let _ = std::process::Command::new("umount")
        .arg(mounted.to_str().unwrap())
        .status();
}

#[tokio::test]
async fn test_interop_push_xattr() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("xattr_file.txt", b"xattr test\n", None)
        .build();

    let src_file = env.src().join("xattr_file.txt");
    let status = std::process::Command::new("setfattr")
        .args(["-n", "user.test", "-v", "hello_xattr", src_file.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: setfattr not available or filesystem does not support user xattrs");
            return;
        }
    }

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_xattrs(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("xattr_file.txt"), "xattr test\n").await;

    let xattr_val = remote_getfattr(&ctx.remote.join("xattr_file.txt"), "user.test").await;
    assert_eq!(xattr_val, "hello_xattr");
}

#[tokio::test]
async fn test_interop_push_acl() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("acl_file.txt", b"acl test\n", None)
        .build();

    let src_file = env.src().join("acl_file.txt");
    let status = std::process::Command::new("setfacl")
        .args(["-m", "u:1000:rw", src_file.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("SKIP: setfacl not available or filesystem does not support POSIX ACLs");
            return;
        }
    }

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_acls(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("acl_file.txt"), "acl test\n").await;

    let acl = remote_getfacl(&ctx.remote.join("acl_file.txt")).await;
    assert!(
        acl.contains("user:1000:rw-"),
        "ACL should contain user:1000:rw- on remote, got: {acl}"
    );
}

// ---------------------------------------------------------------------------
// Push-side mirrors: flags previously only tested in pull
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_push_delete_before() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .build(),
    )
    .await;

    // Seed remote, then create an extraneous file.
    ctx.push(30).await;
    ssh_cmd(&[&format!("echo extra > {}/extra.txt", ctx.remote.path())]).await;

    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::Before)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file_a.txt"), "aaa\n").await;
    assert_remote_absent(&ctx.remote.join("extra.txt")).await;
}

#[tokio::test]
async fn test_interop_push_delete_after() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file_a.txt", b"aaa\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;
    ssh_cmd(&[&format!("echo extra > {}/extra.txt", ctx.remote.path())]).await;

    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::After)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file_a.txt"), "aaa\n").await;
    assert_remote_absent(&ctx.remote.join("extra.txt")).await;
}

#[tokio::test]
async fn test_interop_push_max_delete() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("keep.txt", b"keep\n", None)
            .build(),
    )
    .await;

    // Seed remote with keep.txt + 2 extraneous files.
    ctx.push(30).await;
    ssh_cmd(&[&format!(
        "echo e1 > {}/extra1.txt && echo e2 > {}/extra2.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .delete(DeleteMode::Before)
        .max_delete(1)
        .build();
    ctx.push_opts(opts, 30).await;

    // One extraneous should be deleted, one should remain.
    let e1 = remote_exists(&ctx.remote.join("extra1.txt")).await;
    let e2 = remote_exists(&ctx.remote.join("extra2.txt")).await;
    assert_eq!(
        (e1 as u32) + (e2 as u32),
        1,
        "max-delete=1 should leave one extra file"
    );
    assert_remote_content(&ctx.remote.join("keep.txt"), "keep\n").await;
}

#[tokio::test]
async fn test_interop_push_backup() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"version one\n", None)
            .build(),
    )
    .await;

    // Push v1.
    ctx.push(30).await;
    assert_remote_content(&ctx.remote.join("file.txt"), "version one\n").await;

    // Update local to v2 with different mtime to ensure retransfer.
    std::fs::write(ctx.env.src().join("file.txt"), b"version two\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_800_000_000);

    // Push v2 with backup.
    let opts = TransferOptions::builder()
        .archive()
        .backup(true)
        .suffix(".old")
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file.txt"), "version two\n").await;
    assert_remote_content(&ctx.remote.join("file.txt.old"), "version one\n").await;
}

#[tokio::test]
async fn test_interop_push_backup_dir() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"v1\n", None)
            .build(),
    )
    .await;

    ctx.push(30).await;

    std::fs::write(ctx.env.src().join("file.txt"), b"v2\n").unwrap();
    set_mtime(&ctx.env.src().join("file.txt"), 1_800_000_000);

    // Create backup dir on remote.
    ssh_cmd(&["mkdir", "-p", &ctx.remote.join(".bak")]).await;

    let opts = TransferOptions::builder()
        .archive()
        .backup(true)
        .backup_dir(std::path::PathBuf::from(".bak"))
        .suffix(".orig")
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file.txt"), "v2\n").await;
    assert_remote_content(&ctx.remote.join(".bak/file.txt.orig"), "v1\n").await;
}

#[tokio::test]
async fn test_interop_push_ignore_existing() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"updated\n", None)
            .build(),
    )
    .await;

    // Seed remote with original content.
    ssh_cmd(&[&format!("echo -n original > {}/file.txt", ctx.remote.path())]).await;

    let opts = TransferOptions::builder()
        .archive()
        .ignore_existing(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Remote should still have original content.
    assert_remote_content(&ctx.remote.join("file.txt"), "original").await;
}

#[tokio::test]
async fn test_interop_push_update() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"old source\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    // Seed remote with newer mtime.
    ssh_cmd(&[&format!(
        "echo -n 'newer remote' > {}/file.txt && touch -d @1800000000 {}/file.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .update(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Remote should retain newer content -- update skips files newer on receiver.
    assert_remote_content(&ctx.remote.join("file.txt"), "newer remote").await;
}

#[tokio::test]
async fn test_interop_push_inplace() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"updated content\n", None)
            .build(),
    )
    .await;

    // Seed remote with original content.
    ssh_cmd(&[&format!(
        "echo -n 'original text' > {}/file.txt",
        ctx.remote.path()
    )])
    .await;
    let inode_before = remote_inode(&ctx.remote.join("file.txt")).await;

    let opts = TransferOptions::builder()
        .archive()
        .inplace(true)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file.txt"), "updated content\n").await;

    let inode_after = remote_inode(&ctx.remote.join("file.txt")).await;
    assert_eq!(
        inode_before, inode_after,
        "--inplace should write to the same inode on remote"
    );
}

#[tokio::test]
async fn test_interop_push_sparse() {
    skip_if_no_ssh!();

    // 1MB sparse-friendly data: 4KB 0xFF + 1016KB 0x00 + 4KB 0xAA.
    let mut data = Vec::with_capacity(1_048_576);
    data.extend(std::iter::repeat_n(0xFFu8, 4096));
    data.extend(std::iter::repeat_n(0x00u8, 1016 * 1024));
    data.extend(std::iter::repeat_n(0xAAu8, 4096));

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("sparse.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .sparse(true)
        .build();
    ctx.push_opts(opts, 60).await;

    assert_remote_size(&ctx.remote.join("sparse.dat"), 1_048_576).await;

    // Verify remote file uses fewer disk blocks than full size.
    let blocks = remote_blocks(&ctx.remote.join("sparse.dat")).await;
    let allocated = blocks * 512;
    assert!(
        allocated < 1_048_576,
        "sparse push should use fewer blocks than full size (allocated={allocated})"
    );
}

#[tokio::test]
async fn test_interop_push_bwlimit() {
    skip_if_no_ssh!();

    // 200KB file -- enough that bwlimit is observable.
    let data = vec![b'B'; 200 * 1024];
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("throttled.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .bwlimit(102400) // 100 KB/s
        .build();
    ctx.push_opts(opts, 60).await;

    assert_remote_size(&ctx.remote.join("throttled.dat"), 200 * 1024).await;
}

#[tokio::test]
async fn test_interop_push_chmod() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"chmod test\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .chmod("a+x")
        .build();
    ctx.push_opts(opts, 30).await;

    // Verify remote file has execute bits set. Check that at least user execute is set.
    // We can't use assert_remote_permissions with an exact mode because the source
    // file's base mode varies. Instead, check that the execute bit is present.
    let mode_output = ssh_cmd(&["stat", "-c", "%a", &ctx.remote.join("file.txt")]).await;
    let mode = u32::from_str_radix(mode_output.trim(), 8).unwrap();
    assert!(
        mode & 0o111 != 0,
        "chmod a+x should set execute bits on remote, got {mode:04o}"
    );
}

#[tokio::test]
async fn test_interop_push_chown() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"chown test\n", None)
            .build(),
    )
    .await;

    // We run as root in Docker, so we can set ownership.
    let opts = TransferOptions::builder()
        .archive()
        .chown_uid(0)
        .chown_gid(0)
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_ownership(&ctx.remote.join("file.txt"), 0, 0).await;
}

#[tokio::test]
async fn test_interop_push_copy_links() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("target.txt", b"real content\n", None)
        .build();

    // Create a symlink in source pointing to target.txt.
    #[cfg(unix)]
    std::os::unix::fs::symlink("target.txt", env.src().join("link.txt")).unwrap();
    #[cfg(not(unix))]
    {
        eprintln!("SKIP: symlinks not supported on this platform");
        return;
    }

    let ctx = SshTestContext::new(env).await;

    // With --copy-links, the symlink should be followed and target content copied.
    let opts = TransferOptions::builder()
        .archive()
        .copy_links(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // link.txt on remote should be a regular file with the target's content.
    assert_remote_content(&ctx.remote.join("link.txt"), "real content\n").await;

    // It should NOT be a symlink on the remote.
    assert_remote_is_regular_file(&ctx.remote.join("link.txt")).await;
}

#[tokio::test]
async fn test_interop_push_safe_links() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("safe_target.txt", b"safe\n", None)
        .build();

    #[cfg(unix)]
    {
        // Safe symlink: points within the source tree.
        std::os::unix::fs::symlink("safe_target.txt", env.src().join("safe_link.txt")).unwrap();
        // Unsafe symlink: points outside the source tree.
        std::os::unix::fs::symlink("/etc/hostname", env.src().join("unsafe_link.txt")).unwrap();
    }
    #[cfg(not(unix))]
    {
        eprintln!("SKIP: symlinks not supported");
        return;
    }

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .safe_links(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Safe symlink should be transferred.
    assert_remote_exists(&ctx.remote.join("safe_link.txt")).await;
    // Unsafe symlink should be skipped.
    assert_remote_absent(&ctx.remote.join("unsafe_link.txt")).await;
}

#[tokio::test]
async fn test_interop_push_include_from() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("wanted.txt", b"yes\n", None)
        .with_src_file("unwanted.txt", b"no\n", None)
        .with_src_file("sub/deep.txt", b"deep\n", None)
        .build();

    let include_file = env.dir().join("includes.txt");
    // Include only *.txt at root and the sub/ directory.
    std::fs::write(&include_file, "wanted.txt\nsub/\nsub/deep.txt\n").unwrap();

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .include_from(&include_file)
        .exclude("*")
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_exists(&ctx.remote.join("wanted.txt")).await;
    assert_remote_absent(&ctx.remote.join("unwanted.txt")).await;
    assert_remote_exists(&ctx.remote.join("sub/deep.txt")).await;
}

#[tokio::test]
async fn test_interop_push_list_only() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"list only\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .list_only(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // --list-only should not create any files on remote.
    assert_remote_absent(&ctx.remote.join("file.txt")).await;
}

#[tokio::test]
async fn test_interop_push_relative() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("a/b/file.txt", b"relative\n", None)
        .build();

    let ctx = SshTestContext::new(env).await;

    // Push with --relative: the full source path structure should be preserved.
    let opts = TransferOptions::builder()
        .archive()
        .relative(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // With -R, the directory structure a/b/ should be preserved on remote.
    assert_remote_content(&ctx.remote.join("a/b/file.txt"), "relative\n").await;
}

#[tokio::test]
async fn test_interop_push_modify_window() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"window test\n", Some(1_700_000_000))
            .build(),
    )
    .await;

    // Seed remote with same content but mtime 1 second off.
    ssh_cmd(&[&format!(
        "echo -n 'window test\n' > {}/file.txt && touch -d @1700000001 {}/file.txt",
        ctx.remote.path(),
        ctx.remote.path()
    )])
    .await;

    // With modify-window=2, the 1-second difference should be ignored.
    let opts = TransferOptions::builder()
        .archive()
        .modify_window(2)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    assert_eq!(
        result.stats.files_transferred, 0,
        "modify-window=2 should skip file with 1s mtime difference"
    );
}

#[tokio::test]
async fn test_interop_push_checksum_choice() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("file.txt", b"checksum choice test\n", None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .checksum_choice("md5")
        .build();
    ctx.push_opts(opts, 30).await;

    assert_remote_content(&ctx.remote.join("file.txt"), "checksum choice test\n").await;
}

#[tokio::test]
async fn test_interop_push_timeout() {
    skip_if_no_ssh!();

    // Large file + tiny bwlimit + short timeout = should abort.
    let data = vec![b'T'; 1_048_576]; // 1 MB
    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("huge.dat", &data, None)
            .build(),
    )
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .bwlimit(1024) // 1 KB/s -- would take ~17 minutes
        .timeout(2) // 2 second timeout
        .build();

    // The transfer should fail due to timeout, not complete.
    let server_opts = ferrosync_core::engine::session::build_server_options(&opts, true);
    let transport = ferrosync_core::transport::ssh::SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        std::path::Path::new(ctx.remote.path()),
    );
    let fs = crate::common::env::test_filesystem();
    let session = ferrosync_core::engine::session::SyncSession::new(
        transport,
        TransferOptions::builder().from(opts).source(ctx.env.src()).build(),
        fs,
        ferrosync_core::engine::session::SyncDirection::Push,
    );

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        session.run(),
    )
    .await;

    match result {
        Ok(Ok(_)) => panic!("transfer should have timed out, not completed"),
        Ok(Err(_)) => {} // Expected: transfer error due to timeout
        Err(_) => panic!("outer timeout fired -- inner timeout should have triggered first"),
    }
}

#[tokio::test]
async fn test_interop_push_fuzzy() {
    skip_if_no_ssh!();

    let ctx = SshTestContext::new(
        TestEnv::builder()
            .with_src_file("report_2024.txt", b"annual report data here\n", None)
            .build(),
    )
    .await;

    // Seed remote with a similarly-named file that rsync can use as basis.
    ssh_cmd(&[&format!(
        "echo -n 'annual report data here\n' > {}/report_2023.txt",
        ctx.remote.path()
    )])
    .await;

    let opts = TransferOptions::builder()
        .archive()
        .fuzzy(true)
        .build();
    let result = ctx.push_opts(opts, 30).await;

    // The file should arrive with correct content.
    assert_remote_content(&ctx.remote.join("report_2024.txt"), "annual report data here\n").await;

    // With --fuzzy, rsync should find report_2023.txt as a basis file
    // and use delta transfer. matched_data should be > 0.
    assert!(
        result.stats.matched_data > 0,
        "fuzzy should find basis file and use delta (matched_data={}, literal_data={})",
        result.stats.matched_data,
        result.stats.literal_data
    );
}

#[tokio::test]
async fn test_interop_push_fake_super() {
    skip_if_no_ssh!();

    let env = TestEnv::builder()
        .with_src_file("exec.sh", b"#!/bin/sh\n", None)
        .build();

    // Set source to mode 0755.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            env.src().join("exec.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let ctx = SshTestContext::new(env).await;

    let opts = TransferOptions::builder()
        .archive()
        .preserve_xattrs(true)
        .fake_super(true)
        .build();
    ctx.push_opts(opts, 30).await;

    // Content should arrive.
    assert_remote_content(&ctx.remote.join("exec.sh"), "#!/bin/sh\n").await;

    // Real remote mode should be 0600 (fake-super safe mode).
    let mode_output = ssh_cmd(&["stat", "-c", "%a", &ctx.remote.join("exec.sh")]).await;
    let mode = u32::from_str_radix(mode_output.trim(), 8).unwrap();
    assert_eq!(
        mode, 0o600,
        "fake-super should set real remote mode to 0600, got {mode:04o}"
    );

    // The xattr should store the intended mode in rsync format.
    let xattr_val = remote_getfattr(&ctx.remote.join("exec.sh"), "user.rsync.%stat").await;
    assert!(
        xattr_val.starts_with("100755"),
        "xattr should start with '100755' (rsync format), got: {xattr_val}"
    );
}
