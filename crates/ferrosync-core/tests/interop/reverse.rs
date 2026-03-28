//! Reverse interop tests: rsync client -> ferrosync --server.

use crate::common::assertions::*;
use crate::common::env::{set_mtime, TestEnv};
use crate::common::ssh::*;
use crate::{skip_if_no_reverse, skip_if_no_ssh};

#[tokio::test]
async fn test_reverse_push_single_file() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("hello.txt", b"reverse push\n", None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&remote.join("hello.txt")).await;
    assert_eq!(content, "reverse push\n");
}

#[tokio::test]
async fn test_reverse_push_directory() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("top.txt", b"top\n", None)
        .with_src_file("a/mid.txt", b"mid\n", None)
        .with_src_file("a/b/deep.txt", b"deep\n", None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(remote_cat(&remote.join("top.txt")).await, "top\n");
    assert_eq!(
        remote_cat(&remote.join("a/mid.txt")).await,
        "mid\n"
    );
    assert_eq!(
        remote_cat(&remote.join("a/b/deep.txt")).await,
        "deep\n"
    );
}

#[tokio::test]
async fn test_reverse_push_large_file() {
    skip_if_no_reverse!();

    let data = vec![b'A'; 1024 * 1024];
    let env = TestEnv::builder()
        .with_src_file("big.dat", &data, None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &[], 60).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_remote_size(&remote.join("big.dat"), 1024 * 1024).await;
}

#[tokio::test]
async fn test_reverse_pull_single_file() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'reverse pull' > {}/data.txt", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(remote.path(), &env.dst(), &[], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("data.txt")).unwrap();
    assert_eq!(content, "reverse pull");
}

#[tokio::test]
async fn test_reverse_pull_directory() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&["mkdir", "-p", &remote.join("sub/deep")]).await;
    ssh_cmd(&["sh", "-c", &format!("echo -n 'top' > {}/top.txt", remote.path())]).await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'mid' > {}/sub/mid.txt", remote.path()),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'deep' > {}/sub/deep/deep.txt", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(remote.path(), &env.dst(), &[], 30).await;
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
}

#[tokio::test]
async fn test_reverse_pull_large_file() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    // Create a 1MB file on the remote
    ssh_cmd(&[
        "sh",
        "-c",
        &format!(
            "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\\0' 'B' > {}/big.dat",
            remote.path()
        ),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(remote.path(), &env.dst(), &[], 60).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read(env.dst().join("big.dat")).unwrap();
    assert_eq!(content.len(), 1024 * 1024, "pulled file should be 1MB");
    assert!(
        content.iter().all(|&b| b == b'B'),
        "pulled file content should be all 'B' bytes"
    );
}

// --- Reverse flag-specific tests ---

#[tokio::test]
async fn test_reverse_push_compress() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("compressed.txt", b"compress test data\n", None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &["-z"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&remote.join("compressed.txt")).await;
    assert_eq!(content, "compress test data\n");

    assert_remote_size(&remote.join("compressed.txt"), 19).await;
}

#[tokio::test]
async fn test_reverse_pull_compress() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'compressed pull' > {}/data.txt", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(remote.path(), &env.dst(), &["-z"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("data.txt")).unwrap();
    assert_eq!(content, "compressed pull");

    let metadata = std::fs::metadata(env.dst().join("data.txt")).unwrap();
    assert_eq!(
        metadata.len(),
        15,
        "compressed pull should produce correct file size"
    );
}

#[tokio::test]
async fn test_reverse_push_checksum() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("check.txt", b"version1", None)
        .build();

    let remote = RemoteDir::new().await;

    // Push v1
    let result = rsync_push(&env.src(), remote.path(), &[], 30).await;
    assert!(result.success, "rsync v1 push failed: {}", result.stderr);

    // Overwrite with v2 (same size, same mtime -- only checksum detects the change)
    std::fs::write(env.src().join("check.txt"), b"version2").unwrap();
    set_mtime(&env.src().join("check.txt"), 1700000000);
    // Also set mtime on the remote copy to match
    ssh_cmd(&[
        "touch",
        "-d",
        "@1700000000",
        &remote.join("check.txt"),
    ])
    .await;

    // Push v2 with checksum -- should detect the difference
    let result = rsync_push(&env.src(), remote.path(), &["-c"], 30).await;
    assert!(
        result.success,
        "rsync checksum push failed: {}",
        result.stderr
    );

    let content = remote_cat(&remote.join("check.txt")).await;
    assert_eq!(content, "version2");
}

#[tokio::test]
async fn test_reverse_pull_delete() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'keep' > {}/keep.txt", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();
    // Create an extra file locally that does not exist on remote
    std::fs::write(env.dst().join("extra.txt"), b"should be deleted").unwrap();

    let result = rsync_pull(remote.path(), &env.dst(), &["--delete"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert_eq!(
        std::fs::read_to_string(env.dst().join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(
        !env.dst().join("extra.txt").exists(),
        "extra.txt should have been deleted by --delete"
    );
}

#[tokio::test]
async fn test_reverse_push_dry_run() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("dryrun.txt", b"should not arrive\n", None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &["-n"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    assert!(
        !remote_exists(&remote.join("dryrun.txt")).await,
        "dry-run should not create files on remote"
    );
}

#[tokio::test]
async fn test_reverse_pull_exclude() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'keep' > {}/data.txt", remote.path()),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'skip' > {}/debug.log", remote.path()),
    ])
    .await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'skip2' > {}/trace.log", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();
    let result = rsync_pull(remote.path(), &env.dst(), &["--exclude=*.log"], 30).await;
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
}

#[tokio::test]
async fn test_reverse_push_whole_file() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("whole.txt", b"whole file transfer\n", None)
        .build();

    let remote = RemoteDir::new().await;
    let result = rsync_push(&env.src(), remote.path(), &["-W"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = remote_cat(&remote.join("whole.txt")).await;
    assert_eq!(content, "whole file transfer\n");

    assert_remote_size(&remote.join("whole.txt"), 20).await;
}

#[tokio::test]
async fn test_reverse_pull_update() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'old remote' > {}/file.txt", remote.path()),
    ])
    .await;
    ssh_cmd(&[
        "touch",
        "-d",
        "@1700000000",
        &remote.join("file.txt"),
    ])
    .await;

    let env = TestEnv::builder().build();
    // Create local file with newer mtime -- -u should skip overwriting it
    std::fs::write(env.dst().join("file.txt"), b"newer local").unwrap();
    set_mtime(&env.dst().join("file.txt"), 1800000000);

    let result = rsync_pull(remote.path(), &env.dst(), &["-u"], 30).await;
    assert!(result.success, "rsync failed: {}", result.stderr);

    let content = std::fs::read_to_string(env.dst().join("file.txt")).unwrap();
    assert_eq!(
        content, "newer local",
        "-u should not overwrite newer local file"
    );
}
