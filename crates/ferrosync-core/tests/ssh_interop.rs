//! SSH integration tests: ferrosync client to rsync server over SSH.
//!
//! These are the REAL end-to-end tests. They exercise the exact path users take:
//! ferrosync client -> SSH -> rsync --server on a real Linux box.
//!
//! Requires Docker:
//! ```sh
//! docker compose -f docker-compose.test.yml run ferrosync-dev \
//!     cargo test -p ferrosync-core --test ssh_interop
//! ```
//!
//! Gated behind FERROSYNC_SSH_TEST=1 env var.
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::fs::unix::UnixFileSystem;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::ssh::{KnownHostsPolicy, SshTransport, SshTransportConfig};

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

fn ssh_test_enabled() -> bool {
    std::env::var("FERROSYNC_SSH_TEST").map_or(false, |v| v == "1")
}

fn ssh_host() -> String {
    std::env::var("FERROSYNC_SSH_HOST").unwrap_or_else(|_| "rsync-ssh-target".to_string())
}

macro_rules! skip_if_no_ssh {
    () => {
        if !ssh_test_enabled() {
            eprintln!("skipping: FERROSYNC_SSH_TEST not set");
            return;
        }
    };
}

/// Build an SshTransportConfig pointing at the test container.
fn test_ssh_config() -> SshTransportConfig {
    SshTransportConfig {
        host: ssh_host(),
        port: 22,
        user: "root".to_string(),
        identity_files: vec!["/root/.ssh/id_ed25519".into()],
        known_hosts_policy: KnownHostsPolicy::AcceptAll,
        rsync_path: "rsync".to_string(),
        ..Default::default()
    }
}

/// Run a command on the SSH target via openssh cli.
async fn ssh_cmd(args: &[&str]) -> String {
    let host = ssh_host();
    let output = tokio::process::Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-i", "/root/.ssh/id_ed25519",
        ])
        .arg(format!("root@{host}"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to run ssh command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Create a temp dir on the remote and return its path.
async fn remote_tmpdir() -> String {
    ssh_cmd(&["mktemp", "-d"]).await.trim().to_string()
}

/// Clean up a remote directory.
async fn remote_cleanup(dir: &str) {
    ssh_cmd(&["rm", "-rf", dir]).await;
}

/// Read a file on the remote.
async fn remote_cat(path: &str) -> String {
    ssh_cmd(&["cat", path]).await
}

/// Check if a file exists on the remote.
async fn remote_exists(path: &str) -> bool {
    let output = tokio::process::Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-i", "/root/.ssh/id_ed25519",
        ])
        .arg(format!("root@{}", ssh_host()))
        .args(["test", "-e", path])
        .status()
        .await
        .expect("failed to run ssh command");
    output.success()
}

/// Push helper: builds archive-mode options, creates transport, runs session.
async fn push_archive(
    src: &Path,
    remote_dir: &str,
    timeout_secs: u64,
) -> ferrosync_core::engine::transfer::TransferResult {
    let opts = TransferOptions::builder()
        .archive()
        .source(src.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(remote_dir),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        session.run(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH push failed: {e}"),
        Err(_) => panic!("SSH push timed out after {timeout_secs}s"),
    }
}

/// Pull helper: builds archive-mode options, creates transport, runs session.
async fn pull_archive(
    remote_path: &str,
    dest: &Path,
    timeout_secs: u64,
) -> ferrosync_core::engine::transfer::TransferResult {
    let opts = TransferOptions::builder()
        .archive()
        .dest(dest.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = SshTransport::new(
        test_ssh_config(),
        false,
        &server_opts,
        Path::new(remote_path),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        session.run(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out after {timeout_secs}s"),
    }
}

// ---------------------------------------------------------------------------
// Push tests: ferrosync client -> rsync server over SSH
// All use -rav (archive mode) unless noted.
// ---------------------------------------------------------------------------

/// Push a single small file with archive mode.
#[tokio::test]
async fn test_ssh_push_single_file() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), "hello via SSH\n").unwrap();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&src, &remote_dir, 30).await;
    assert!(result.stats.files_transferred >= 1);

    let content = remote_cat(&format!("{remote_dir}/hello.txt")).await;
    assert_eq!(content, "hello via SSH\n");

    remote_cleanup(&remote_dir).await;
}

/// Push a directory tree with subdirs.
#[tokio::test]
async fn test_ssh_push_directory_recursive() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("a/b")).unwrap();
    std::fs::write(src.join("top.txt"), "top\n").unwrap();
    std::fs::write(src.join("a/mid.txt"), "mid\n").unwrap();
    std::fs::write(src.join("a/b/deep.txt"), "deep\n").unwrap();

    let remote_dir = remote_tmpdir().await;
    push_archive(&src, &remote_dir, 30).await;

    assert_eq!(remote_cat(&format!("{remote_dir}/top.txt")).await, "top\n");
    assert_eq!(remote_cat(&format!("{remote_dir}/a/mid.txt")).await, "mid\n");
    assert_eq!(remote_cat(&format!("{remote_dir}/a/b/deep.txt")).await, "deep\n");

    remote_cleanup(&remote_dir).await;
}

/// Push many small files to exercise the sender loop with multiple NDX rounds.
#[tokio::test]
async fn test_ssh_push_many_small_files() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Create 50 small files
    for i in 0..50 {
        std::fs::write(src.join(format!("file_{i:03}.txt")), format!("content {i}\n")).unwrap();
    }

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&src, &remote_dir, 60).await;
    assert_eq!(result.stats.files_transferred, 50);

    // Spot-check a few
    assert_eq!(remote_cat(&format!("{remote_dir}/file_000.txt")).await, "content 0\n");
    assert_eq!(remote_cat(&format!("{remote_dir}/file_049.txt")).await, "content 49\n");

    remote_cleanup(&remote_dir).await;
}

/// Push a large file (1MB) that requires multiple 32KB MUX chunks.
/// This exercises flow control between sender writes and demux reads.
#[tokio::test]
async fn test_ssh_push_large_file() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // 1MB file with recognizable pattern
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.join("big.dat"), &data).unwrap();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&src, &remote_dir, 60).await;
    assert_eq!(result.stats.files_transferred, 1);

    // Verify size on remote
    let size = ssh_cmd(&["stat", "-c", "%s", &format!("{remote_dir}/big.dat")]).await;
    assert_eq!(size.trim(), "1048576");

    // Verify first and last bytes match via xxd
    let head = ssh_cmd(&["xxd", "-l", "16", "-p", &format!("{remote_dir}/big.dat")]).await;
    let expected_head: String = data[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(head.trim(), expected_head, "large file head mismatch");

    let tail = ssh_cmd(&[
        "xxd", "-s", "-16", "-l", "16", "-p",
        &format!("{remote_dir}/big.dat"),
    ]).await;
    let expected_tail: String = data[data.len() - 16..].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(tail.trim(), expected_tail, "large file tail mismatch");

    remote_cleanup(&remote_dir).await;
}

/// Push a mixed directory: subdirs + many small files + one large file.
/// This is the scenario that deadlocks with the 64KB demux pipe.
#[tokio::test]
async fn test_ssh_push_mixed_directory() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();

    // 20 small files in root
    for i in 0..20 {
        std::fs::write(src.join(format!("small_{i:02}.txt")), format!("data {i}\n")).unwrap();
    }

    // 10 small files in subdir
    for i in 0..10 {
        std::fs::write(
            src.join(format!("sub/nested_{i:02}.txt")),
            format!("nested {i}\n"),
        )
        .unwrap();
    }

    // One 512KB file
    let big_data: Vec<u8> = (0..524_288).map(|i| (i % 199) as u8).collect();
    std::fs::write(src.join("medium.bin"), &big_data).unwrap();

    let remote_dir = remote_tmpdir().await;
    let result = push_archive(&src, &remote_dir, 120).await;

    // 20 + 10 + 1 = 31 files
    assert_eq!(result.stats.files_transferred, 31);

    // Spot-check
    assert_eq!(remote_cat(&format!("{remote_dir}/small_00.txt")).await, "data 0\n");
    assert_eq!(remote_cat(&format!("{remote_dir}/sub/nested_09.txt")).await, "nested 9\n");
    assert!(remote_exists(&format!("{remote_dir}/medium.bin")).await);

    remote_cleanup(&remote_dir).await;
}

/// Push preserves mtime.
#[tokio::test]
async fn test_ssh_push_preserves_mtime() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("timed.txt"), "check mtime\n").unwrap();

    let known_mtime = filetime::FileTime::from_unix_time(1700000000, 0);
    filetime::set_file_mtime(src.join("timed.txt"), known_mtime).unwrap();

    let remote_dir = remote_tmpdir().await;
    push_archive(&src, &remote_dir, 30).await;

    let stat_output = ssh_cmd(&["stat", "-c", "%Y", &format!("{remote_dir}/timed.txt")]).await;
    let remote_mtime: i64 = stat_output.trim().parse().unwrap();
    assert_eq!(remote_mtime, 1700000000, "mtime should be preserved");

    remote_cleanup(&remote_dir).await;
}

/// Push twice -- second push should succeed (idempotent).
#[tokio::test]
async fn test_ssh_push_idempotent() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("stable.txt"), "no change\n").unwrap();

    let remote_dir = remote_tmpdir().await;

    // First push
    push_archive(&src, &remote_dir, 30).await;

    // Second push (should succeed, ideally fewer transfers)
    let result2 = push_archive(&src, &remote_dir, 30).await;
    eprintln!("second push: {} files transferred", result2.stats.files_transferred);

    let content = remote_cat(&format!("{remote_dir}/stable.txt")).await;
    assert_eq!(content, "no change\n");

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Pull tests: ferrosync client <- rsync server over SSH
// ---------------------------------------------------------------------------

/// Pull a single file with archive mode.
#[tokio::test]
async fn test_ssh_pull_single_file() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&["sh", "-c", &format!("echo 'pulled via SSH' > {remote_dir}/pull.txt")]).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &dst, 30).await;

    let content = std::fs::read_to_string(dst.join("pull.txt")).unwrap();
    assert_eq!(content, "pulled via SSH\n");

    remote_cleanup(&remote_dir).await;
}

/// Pull a directory tree with subdirs.
#[tokio::test]
async fn test_ssh_pull_directory_recursive() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    let remote_dir = remote_tmpdir().await;
    ssh_cmd(&["mkdir", "-p", &format!("{remote_dir}/sub")]).await;
    ssh_cmd(&["sh", "-c", &format!("echo 'top' > {remote_dir}/top.txt")]).await;
    ssh_cmd(&["sh", "-c", &format!("echo 'deep' > {remote_dir}/sub/deep.txt")]).await;

    let remote_path = format!("{remote_dir}/");
    pull_archive(&remote_path, &dst, 30).await;

    assert_eq!(std::fs::read_to_string(dst.join("top.txt")).unwrap(), "top\n");
    assert_eq!(std::fs::read_to_string(dst.join("sub/deep.txt")).unwrap(), "deep\n");

    remote_cleanup(&remote_dir).await;
}
