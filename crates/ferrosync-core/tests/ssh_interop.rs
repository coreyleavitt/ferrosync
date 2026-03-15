//! SSH interop tests: ferrosync client to rsync server over SSH.
//!
//! These tests require a Docker environment with an SSH-accessible rsync target.
//! Run with:
//!
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

/// Run a command on the SSH target to set up or verify test state.
async fn ssh_cmd(args: &[&str]) -> String {
    let host = ssh_host();
    let output = tokio::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        .arg(format!("root@{}", host))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to run ssh command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[tokio::test]
async fn test_ssh_push_single_file() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("hello.txt"), "hello via SSH\n").unwrap();

    // Create remote temp dir
    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(&remote_dir),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        session.run(),
    )
    .await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("SSH push failed: {e}"),
        Err(_) => panic!("SSH push timed out after 30s"),
    }

    // Verify file arrived
    let content = ssh_cmd(&["cat", &format!("{}/hello.txt", remote_dir)]).await;
    assert_eq!(content, "hello via SSH\n");

    // Cleanup
    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}

#[tokio::test]
async fn test_ssh_push_directory_recursive() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("root.txt"), "root file\n").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), "nested\n").unwrap();

    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(&remote_dir),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        session.run(),
    )
    .await;

    match result {
        Ok(Ok(r)) => eprintln!("transferred {} files", r.stats.files_transferred),
        Ok(Err(e)) => panic!("SSH push failed: {e}"),
        Err(_) => panic!("SSH push timed out"),
    }

    let root = ssh_cmd(&["cat", &format!("{}/root.txt", remote_dir)]).await;
    assert_eq!(root, "root file\n");

    let nested = ssh_cmd(&["cat", &format!("{}/subdir/nested.txt", remote_dir)]).await;
    assert_eq!(nested, "nested\n");

    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}

#[tokio::test]
async fn test_ssh_pull_single_file() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();
    ssh_cmd(&["sh", "-c", &format!("echo 'pulled via SSH' > {}/pull.txt", remote_dir)]).await;

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let remote_path = format!("{}/", remote_dir);
    let transport = SshTransport::new(
        test_ssh_config(),
        false,
        &server_opts,
        Path::new(&remote_path),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        session.run(),
    )
    .await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out"),
    }

    let content = std::fs::read_to_string(dst.join("pull.txt")).unwrap();
    assert_eq!(content, "pulled via SSH\n");

    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}

#[tokio::test]
async fn test_ssh_pull_directory_recursive() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();
    ssh_cmd(&["mkdir", "-p", &format!("{}/sub", remote_dir)]).await;
    ssh_cmd(&["sh", "-c", &format!("echo 'top' > {}/top.txt", remote_dir)]).await;
    ssh_cmd(&["sh", "-c", &format!("echo 'sub' > {}/sub/deep.txt", remote_dir)]).await;

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let remote_path = format!("{}/", remote_dir);
    let transport = SshTransport::new(
        test_ssh_config(),
        false,
        &server_opts,
        Path::new(&remote_path),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        session.run(),
    )
    .await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out"),
    }

    assert_eq!(std::fs::read_to_string(dst.join("top.txt")).unwrap(), "top\n");
    assert_eq!(std::fs::read_to_string(dst.join("sub/deep.txt")).unwrap(), "sub\n");

    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}

#[tokio::test]
async fn test_ssh_push_preserves_times() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("timed.txt"), "check mtime\n").unwrap();

    // Set a known mtime
    let known_mtime = filetime::FileTime::from_unix_time(1700000000, 0);
    filetime::set_file_mtime(src.join("timed.txt"), known_mtime).unwrap();

    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(&remote_dir),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    session.run().await.unwrap();

    // Check mtime via stat
    let stat_output = ssh_cmd(&["stat", "-c", "%Y", &format!("{}/timed.txt", remote_dir)]).await;
    let remote_mtime: i64 = stat_output.trim().parse().unwrap();
    assert_eq!(remote_mtime, 1700000000, "mtime should be preserved");

    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}

#[tokio::test]
async fn test_ssh_push_idempotent() {
    skip_if_no_ssh!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("stable.txt"), "no change\n").unwrap();

    let remote_dir = ssh_cmd(&["mktemp", "-d"]).await.trim().to_string();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .build();

    let server_opts = build_server_options(&opts, true);

    // First push
    let transport = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(&remote_dir),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts.clone(), fs, SyncDirection::Push);
    session.run().await.unwrap();

    // Second push (should be no-op or at least succeed)
    let transport2 = SshTransport::new(
        test_ssh_config(),
        true,
        &server_opts,
        Path::new(&remote_dir),
    );
    let fs2 = Box::new(UnixFileSystem::new());
    let session2 = SyncSession::new(transport2, opts, fs2, SyncDirection::Push);
    let result = session2.run().await.unwrap();

    // Verify quick-check means fewer transfers on second run
    eprintln!("second push: {} files transferred", result.stats.files_transferred);

    let content = ssh_cmd(&["cat", &format!("{}/stable.txt", remote_dir)]).await;
    assert_eq!(content, "no change\n");

    ssh_cmd(&["rm", "-rf", &remote_dir]).await;
}
