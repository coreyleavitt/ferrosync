use std::path::Path;
use std::process::Stdio;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::engine::transfer::TransferResult;
use ferrosync_core::fs::unix::UnixFileSystem;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::ssh::{KnownHostsPolicy, SshTransport, SshTransportConfig};

/// Check if SSH interop tests are enabled via environment variable.
pub fn ssh_test_enabled() -> bool {
    std::env::var("FERROSYNC_SSH_TEST").is_ok_and(|v| v == "1")
}

/// Get the SSH target hostname from the environment.
pub fn ssh_host() -> String {
    std::env::var("FERROSYNC_SSH_HOST").unwrap_or_else(|_| "rsync-ssh-target".to_string())
}

/// Initialize tracing for test output (idempotent).
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Skip the current test if FERROSYNC_SSH_TEST is not set.
#[macro_export]
macro_rules! skip_if_no_ssh {
    () => {
        if !$crate::common::ssh::ssh_test_enabled() {
            eprintln!("skipping: FERROSYNC_SSH_TEST not set");
            return;
        }
        $crate::common::ssh::init_tracing();
    };
}

/// Build an SshTransportConfig pointing at the test container.
pub fn test_ssh_config() -> SshTransportConfig {
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

/// Run a command on the SSH target via openssh CLI.
pub async fn ssh_cmd(args: &[&str]) -> String {
    let host = ssh_host();
    let output = tokio::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            "/root/.ssh/id_ed25519",
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
pub async fn remote_tmpdir() -> String {
    ssh_cmd(&["mktemp", "-d"]).await.trim().to_string()
}

/// Clean up a remote directory.
pub async fn remote_cleanup(dir: &str) {
    ssh_cmd(&["rm", "-rf", dir]).await;
}

/// Read a file on the remote.
pub async fn remote_cat(path: &str) -> String {
    ssh_cmd(&["cat", path]).await
}

/// Check if a file exists on the remote.
pub async fn remote_exists(path: &str) -> bool {
    let output = tokio::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            "/root/.ssh/id_ed25519",
        ])
        .arg(format!("root@{}", ssh_host()))
        .args(["test", "-e", path])
        .status()
        .await
        .expect("failed to run ssh command");
    output.success()
}

/// Push with archive mode over SSH. Returns the transfer result.
pub async fn push_archive(src: &Path, remote_dir: &str, timeout_secs: u64) -> TransferResult {
    let opts = TransferOptions::builder()
        .archive()
        .source(src.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(test_ssh_config(), true, &server_opts, Path::new(remote_dir));
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH push failed: {e}"),
        Err(_) => panic!("SSH push timed out after {timeout_secs}s"),
    }
}

/// Pull with archive mode over SSH. Returns the transfer result.
pub async fn pull_archive(remote_path: &str, dest: &Path, timeout_secs: u64) -> TransferResult {
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

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out after {timeout_secs}s"),
    }
}

/// Push with custom options over SSH. Returns the transfer result.
pub async fn push_with_opts(
    opts: TransferOptions,
    remote_dir: &str,
    timeout_secs: u64,
) -> TransferResult {
    let server_opts = build_server_options(&opts, true);
    let transport = SshTransport::new(test_ssh_config(), true, &server_opts, Path::new(remote_dir));
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH push failed: {e}"),
        Err(_) => panic!("SSH push timed out after {timeout_secs}s"),
    }
}

/// Pull with custom options over SSH. Returns the transfer result.
pub async fn pull_with_opts(
    opts: TransferOptions,
    remote_path: &str,
    timeout_secs: u64,
) -> TransferResult {
    let server_opts = build_server_options(&opts, false);
    let transport = SshTransport::new(
        test_ssh_config(),
        false,
        &server_opts,
        Path::new(remote_path),
    );
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out after {timeout_secs}s"),
    }
}
