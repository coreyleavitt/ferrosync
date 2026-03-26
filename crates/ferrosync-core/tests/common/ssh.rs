use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::engine::transfer::TransferResult;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::ssh::{KnownHostsPolicy, SshTransport, SshTransportConfig};
use ferrosync_core::transport::ssh_auth::AuthPrompter;

use super::env::test_filesystem;

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
        use_agent: false,
        ..Default::default()
    }
}

/// Mock auth prompter for testing password and keyboard-interactive auth.
///
/// Returns canned responses instead of prompting a terminal.
pub struct MockPrompter {
    pub password: String,
}

impl AuthPrompter for MockPrompter {
    fn prompt_password(
        &self,
        _user: &str,
        _host: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let pw = self.password.clone();
        Box::pin(async move { Some(pw) })
    }

    fn prompt_keyboard_interactive(
        &self,
        _user: &str,
        _host: &str,
        _name: &str,
        _instructions: &str,
        prompts: &[(String, bool)],
    ) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + '_>> {
        // Answer every prompt with the stored password.
        let responses: Vec<String> = prompts.iter().map(|_| self.password.clone()).collect();
        Box::pin(async move { Some(responses) })
    }
}

/// Build an SshTransportConfig for the password test user.
pub fn test_password_ssh_config() -> SshTransportConfig {
    SshTransportConfig {
        host: ssh_host(),
        port: 22,
        user: "testpw".to_string(),
        identity_files: vec![], // no keys
        known_hosts_policy: KnownHostsPolicy::AcceptAll,
        rsync_path: "rsync".to_string(),
        use_agent: false,
        auth_prompter: Some(Arc::new(MockPrompter {
            password: "testpass123".to_string(),
        })),
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
    let fs = test_filesystem();
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
    let fs = test_filesystem();
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
    let fs = test_filesystem();
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
    let fs = test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("SSH pull failed: {e}"),
        Err(_) => panic!("SSH pull timed out after {timeout_secs}s"),
    }
}

// ---------------------------------------------------------------------------
// Reverse interop helpers: rsync client → ferrosync --server
// ---------------------------------------------------------------------------

/// Result of running an rsync CLI command.
pub struct RsyncResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Check if ferrosync binary is available on the SSH target.
pub async fn ferrosync_available_on_target() -> bool {
    let output = ssh_cmd(&["which", "ferrosync"]).await;
    !output.trim().is_empty()
}

/// SSH command prefix for rsync -e flag.
fn rsync_ssh_args() -> String {
    "ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR".to_string()
}

/// Push local files to remote using rsync client → ferrosync --server.
pub async fn rsync_push(
    local_src: &Path,
    remote_dest: &str,
    extra_args: &[&str],
    timeout_secs: u64,
) -> RsyncResult {
    let host = ssh_host();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::process::Command::new("rsync")
            .arg("-a")
            .arg("--rsync-path=ferrosync")
            .args(extra_args)
            .arg("-e")
            .arg(rsync_ssh_args())
            .arg(format!("{}/", local_src.display()))
            .arg(format!("root@{host}:{remote_dest}/"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("rsync push timed out after {timeout_secs}s"))
    .expect("failed to run rsync command");

    RsyncResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Pull remote files to local using rsync client → ferrosync --server.
pub async fn rsync_pull(
    remote_src: &str,
    local_dest: &Path,
    extra_args: &[&str],
    timeout_secs: u64,
) -> RsyncResult {
    let host = ssh_host();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::process::Command::new("rsync")
            .arg("-a")
            .arg("--rsync-path=ferrosync")
            .args(extra_args)
            .arg("-e")
            .arg(rsync_ssh_args())
            .arg(format!("root@{host}:{remote_src}/"))
            .arg(format!("{}/", local_dest.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("rsync pull timed out after {timeout_secs}s"))
    .expect("failed to run rsync command");

    RsyncResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Skip macro for reverse interop tests.
///
/// Skips if SSH tests are not enabled or if ferrosync binary is not
/// available on the SSH target.
#[macro_export]
macro_rules! skip_if_no_reverse {
    () => {
        if !$crate::common::ssh::ssh_test_enabled() {
            eprintln!("skipping: FERROSYNC_SSH_TEST not set");
            return;
        }
        $crate::common::ssh::init_tracing();
        if !$crate::common::ssh::ferrosync_available_on_target().await {
            eprintln!("skipping: ferrosync not found on SSH target (run cargo build -p ferrosync-cli first)");
            return;
        }
    };
}
