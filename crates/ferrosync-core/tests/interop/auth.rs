//! Authentication tests: verify that agent, password, and keyboard-interactive
//! auth methods work against real sshd.

use std::path::Path;
use std::sync::Arc;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::ssh::{KnownHostsPolicy, SshTransport, SshTransportConfig};

use crate::common::assertions::*;
use crate::common::env::TestEnv;
use crate::common::ssh::*;
use crate::skip_if_no_ssh;

/// Pull a single file using a custom SSH config.
async fn pull_with_config(
    config: SshTransportConfig,
    remote_path: &str,
    dest: &Path,
    timeout_secs: u64,
) {
    let opts = TransferOptions::builder()
        .archive()
        .dest(dest.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = SshTransport::new(config, false, &server_opts, Path::new(remote_path));
    let fs = crate::common::env::test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), session.run()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("SSH pull with custom config failed: {e}"),
        Err(_) => panic!("SSH pull timed out after {timeout_secs}s"),
    }
}

// -------------------------------------------------------------------------
// Password authentication
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_password_pull() {
    skip_if_no_ssh!();

    // Set up a file on the remote (via root key-based auth).
    let remote_dir = remote_tmpdir().await;
    let env = TestEnv::builder()
        .with_src_file("auth_test.txt", b"password auth works\n", None)
        .build();
    push_archive(&env.src(), &remote_dir, 30).await;

    // Make the remote dir world-readable so testpw can access it.
    ssh_cmd(&["chmod", "-R", "o+rX", &remote_dir]).await;

    // Pull the file as the password-auth user.
    let pull_dest = TestEnv::builder().build();
    let remote_path = format!("{remote_dir}/");
    pull_with_config(
        test_password_ssh_config(),
        &remote_path,
        &pull_dest.dst(),
        30,
    )
    .await;

    // Verify the file arrived with correct content.
    let content = std::fs::read_to_string(pull_dest.dst().join("auth_test.txt")).unwrap();
    assert_eq!(content, "password auth works\n");

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_auth_password_wrong_password_fails() {
    skip_if_no_ssh!();

    let config = SshTransportConfig {
        host: ssh_host(),
        user: "testpw".to_string(),
        identity_files: vec![],
        known_hosts_policy: KnownHostsPolicy::AcceptAll,
        rsync_path: "rsync".to_string(),
        use_agent: false,
        auth_prompter: Some(Arc::new(MockPrompter {
            password: "wrongpassword".to_string(),
        })),
        ..Default::default()
    };

    let pull_dest = TestEnv::builder().build();
    let opts = TransferOptions::builder()
        .archive()
        .dest(pull_dest.dst())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = SshTransport::new(config, false, &server_opts, Path::new("/tmp/"));
    let fs = crate::common::env::test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result =
        tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await;

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("authentication") || msg.contains("auth"),
                "expected auth error, got: {msg}"
            );
        }
        Ok(Ok(_)) => panic!("expected auth failure with wrong password"),
        Err(_) => panic!("timed out -- should have failed quickly with wrong password"),
    }
}

// -------------------------------------------------------------------------
// Agent authentication
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_agent_pull() {
    skip_if_no_ssh!();

    // Start ssh-agent and add the test key.
    let agent_setup = tokio::process::Command::new("bash")
        .args(["-c", "eval $(ssh-agent -s) && ssh-add /root/.ssh/id_ed25519 2>/dev/null && echo $SSH_AUTH_SOCK"])
        .output()
        .await
        .expect("failed to start ssh-agent");

    let stdout = String::from_utf8_lossy(&agent_setup.stdout);
    let auth_sock = stdout.lines().last().unwrap_or("").trim();
    if auth_sock.is_empty() || !auth_sock.starts_with('/') {
        eprintln!("skipping agent test: could not start ssh-agent");
        return;
    }

    // Set the SSH_AUTH_SOCK for this test.
    std::env::set_var("SSH_AUTH_SOCK", auth_sock);

    // Set up a file on the remote.
    let remote_dir = remote_tmpdir().await;
    let env = TestEnv::builder()
        .with_src_file("agent_test.txt", b"agent auth works\n", None)
        .build();
    push_archive(&env.src(), &remote_dir, 30).await;

    // Pull using agent auth: no identity files, agent enabled.
    let config = SshTransportConfig {
        host: ssh_host(),
        user: "root".to_string(),
        identity_files: vec![], // no keys on disk
        known_hosts_policy: KnownHostsPolicy::AcceptAll,
        rsync_path: "rsync".to_string(),
        use_agent: true, // use agent
        auth_prompter: None,
        ..Default::default()
    };

    let pull_dest = TestEnv::builder().build();
    let remote_path = format!("{remote_dir}/");
    pull_with_config(config, &remote_path, &pull_dest.dst(), 30).await;

    // Verify file content.
    let content = std::fs::read_to_string(pull_dest.dst().join("agent_test.txt")).unwrap();
    assert_eq!(content, "agent auth works\n");

    // Clean up: kill the agent.
    std::env::remove_var("SSH_AUTH_SOCK");
    remote_cleanup(&remote_dir).await;
}

// -------------------------------------------------------------------------
// Negative: batch mode with no keys or agent
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_batch_mode_no_keys_fails() {
    skip_if_no_ssh!();

    // No agent, no keys, no prompter = should fail.
    let config = SshTransportConfig {
        host: ssh_host(),
        user: "testpw".to_string(),
        identity_files: vec![],
        known_hosts_policy: KnownHostsPolicy::AcceptAll,
        rsync_path: "rsync".to_string(),
        use_agent: false,
        auth_prompter: None, // batch mode: no interactive prompts
        ..Default::default()
    };

    let pull_dest = TestEnv::builder().build();
    let opts = TransferOptions::builder()
        .archive()
        .dest(pull_dest.dst())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = SshTransport::new(config, false, &server_opts, Path::new("/tmp/"));
    let fs = crate::common::env::test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result =
        tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await;

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("authentication") || msg.contains("auth"),
                "expected auth error, got: {msg}"
            );
        }
        Ok(Ok(_)) => panic!("expected auth failure with no keys and no prompter"),
        Err(_) => panic!("timed out -- should have failed quickly"),
    }
}
