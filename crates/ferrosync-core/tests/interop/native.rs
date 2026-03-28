//! Native tests: ferrosync client -> ferrosync --server over SSH.

use crate::common::assertions::*;
use crate::common::env::TestEnv;
use crate::common::ssh::*;
use crate::common::TransferOptions;
use crate::skip_if_no_reverse;

#[tokio::test]
async fn test_native_push() {
    skip_if_no_reverse!();

    let env = TestEnv::builder()
        .with_src_file("native.txt", b"native push\n", None)
        .build();

    let remote = RemoteDir::new().await;

    let opts = TransferOptions::builder()
        .archive()
        .source(env.src())
        .build();

    let mut ssh_config = crate::common::ssh::test_ssh_config();
    ssh_config.rsync_path = "ferrosync".to_string();

    let server_opts = ferrosync_core::engine::session::build_server_options(&opts, true);
    let transport = ferrosync_core::transport::ssh::SshTransport::new(
        ssh_config,
        true,
        &server_opts,
        std::path::Path::new(remote.path()),
    );
    let fs = crate::common::env::test_filesystem();
    let session = ferrosync_core::engine::session::SyncSession::new(
        transport,
        opts,
        fs,
        ferrosync_core::engine::session::SyncDirection::Push,
    );

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), session.run())
        .await
        .expect("native push timed out")
        .expect("native push failed");

    assert!(
        result.stats.files_transferred == 1,
        "native push should transfer exactly 1 file, got {}",
        result.stats.files_transferred
    );

    let content = remote_cat(&remote.join("native.txt")).await;
    assert_eq!(content, "native push\n");
}

#[tokio::test]
async fn test_native_pull() {
    skip_if_no_reverse!();

    let remote = RemoteDir::new().await;
    ssh_cmd(&[
        "sh",
        "-c",
        &format!("echo -n 'native pull' > {}/native.txt", remote.path()),
    ])
    .await;

    let env = TestEnv::builder().build();

    let opts = TransferOptions::builder().archive().dest(env.dst()).build();

    let mut ssh_config = crate::common::ssh::test_ssh_config();
    ssh_config.rsync_path = "ferrosync".to_string();

    let remote_path = remote.path_slash();
    let server_opts = ferrosync_core::engine::session::build_server_options(&opts, false);
    let transport = ferrosync_core::transport::ssh::SshTransport::new(
        ssh_config,
        false,
        &server_opts,
        std::path::Path::new(&remote_path),
    );
    let fs = crate::common::env::test_filesystem();
    let session = ferrosync_core::engine::session::SyncSession::new(
        transport,
        opts,
        fs,
        ferrosync_core::engine::session::SyncDirection::Pull,
    );

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), session.run())
        .await
        .expect("native pull timed out")
        .expect("native pull failed");

    assert!(
        result.stats.files_transferred == 1,
        "native pull should transfer exactly 1 file, got {}",
        result.stats.files_transferred
    );

    let content = std::fs::read_to_string(env.dst().join("native.txt")).unwrap();
    assert_eq!(content, "native pull");
}
