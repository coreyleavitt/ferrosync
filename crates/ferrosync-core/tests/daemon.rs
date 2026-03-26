//! Daemon tests: ferrosync client to ferrosync daemon server.
//!
//! These tests verify the daemon transport layer, module system,
//! and authentication -- concerns that cannot be tested through
//! `execute_transfer` alone. General transfer correctness is tested
//! in `engine.rs`; these tests focus on what is unique to daemon mode.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::watch;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::options::TransferOptions;

use common::env::test_filesystem;
use ferrosync_core::server::listener::{DaemonListener, ListenerConfig};
use ferrosync_core::server::module::{AccessControl, Module, ModuleAuth, ModuleRegistry};
use ferrosync_core::transport::daemon::{DaemonTransport, DaemonTransportConfig};

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Start a test server with a single module pointing at the given path.
///
/// Returns the bound address and a shutdown sender.
async fn start_test_server(
    module_path: &Path,
    read_only: bool,
) -> (SocketAddr, watch::Sender<bool>) {
    let mut registry = ModuleRegistry::new();
    registry.register(Module {
        name: "test".to_string(),
        path: module_path.to_path_buf(),
        read_only,
        list: true,
        comment: "Test module".to_string(),
        auth: ModuleAuth {
            auth_users: String::new(),
            secrets_file: None,
        },
        access: AccessControl::default(),
        max_connections: 0,
        timeout: 0,
        exclude: Vec::new(),
        include: Vec::new(),
        filter: Vec::new(),
    });

    let config = ListenerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        motd: None,
    };

    let listener = DaemonListener::new(config, Arc::new(registry));
    let shutdown = listener.shutdown_handle();

    let (tcp_listener, addr) = listener.bind().await.expect("failed to bind test server");

    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);
    tokio::spawn(async move {
        let _ = listener_clone.serve(tcp_listener).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    (addr, shutdown)
}

/// Pull files from a test server module to a local destination.
async fn ferrosync_client_pull(addr: SocketAddr, module: &str, dest: &Path) {
    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .dest(dest.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, false);

    let config = DaemonTransportConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        module: module.to_string(),
        path: ".".to_string(),
        user: None,
        password: None,
        connect_timeout: std::time::Duration::from_secs(5),
    };

    let transport = DaemonTransport::new(config, false, &server_opts);
    let fs = test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull session failed: {e}"),
        Err(_) => panic!("pull session timed out after 15s"),
    }
}

/// Push files from a local source to a test server module.
async fn ferrosync_client_push(addr: SocketAddr, module: &str, source: &Path) {
    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(source.to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, true);

    let config = DaemonTransportConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        module: module.to_string(),
        path: ".".to_string(),
        user: None,
        password: None,
        connect_timeout: std::time::Duration::from_secs(5),
    };

    let transport = DaemonTransport::new(config, true, &server_opts);
    let fs = test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    match tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("push session failed: {e}"),
        Err(_) => panic!("push session timed out after 15s"),
    }
}

// ---------------------------------------------------------------------------
// Transport smoke tests (one per direction)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_daemon_pull_smoke() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = b"hello from the server!";
    std::fs::write(server_dir.path().join("greeting.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let pulled = std::fs::read(client_dir.path().join("greeting.txt")).unwrap();
    assert_eq!(pulled, content);
}

/// Daemon push is known to deadlock on the current demux pipe architecture.
/// These tests document the expected behavior but are ignored until the
/// BidirectionalIo rewrite lands.
#[tokio::test]
#[ignore = "daemon push deadlocks due to demux pipe architecture"]
async fn test_daemon_push_smoke() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = b"pushed from client";
    std::fs::write(client_dir.path().join("upload.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;
    ferrosync_client_push(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let pushed = std::fs::read(server_dir.path().join("upload.txt")).unwrap();
    assert_eq!(pushed, content);
}

// ---------------------------------------------------------------------------
// Daemon-specific behavior tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_daemon_idempotent_pull() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    std::fs::write(server_dir.path().join("stable.txt"), b"unchanged").unwrap();

    // First pull.
    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let first = std::fs::read(client_dir.path().join("stable.txt")).unwrap();
    assert_eq!(first, b"unchanged");

    // Second pull (should be a no-op).
    let (addr2, shutdown2) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr2, "test", client_dir.path()).await;
    let _ = shutdown2.send(true);

    let second = std::fs::read(client_dir.path().join("stable.txt")).unwrap();
    assert_eq!(second, b"unchanged");
}

#[tokio::test]
async fn test_daemon_empty_module() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Server directory is empty.
    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let entries: Vec<_> = std::fs::read_dir(client_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 0, "empty module should transfer no files");
}

#[tokio::test]
async fn test_daemon_pull_archive_mode() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = b"archive mode pull test";
    std::fs::write(server_dir.path().join("archive.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;

    let opts = TransferOptions::builder()
        .archive()
        .dest(client_dir.path().to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, false);

    let config = DaemonTransportConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        module: "test".to_string(),
        path: ".".to_string(),
        user: None,
        password: None,
        connect_timeout: std::time::Duration::from_secs(5),
    };

    let transport = DaemonTransport::new(config, false, &server_opts);
    let fs = test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    match tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("archive pull failed: {e}"),
        Err(_) => panic!("archive pull timed out after 15s"),
    }

    let _ = shutdown.send(true);

    let pulled = std::fs::read(client_dir.path().join("archive.txt")).unwrap();
    assert_eq!(pulled, content);
}

/// Push with archive mode -- ignored due to daemon push deadlock.
#[tokio::test]
#[ignore = "daemon push deadlocks due to demux pipe architecture"]
async fn test_daemon_push_archive_mode() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = b"archive mode push test";
    std::fs::write(client_dir.path().join("archive.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;

    let opts = TransferOptions::builder()
        .archive()
        .source(client_dir.path().to_path_buf())
        .build();

    let server_opts = build_server_options(&opts, true);

    let config = DaemonTransportConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        module: "test".to_string(),
        path: ".".to_string(),
        user: None,
        password: None,
        connect_timeout: std::time::Duration::from_secs(5),
    };

    let transport = DaemonTransport::new(config, true, &server_opts);
    let fs = test_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    match tokio::time::timeout(std::time::Duration::from_secs(15), session.run()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("archive push failed: {e}"),
        Err(_) => panic!("archive push timed out after 15s"),
    }

    let _ = shutdown.send(true);

    let pushed = std::fs::read(server_dir.path().join("archive.txt")).unwrap();
    assert_eq!(pushed, content);
}

// ---------------------------------------------------------------------------
// Module filter tests
// ---------------------------------------------------------------------------

/// Start a test server with custom module filter config.
async fn start_test_server_with_filters(
    module_path: &Path,
    exclude: Vec<String>,
    include: Vec<String>,
    filter: Vec<String>,
) -> (SocketAddr, watch::Sender<bool>) {
    let mut registry = ModuleRegistry::new();
    registry.register(Module {
        name: "test".to_string(),
        path: module_path.to_path_buf(),
        read_only: true,
        list: true,
        comment: "Test module with filters".to_string(),
        auth: ModuleAuth {
            auth_users: String::new(),
            secrets_file: None,
        },
        access: AccessControl::default(),
        max_connections: 0,
        timeout: 0,
        exclude,
        include,
        filter,
    });

    let config = ListenerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        motd: None,
    };

    let listener = DaemonListener::new(config, Arc::new(registry));
    let shutdown = listener.shutdown_handle();

    let (tcp_listener, addr) = listener.bind().await.expect("failed to bind test server");

    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);
    tokio::spawn(async move {
        let _ = listener_clone.serve(tcp_listener).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    (addr, shutdown)
}

/// Module exclude pattern: *.log files are excluded from the file list.
/// If filters were silently ignored, debug.log would appear in the pull.
#[tokio::test]
async fn test_daemon_module_exclude() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    std::fs::write(server_dir.path().join("data.txt"), b"keep me").unwrap();
    std::fs::write(server_dir.path().join("debug.log"), b"exclude me").unwrap();

    let (addr, shutdown) = start_test_server_with_filters(
        server_dir.path(),
        vec!["*.log".into()],
        Vec::new(),
        Vec::new(),
    )
    .await;

    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(client_dir.path().join("data.txt")).unwrap(),
        b"keep me"
    );
    assert!(
        !client_dir.path().join("debug.log").exists(),
        "debug.log should be excluded by module filter"
    );
}

/// Module include + exclude whitelist: only *.txt files are included.
/// If filters were silently ignored, skip.bin would appear in the pull.
#[tokio::test]
async fn test_daemon_module_include_exclude() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    std::fs::write(server_dir.path().join("keep.txt"), b"included").unwrap();
    std::fs::write(server_dir.path().join("skip.bin"), b"excluded").unwrap();

    let (addr, shutdown) = start_test_server_with_filters(
        server_dir.path(),
        vec!["*".into()],
        vec!["*.txt".into()],
        Vec::new(),
    )
    .await;

    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(client_dir.path().join("keep.txt")).unwrap(),
        b"included"
    );
    assert!(
        !client_dir.path().join("skip.bin").exists(),
        "skip.bin should be excluded by module whitelist filter"
    );
}

/// Module filter rules: "+ *.rs" then "- *" whitelists Rust files only.
/// If filters were silently ignored, data.bin would appear in the pull.
#[tokio::test]
async fn test_daemon_module_filter() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    std::fs::write(server_dir.path().join("main.rs"), b"fn main() {}").unwrap();
    std::fs::write(server_dir.path().join("data.bin"), b"binary data").unwrap();

    let (addr, shutdown) = start_test_server_with_filters(
        server_dir.path(),
        Vec::new(),
        Vec::new(),
        vec!["+ *.rs".into(), "- *".into()],
    )
    .await;

    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(client_dir.path().join("main.rs")).unwrap(),
        b"fn main() {}"
    );
    assert!(
        !client_dir.path().join("data.bin").exists(),
        "data.bin should be excluded by module filter rule"
    );
}
