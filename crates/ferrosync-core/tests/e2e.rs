//! End-to-end tests: ferrosync client to ferrosync server.
//!
//! These tests spin up a ferrosync daemon server on a random port, then
//! connect a ferrosync client to it and verify full transfer correctness.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::watch;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::options::TransferOptions;

/// Create a platform-appropriate FileSystem instance.
fn new_filesystem() -> Box<dyn ferrosync_core::fs::FileSystem> {
    #[cfg(unix)]
    {
        Box::new(ferrosync_core::fs::unix::UnixFileSystem::new())
    }
    #[cfg(windows)]
    {
        Box::new(ferrosync_core::fs::windows::WindowsFileSystem::new())
    }
}
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

    // Spawn the accept loop in a background task. We need to move listener
    // into the task, but serve takes &self... so we wrap it.
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);
    tokio::spawn(async move {
        let _ = listener_clone.serve(tcp_listener).await;
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    (addr, shutdown)
}

/// Pull files from a test server module to a local destination (inner, returns Result).
async fn ferrosync_client_pull_inner(
    addr: SocketAddr,
    module: &str,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    // am_sender=false means we are pulling (server is the sender).
    let transport = DaemonTransport::new(config, false, &server_opts);
    let fs = new_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);
    session.run().await?;
    Ok(())
}

/// Pull files from a test server module to a local destination.
async fn ferrosync_client_pull(addr: SocketAddr, module: &str, dest: &Path) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        ferrosync_client_pull_inner(addr, module, dest),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("pull session failed: {e}"),
        Err(_) => panic!("pull session timed out after 15s"),
    }
}

/// Push files from a local source to a test server module.
async fn ferrosync_client_push(addr: SocketAddr, module: &str, source: &Path) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        ferrosync_client_push_inner(addr, module, source),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("push session failed: {e}"),
        Err(_) => panic!("push session timed out after 15s"),
    }
}

async fn ferrosync_client_push_inner(
    addr: SocketAddr,
    module: &str,
    source: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    // am_sender=true means we are pushing (we are the sender).
    let transport = DaemonTransport::new(config, true, &server_opts);
    let fs = new_filesystem();
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);
    session.run().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// E2E tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_pull_single_file() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create a file on the server side.
    let content = b"hello from the server!";
    std::fs::write(server_dir.path().join("greeting.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    // Verify the file was pulled.
    let pulled = std::fs::read(client_dir.path().join("greeting.txt")).unwrap();
    assert_eq!(pulled, content);
}

#[tokio::test]
async fn test_e2e_pull_directory_recursive() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create a directory tree on the server.
    std::fs::create_dir_all(server_dir.path().join("subdir")).unwrap();
    std::fs::write(server_dir.path().join("root.txt"), b"root file").unwrap();
    std::fs::write(
        server_dir.path().join("subdir/nested.txt"),
        b"nested file content",
    )
    .unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(client_dir.path().join("root.txt")).unwrap(),
        b"root file"
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("subdir/nested.txt")).unwrap(),
        b"nested file content"
    );
}

#[tokio::test]
async fn test_e2e_push_single_file() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create a file on the client side.
    let content = b"pushed from client";
    std::fs::write(client_dir.path().join("upload.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;
    ferrosync_client_push(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    // Verify the file arrived on the server.
    let pushed = std::fs::read(server_dir.path().join("upload.txt")).unwrap();
    assert_eq!(pushed, content);
}

#[tokio::test]
async fn test_e2e_push_directory_recursive() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create a directory tree on the client.
    std::fs::create_dir_all(client_dir.path().join("a/b")).unwrap();
    std::fs::write(client_dir.path().join("top.txt"), b"top level").unwrap();
    std::fs::write(client_dir.path().join("a/mid.txt"), b"middle level").unwrap();
    std::fs::write(client_dir.path().join("a/b/deep.txt"), b"deep level").unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;
    ferrosync_client_push(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(server_dir.path().join("top.txt")).unwrap(),
        b"top level"
    );
    assert_eq!(
        std::fs::read(server_dir.path().join("a/mid.txt")).unwrap(),
        b"middle level"
    );
    assert_eq!(
        std::fs::read(server_dir.path().join("a/b/deep.txt")).unwrap(),
        b"deep level"
    );
}

#[tokio::test]
async fn test_e2e_pull_with_checksums() {
    // Verify that pull works correctly with different checksum algorithms.
    // ferrosync-to-ferrosync negotiates blake3 by default, so this implicitly
    // tests blake3. We verify correctness by content comparison.
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = vec![0xABu8; 4096];
    std::fs::write(server_dir.path().join("checksum_test.bin"), &content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let pulled = std::fs::read(client_dir.path().join("checksum_test.bin")).unwrap();
    assert_eq!(pulled, content);
}

#[tokio::test]
async fn test_e2e_delta_transfer() {
    // First sync, then modify a file on the server, then sync again.
    // The second sync should transfer only the delta.
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create initial file.
    let mut initial = vec![0u8; 8192];
    for (i, b) in initial.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    std::fs::write(server_dir.path().join("data.bin"), &initial).unwrap();

    // First pull.
    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let pulled = std::fs::read(client_dir.path().join("data.bin")).unwrap();
    assert_eq!(pulled, initial);

    // Modify the file on the server (change a few bytes).
    let mut modified = initial.clone();
    modified[4096] = 0xFF;
    modified[4097] = 0xFE;
    modified[4098] = 0xFD;
    std::fs::write(server_dir.path().join("data.bin"), &modified).unwrap();
    // Set a future mtime so the client's quick-check detects the change.
    let future_time = filetime::FileTime::from_unix_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 100,
        0,
    );
    filetime::set_file_mtime(server_dir.path().join("data.bin"), future_time).unwrap();

    // Second pull (delta transfer).
    let (addr2, shutdown2) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr2, "test", client_dir.path()).await;
    let _ = shutdown2.send(true);

    let pulled2 = std::fs::read(client_dir.path().join("data.bin")).unwrap();
    assert_eq!(pulled2, modified);
}

#[tokio::test]
async fn test_e2e_idempotent_pull() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    std::fs::write(server_dir.path().join("stable.txt"), b"unchanged").unwrap();

    // First pull.
    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    let first = std::fs::read(client_dir.path().join("stable.txt")).unwrap();
    assert_eq!(first, b"unchanged");

    // Second pull (should be a no-op or at least produce identical output).
    let (addr2, shutdown2) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr2, "test", client_dir.path()).await;
    let _ = shutdown2.send(true);

    let second = std::fs::read(client_dir.path().join("stable.txt")).unwrap();
    assert_eq!(second, b"unchanged");
}

#[tokio::test]
async fn test_e2e_empty_module() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Server directory is empty.
    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    // Client directory should exist but have no files (only the "." dir entry).
    let entries: Vec<_> = std::fs::read_dir(client_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 0, "empty module should transfer no files");
}

// ---------------------------------------------------------------------------
// Archive mode tests (-a = -rlptgoD)
//
// These exercise uid/gid name list exchange and preserve_owner/group flags
// that the basic tests above don't cover.
// ---------------------------------------------------------------------------

/// Push with archive mode to exercise uid/gid name list encoding.
#[tokio::test]
async fn test_e2e_push_archive_mode() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let content = b"archive mode push test";
    std::fs::write(client_dir.path().join("archive.txt"), content).unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;

    // Build archive-mode options.
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
    let fs = new_filesystem();
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
// Pipelining stress tests
//
// These tests exercise the concurrent generator/receiver pipeline by
// transferring many files (where the generator can send signatures for
// file N+1 while the receiver is still processing file N's delta).
// ---------------------------------------------------------------------------

/// Pull many small files to exercise generator/receiver pipelining.
#[tokio::test]
async fn test_e2e_pull_many_small_files() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create 50 small files on the server.
    let file_count = 50;
    for i in 0..file_count {
        let content = format!("file {i} content -- small file pipelining test\n");
        std::fs::write(
            server_dir.path().join(format!("file_{i:03}.txt")),
            content.as_bytes(),
        )
        .unwrap();
    }

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    // Verify all files arrived correctly.
    for i in 0..file_count {
        let expected = format!("file {i} content -- small file pipelining test\n");
        let actual = std::fs::read(client_dir.path().join(format!("file_{i:03}.txt"))).unwrap();
        assert_eq!(actual, expected.as_bytes(), "mismatch for file_{i:03}.txt");
    }
}

/// Push many small files to exercise server-side pipelined receiver.
#[tokio::test]
async fn test_e2e_push_many_small_files() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Create 50 small files on the client.
    let file_count = 50;
    for i in 0..file_count {
        let content = format!("pushed file {i}\n");
        std::fs::write(
            client_dir.path().join(format!("push_{i:03}.txt")),
            content.as_bytes(),
        )
        .unwrap();
    }

    let (addr, shutdown) = start_test_server(server_dir.path(), false).await;
    ferrosync_client_push(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    for i in 0..file_count {
        let expected = format!("pushed file {i}\n");
        let actual = std::fs::read(server_dir.path().join(format!("push_{i:03}.txt"))).unwrap();
        assert_eq!(actual, expected.as_bytes(), "mismatch for push_{i:03}.txt");
    }
}

/// Pull a mix of large and small files to stress the pipeline with
/// varied per-file processing times.
#[tokio::test]
async fn test_e2e_pull_mixed_file_sizes() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    // Small files interspersed with larger ones.
    std::fs::write(server_dir.path().join("tiny_1.txt"), b"a").unwrap();
    let medium: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    std::fs::write(server_dir.path().join("medium.bin"), &medium).unwrap();
    std::fs::write(server_dir.path().join("tiny_2.txt"), b"bb").unwrap();
    let large: Vec<u8> = (0..128 * 1024).map(|i| (i % 199) as u8).collect();
    std::fs::write(server_dir.path().join("large.bin"), &large).unwrap();
    std::fs::write(server_dir.path().join("tiny_3.txt"), b"ccc").unwrap();
    std::fs::write(server_dir.path().join("empty.dat"), b"").unwrap();

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    assert_eq!(
        std::fs::read(client_dir.path().join("tiny_1.txt")).unwrap(),
        b"a"
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("medium.bin")).unwrap(),
        medium
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("tiny_2.txt")).unwrap(),
        b"bb"
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("large.bin")).unwrap(),
        large
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("tiny_3.txt")).unwrap(),
        b"ccc"
    );
    assert_eq!(
        std::fs::read(client_dir.path().join("empty.dat")).unwrap(),
        b""
    );
}

/// Pull with delta: many files where the basis already exists at the
/// destination. Exercises pipelining with non-trivial block matching.
#[tokio::test]
async fn test_e2e_pull_many_files_delta() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();

    let file_count = 20;
    for i in 0..file_count {
        // Create basis on client (old version).
        let mut basis = vec![0u8; 4096];
        for (j, b) in basis.iter_mut().enumerate() {
            *b = ((i + j) % 256) as u8;
        }
        std::fs::write(
            client_dir.path().join(format!("delta_{i:02}.bin")),
            &basis,
        )
        .unwrap();

        // Create modified version on server.
        let mut modified = basis.clone();
        modified[2048] = 0xFF;
        modified[2049] = 0xFE;
        std::fs::write(
            server_dir.path().join(format!("delta_{i:02}.bin")),
            &modified,
        )
        .unwrap();
        // Set future mtime so quick-check detects the change.
        let future = filetime::FileTime::from_unix_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 200,
            0,
        );
        filetime::set_file_mtime(
            server_dir.path().join(format!("delta_{i:02}.bin")),
            future,
        )
        .unwrap();
    }

    let (addr, shutdown) = start_test_server(server_dir.path(), true).await;
    ferrosync_client_pull(addr, "test", client_dir.path()).await;
    let _ = shutdown.send(true);

    for i in 0..file_count {
        let mut expected = vec![0u8; 4096];
        for (j, b) in expected.iter_mut().enumerate() {
            *b = ((i + j) % 256) as u8;
        }
        expected[2048] = 0xFF;
        expected[2049] = 0xFE;
        let actual = std::fs::read(client_dir.path().join(format!("delta_{i:02}.bin"))).unwrap();
        assert_eq!(actual, expected, "mismatch for delta_{i:02}.bin");
    }
}

/// Pull with archive mode to exercise uid/gid name list decoding.
#[tokio::test]
async fn test_e2e_pull_archive_mode() {
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
    let fs = new_filesystem();
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
