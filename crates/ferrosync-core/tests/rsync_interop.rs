//! Interop tests: ferrosync client against real rsync binary.
//!
//! These tests spawn `rsync --server` as a subprocess and run our
//! client-side protocol against it. This is TEST INFRASTRUCTURE ONLY --
//! production code never spawns rsync.
//!
//! Requires rsync installed and a Unix environment.
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::error::TransportError;
use ferrosync_core::fs::unix::UnixFileSystem;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::{Transport, TransportStreams};

/// Check if rsync is available. Skip tests if not.
fn rsync_available() -> bool {
    std::process::Command::new("rsync")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

macro_rules! skip_if_no_rsync {
    () => {
        if !rsync_available() {
            eprintln!("skipping: rsync not found");
            return;
        }
    };
}

/// Test-only transport that spawns rsync --server as a subprocess.
/// This exists ONLY in test code for interop testing.
struct RsyncServerTransport {
    args: Vec<String>,
    cwd: std::path::PathBuf,
}

impl RsyncServerTransport {
    fn new(am_sender: bool, options: &str, cwd: &Path) -> Self {
        let mut args = vec!["--server".to_string()];
        if !am_sender {
            args.push("--sender".to_string());
        }
        args.push(options.to_string());
        args.push(".".to_string());
        args.push(".".to_string());

        Self {
            args,
            cwd: cwd.to_path_buf(),
        }
    }
}

impl Transport for RsyncServerTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStreams, TransportError>> + Send>,
    > {
        Box::pin(async move {
            let mut child = Command::new("rsync")
                .args(&self.args)
                .current_dir(&self.cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("failed to spawn rsync: {e}"),
                })?;

            let stdin = child.stdin.take().ok_or_else(|| {
                TransportError::ConnectionFailed {
                    message: "failed to open rsync stdin".to_string(),
                }
            })?;

            let stdout = child.stdout.take().ok_or_else(|| {
                TransportError::ConnectionFailed {
                    message: "failed to open rsync stdout".to_string(),
                }
            })?;

            // Monitor child in background for diagnostics.
            tokio::spawn(async move {
                let output = child.wait_with_output().await;
                if let Ok(output) = output {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!(
                            "[rsync-interop] exit={:?} stderr: {}",
                            output.status.code(),
                            stderr.trim()
                        );
                    }
                }
            });

            Ok(TransportStreams::new(
                Box::new(stdout),
                Box::new(stdin),
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Pull tests (ferrosync pulls from rsync --server --sender)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_pull_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("hello.txt"), "hello from rsync\n").unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = session.run().await;
    if let Err(ref e) = result {
        eprintln!("pull failed: {e}");
    }
    result.unwrap();

    let content = std::fs::read(dst.join("hello.txt")).unwrap();
    assert_eq!(content, b"hello from rsync\n");
}

#[tokio::test]
async fn test_interop_pull_directory_recursive() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("root.txt"), "root file\n").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), "nested\n").unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    session.run().await.unwrap();

    assert_eq!(std::fs::read(dst.join("root.txt")).unwrap(), b"root file\n");
    assert_eq!(
        std::fs::read(dst.join("subdir/nested.txt")).unwrap(),
        b"nested\n"
    );
}

// ---------------------------------------------------------------------------
// Push tests (ferrosync pushes to rsync --server receiver)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_push_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("upload.txt"), "pushed to rsync\n").unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = RsyncServerTransport::new(true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        session.run(),
    ).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            // Give monitor task time to capture stderr.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            panic!("push failed: {e}");
        }
        Err(_) => panic!("push timed out after 10s"),
    }

    // List what rsync actually wrote.
    eprintln!("dst contents:");
    if let Ok(entries) = std::fs::read_dir(&dst) {
        for entry in entries.flatten() {
            eprintln!("  {}", entry.path().display());
        }
    } else {
        eprintln!("  (directory doesn't exist or can't be read)");
    }

    let content = std::fs::read(dst.join("upload.txt")).unwrap();
    assert_eq!(content, b"pushed to rsync\n");
}

#[tokio::test]
async fn test_interop_push_directory_recursive() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("a/b")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("top.txt"), "top\n").unwrap();
    std::fs::write(src.join("a/mid.txt"), "mid\n").unwrap();
    std::fs::write(src.join("a/b/deep.txt"), "deep\n").unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = RsyncServerTransport::new(true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = session.run().await;
    if let Err(ref e) = result {
        eprintln!("push failed: {e}");
    }
    result.unwrap();

    assert_eq!(std::fs::read(dst.join("top.txt")).unwrap(), b"top\n");
    assert_eq!(std::fs::read(dst.join("a/mid.txt")).unwrap(), b"mid\n");
    assert_eq!(
        std::fs::read(dst.join("a/b/deep.txt")).unwrap(),
        b"deep\n"
    );
}

#[tokio::test]
async fn test_interop_pull_large_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.join("big.dat"), &data).unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    session.run().await.unwrap();

    let pulled = std::fs::read(dst.join("big.dat")).unwrap();
    assert_eq!(pulled.len(), data.len());
    assert_eq!(pulled, data);
}

#[tokio::test]
async fn test_interop_pull_empty_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("empty.txt"), b"").unwrap();

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    session.run().await.unwrap();

    let content = std::fs::read(dst.join("empty.txt")).unwrap();
    assert!(content.is_empty());
}
