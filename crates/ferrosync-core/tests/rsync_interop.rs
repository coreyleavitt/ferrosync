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

/// Locate a usable rsync binary.
///
/// Prefers `RSYNC_BIN` env var, then `/tmp/rsync-3.4.1/rsync` (vanilla build
/// for systems with a vendor-patched rsync), then `rsync` from PATH.
fn rsync_binary() -> Option<String> {
    if let Ok(bin) = std::env::var("RSYNC_BIN") {
        if std::process::Command::new(&bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(bin);
        }
    }

    // Prefer vanilla build over potentially vendor-patched system rsync.
    for candidate in &["/tmp/rsync-3.4.1/rsync", "rsync"] {
        if std::process::Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(candidate.to_string());
        }
    }

    None
}

/// Check if rsync is available. Skip tests if not.
fn rsync_available() -> bool {
    rsync_binary().is_some()
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
    rsync_bin: String,
    args: Vec<String>,
    cwd: std::path::PathBuf,
}

impl RsyncServerTransport {
    fn new(am_sender: bool, options: &str, cwd: &Path) -> Self {
        Self::new_with_extra_args(am_sender, options, cwd, &[])
    }

    fn new_with_extra_args(
        am_sender: bool,
        options: &str,
        cwd: &Path,
        extra_args: &[String],
    ) -> Self {
        let mut args = vec!["--server".to_string()];
        if !am_sender {
            args.push("--sender".to_string());
        }
        args.push(options.to_string());
        // Extra long options (e.g., --link-dest=DIR) go before the path args.
        args.extend(extra_args.iter().cloned());
        args.push(".".to_string());
        args.push(".".to_string());

        Self {
            rsync_bin: rsync_binary().unwrap_or_else(|| "rsync".to_string()),
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
            let mut child = Command::new(&self.rsync_bin)
                .args(&self.args)
                .current_dir(&self.cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("failed to spawn rsync: {e}"),
                })?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| TransportError::ConnectionFailed {
                    message: "failed to open rsync stdin".to_string(),
                })?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| TransportError::ConnectionFailed {
                    message: "failed to open rsync stdout".to_string(),
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

            Ok(TransportStreams::new(Box::new(stdout), Box::new(stdin)))
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

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("push failed: {e}"),
        Err(_) => panic!("push timed out after 10s"),
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
    assert_eq!(std::fs::read(dst.join("a/b/deep.txt")).unwrap(), b"deep\n");
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

// ---------------------------------------------------------------------------
// File list codec validation (Phase 4)
//
// These tests verify our flist wire encoding is correctly parsed by real rsync
// by checking that file metadata (name, size, mode, mtime) survives a push.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_flist_preserves_mtime() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("timed.txt"), "check mtime\n").unwrap();

    // Set a specific mtime to verify it's preserved through the wire encoding.
    let known_time = filetime::FileTime::from_unix_time(1700000000, 0);
    filetime::set_file_mtime(src.join("timed.txt"), known_time).unwrap();

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
    session.run().await.unwrap();

    let content = std::fs::read(dst.join("timed.txt")).unwrap();
    assert_eq!(content, b"check mtime\n");

    // Verify rsync set the mtime correctly.
    let meta = std::fs::metadata(dst.join("timed.txt")).unwrap();
    let actual_mtime = meta
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        actual_mtime, 1700000000,
        "mtime should be preserved through flist encoding"
    );
}

#[tokio::test]
async fn test_interop_flist_preserves_permissions() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("script.sh"), "#!/bin/sh\necho hi\n").unwrap();
    // Set executable permission.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            src.join("script.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .preserve_perms(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = RsyncServerTransport::new(true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);
    session.run().await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dst.join("script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "permissions should be preserved through flist encoding"
        );
    }
}

#[tokio::test]
async fn test_interop_flist_multiple_files_sorted() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // Create files with names that test prefix compression in the codec.
    let files = vec![
        ("alpha.txt", "aaa"),
        ("alpha_test.txt", "bbb"), // shares "alpha" prefix
        ("beta.txt", "ccc"),
        ("beta_long_name.txt", "ddd"),
    ];

    for (name, content) in &files {
        std::fs::write(src.join(name), content).unwrap();
    }

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
    session.run().await.unwrap();

    // Verify all files arrived with correct content.
    for (name, content) in &files {
        let actual = std::fs::read(dst.join(name)).unwrap();
        assert_eq!(
            actual,
            content.as_bytes(),
            "file {name} content mismatch after flist push"
        );
    }
}

/// Push with archive mode (-a = -rlptgoD) which enables preserve_uid/gid.
/// This exercises the uid/gid name list exchange after the file list.
#[tokio::test]
async fn test_interop_push_archive_mode() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("archive.txt"), "archive mode push\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = RsyncServerTransport::new(true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("archive push failed: {e}"),
        Err(_) => panic!("archive push timed out after 10s"),
    }

    let content = std::fs::read(dst.join("archive.txt")).unwrap();
    assert_eq!(content, b"archive mode push\n");
}

/// Pull with archive mode exercises the uid/gid name list on the receive side.
#[tokio::test]
async fn test_interop_pull_archive_mode() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("archive.txt"), "archive mode pull\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("archive pull failed: {e}"),
        Err(_) => panic!("archive pull timed out after 10s"),
    }

    let content = std::fs::read(dst.join("archive.txt")).unwrap();
    assert_eq!(content, b"archive mode pull\n");
}

// ---------------------------------------------------------------------------
// SSH-simulated tests (is_remote=true)
//
// These use new_remote() to simulate the SSH protocol path where the filter
// list is ALWAYS sent (matching rsync --server with local_server=0).
//
// IMPORTANT: A local rsync subprocess has local_server=1, which means it
// conditionally reads the filter list. When is_remote=true, we send the
// filter list, but the local subprocess may NOT read it -- causing desync.
// These tests verify our wire format matches what rsync expects over SSH.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_ssh_push_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("hello.txt"), "ssh push test\n").unwrap();

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

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("ssh push failed: {e}"),
        Err(_) => panic!("ssh push timed out after 10s"),
    }

    let content = std::fs::read(dst.join("hello.txt")).unwrap();
    assert_eq!(content, b"ssh push test\n");
}

#[tokio::test]
async fn test_interop_ssh_push_archive_mode() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("archive.txt"), "ssh archive push\n").unwrap();

    let opts = TransferOptions::builder()
        .archive()
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, true);
    let transport = RsyncServerTransport::new(true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Push);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("ssh archive push failed: {e}"),
        Err(_) => panic!("ssh archive push timed out after 10s"),
    }

    let content = std::fs::read(dst.join("archive.txt")).unwrap();
    assert_eq!(content, b"ssh archive push\n");
}

#[tokio::test]
async fn test_interop_ssh_pull_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("hello.txt"), "ssh pull test\n").unwrap();

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

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("ssh pull failed: {e}"),
        Err(_) => panic!("ssh pull timed out after 10s"),
    }

    let content = std::fs::read(dst.join("hello.txt")).unwrap();
    assert_eq!(content, b"ssh pull test\n");
}

// ---------------------------------------------------------------------------
// Link-dest tests (ferrosync pulls from rsync --server --sender)
//
// --link-dest is a receiver-side feature: when a file in the source matches
// (content + mtime) a file in a link-dest directory, the receiver hard-links
// instead of transferring. All tests here are PULL tests.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn inode_of(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().ino()
}

/// Helper to set mtime on a file to a specific unix timestamp.
fn set_mtime(path: &std::path::Path, unix_secs: i64) {
    let ft = filetime::FileTime::from_unix_time(unix_secs, 0);
    filetime::set_file_mtime(path, ft).unwrap();
}

#[tokio::test]
async fn test_interop_pull_link_dest_basic() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let prev = tmp.path().join("prev");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file_a.txt"), "hello\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);

    std::fs::write(prev.join("file_a.txt"), "hello\n").unwrap();
    set_mtime(&prev.join("file_a.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .link_dest(&prev)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull failed: {e}"),
        Err(_) => panic!("pull timed out after 10s"),
    }

    let content = std::fs::read(dst.join("file_a.txt")).unwrap();
    assert_eq!(content, b"hello\n");

    assert_eq!(
        inode_of(&dst.join("file_a.txt")),
        inode_of(&prev.join("file_a.txt")),
        "dst/file_a.txt should be hard-linked to prev/file_a.txt"
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_relative_path() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    let current = base.join("current");
    let new_dir = base.join("new");
    std::fs::create_dir_all(&current).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();

    std::fs::write(current.join("file.txt"), "content\n").unwrap();
    set_mtime(&current.join("file.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .link_dest("../current")
        .source(current.clone())
        .dest(new_dir.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &current);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull failed: {e}"),
        Err(_) => panic!("pull timed out after 10s"),
    }

    let content = std::fs::read(new_dir.join("file.txt")).unwrap();
    assert_eq!(content, b"content\n");

    assert_eq!(
        inode_of(&new_dir.join("file.txt")),
        inode_of(&current.join("file.txt")),
        "new/file.txt should be hard-linked to current/file.txt"
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_multiple_dirs() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let alt1 = tmp.path().join("alt1");
    let alt2 = tmp.path().join("alt2");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&alt1).unwrap();
    std::fs::create_dir_all(&alt2).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file_a.txt"), "aaa\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);
    std::fs::write(src.join("file_b.txt"), "bbb\n").unwrap();
    set_mtime(&src.join("file_b.txt"), 1_700_000_000);

    std::fs::write(alt1.join("file_a.txt"), "aaa\n").unwrap();
    set_mtime(&alt1.join("file_a.txt"), 1_700_000_000);

    std::fs::write(alt2.join("file_b.txt"), "bbb\n").unwrap();
    set_mtime(&alt2.join("file_b.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .link_dest(&alt1)
        .link_dest(&alt2)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull failed: {e}"),
        Err(_) => panic!("pull timed out after 10s"),
    }

    assert_eq!(std::fs::read(dst.join("file_a.txt")).unwrap(), b"aaa\n");
    assert_eq!(std::fs::read(dst.join("file_b.txt")).unwrap(), b"bbb\n");

    assert_eq!(
        inode_of(&dst.join("file_a.txt")),
        inode_of(&alt1.join("file_a.txt")),
        "dst/file_a.txt should be hard-linked from alt1"
    );
    assert_eq!(
        inode_of(&dst.join("file_b.txt")),
        inode_of(&alt2.join("file_b.txt")),
        "dst/file_b.txt should be hard-linked from alt2"
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_mtime_mismatch() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let prev = tmp.path().join("prev");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file.txt"), "same content\n").unwrap();
    set_mtime(&src.join("file.txt"), 1_700_000_000);

    // Same content but DIFFERENT mtime -- should NOT be hard-linked.
    std::fs::write(prev.join("file.txt"), "same content\n").unwrap();
    set_mtime(&prev.join("file.txt"), 1_600_000_000);

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .link_dest(&prev)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull failed: {e}"),
        Err(_) => panic!("pull timed out after 10s"),
    }

    let content = std::fs::read(dst.join("file.txt")).unwrap();
    assert_eq!(content, b"same content\n");

    assert_ne!(
        inode_of(&dst.join("file.txt")),
        inode_of(&prev.join("file.txt")),
        "dst/file.txt should NOT be hard-linked when mtime differs"
    );
}

#[tokio::test]
async fn test_interop_pull_link_dest_changed_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let prev = tmp.path().join("prev");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // file_a: changed between prev and src
    std::fs::write(src.join("file_a.txt"), "version 2\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);
    std::fs::write(prev.join("file_a.txt"), "version 1\n").unwrap();
    set_mtime(&prev.join("file_a.txt"), 1_600_000_000);

    // file_b: unchanged between prev and src
    std::fs::write(src.join("file_b.txt"), "same\n").unwrap();
    set_mtime(&src.join("file_b.txt"), 1_700_000_000);
    std::fs::write(prev.join("file_b.txt"), "same\n").unwrap();
    set_mtime(&prev.join("file_b.txt"), 1_700_000_000);

    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .link_dest(&prev)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&opts, false);
    let transport = RsyncServerTransport::new(false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());
    let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("pull failed: {e}"),
        Err(_) => panic!("pull timed out after 10s"),
    }

    // Unchanged file should be hard-linked.
    assert_eq!(
        inode_of(&dst.join("file_b.txt")),
        inode_of(&prev.join("file_b.txt")),
        "unchanged file_b.txt should be hard-linked"
    );

    // Changed file should be a new copy, not hard-linked.
    assert_ne!(
        inode_of(&dst.join("file_a.txt")),
        inode_of(&prev.join("file_a.txt")),
        "changed file_a.txt should NOT be hard-linked"
    );
    assert_eq!(
        std::fs::read(dst.join("file_a.txt")).unwrap(),
        b"version 2\n"
    );
}

#[tokio::test]
async fn test_interop_link_dest_snapshot_rotation() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let backup_0 = tmp.path().join("backup_0");
    let backup_1 = tmp.path().join("backup_1");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&backup_0).unwrap();

    // Initial source state.
    std::fs::write(src.join("file_a.txt"), "original\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_000_000);
    std::fs::write(src.join("file_b.txt"), "stable\n").unwrap();
    set_mtime(&src.join("file_b.txt"), 1_700_000_000);

    // First sync: pull src/ -> backup_0/ (no link-dest).
    {
        let opts = TransferOptions::builder()
            .recursive(true)
            .preserve_times(true)
            .source(src.clone())
            .dest(backup_0.clone())
            .build();

        let server_opts = build_server_options(&opts, false);
        let transport = RsyncServerTransport::new(false, &server_opts, &src);
        let fs = Box::new(UnixFileSystem::new());
        let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("first sync failed: {e}"),
            Err(_) => panic!("first sync timed out"),
        }
    }

    // Modify source: change file_a, leave file_b stable.
    std::fs::write(src.join("file_a.txt"), "modified\n").unwrap();
    set_mtime(&src.join("file_a.txt"), 1_700_001_000);

    // Second sync: pull src/ -> backup_1/ with --link-dest=backup_0/.
    std::fs::create_dir_all(&backup_1).unwrap();
    {
        let opts = TransferOptions::builder()
            .recursive(true)
            .preserve_times(true)
            .link_dest(&backup_0)
            .source(src.clone())
            .dest(backup_1.clone())
            .build();

        let server_opts = build_server_options(&opts, false);
        let transport = RsyncServerTransport::new(false, &server_opts, &src);
        let fs = Box::new(UnixFileSystem::new());
        let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("second sync failed: {e}"),
            Err(_) => panic!("second sync timed out"),
        }
    }

    // Unchanged file_b should be hard-linked across snapshots.
    assert_eq!(
        inode_of(&backup_1.join("file_b.txt")),
        inode_of(&backup_0.join("file_b.txt")),
        "stable file_b.txt should be hard-linked between snapshots"
    );

    // Changed file_a should have a different inode.
    assert_ne!(
        inode_of(&backup_1.join("file_a.txt")),
        inode_of(&backup_0.join("file_a.txt")),
        "modified file_a.txt should NOT be hard-linked"
    );

    // Both snapshots should be complete.
    assert!(backup_0.join("file_a.txt").exists());
    assert!(backup_0.join("file_b.txt").exists());
    assert!(backup_1.join("file_a.txt").exists());
    assert!(backup_1.join("file_b.txt").exists());

    // Verify content correctness.
    assert_eq!(
        std::fs::read(backup_0.join("file_a.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        std::fs::read(backup_1.join("file_a.txt")).unwrap(),
        b"modified\n"
    );
}

#[tokio::test]
async fn test_interop_link_dest_rerun_idempotent() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let prev = tmp.path().join("prev");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file.txt"), "idempotent\n").unwrap();
    set_mtime(&src.join("file.txt"), 1_700_000_000);

    // First pull: src/ -> dst/ (no link-dest).
    {
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

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("first pull failed: {e}"),
            Err(_) => panic!("first pull timed out"),
        }
    }

    // Create prev/ as a copy of dst/ with matching content and mtimes.
    std::fs::create_dir_all(&prev).unwrap();
    std::fs::copy(dst.join("file.txt"), prev.join("file.txt")).unwrap();
    set_mtime(&prev.join("file.txt"), 1_700_000_000);

    // Re-run pull with link-dest=prev into a fresh dst.
    let dst2 = tmp.path().join("dst2");
    std::fs::create_dir_all(&dst2).unwrap();
    {
        let opts = TransferOptions::builder()
            .recursive(true)
            .preserve_times(true)
            .link_dest(&prev)
            .source(src.clone())
            .dest(dst2.clone())
            .build();

        let server_opts = build_server_options(&opts, false);
        let transport = RsyncServerTransport::new(false, &server_opts, &src);
        let fs = Box::new(UnixFileSystem::new());
        let session = SyncSession::new(transport, opts, fs, SyncDirection::Pull);

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), session.run()).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("re-run pull failed: {e}"),
            Err(_) => panic!("re-run pull timed out"),
        }
    }

    let content = std::fs::read(dst2.join("file.txt")).unwrap();
    assert_eq!(content, b"idempotent\n");
}
