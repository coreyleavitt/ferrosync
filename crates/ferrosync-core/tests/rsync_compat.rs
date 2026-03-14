//! Integration tests against a real rsync binary.
//!
//! These tests verify wire-level compatibility by running ferrosync's
//! `SyncSession` against `rsync --server` via `LocalTransport`.
//!
//! Gated behind rsync being available on PATH. Tests will be skipped
//! (not failed) if rsync is not found.

use std::path::Path;

use ferrosync_core::engine::session::{build_server_options, SyncDirection, SyncSession};
use ferrosync_core::fs::unix::UnixFileSystem;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::transport::local::LocalTransport;
use ferrosync_core::transport::{Transport, TransportStreams};

/// Check if rsync is available and return its protocol version.
fn rsync_protocol_version() -> Option<u8> {
    let output = std::process::Command::new("rsync")
        .arg("--version")
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "protocol version NN" from the version output.
    for line in stdout.lines() {
        if line.strip_prefix("rsync  version ").is_some() {
            // First line is the version string, keep looking for protocol line.
            continue;
        }
        if line.contains("protocol version") {
            let version_str = line.split_whitespace().last()?;
            return version_str.parse().ok();
        }
    }
    // Fallback: just check it runs
    Some(31)
}

macro_rules! skip_if_no_rsync {
    () => {
        if rsync_protocol_version().is_none() {
            eprintln!("skipping: rsync not found on PATH");
            return;
        }
    };
}

/// Create a temp source directory with known test files.
fn create_test_tree(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("hello.txt"), "Hello, world!\n").unwrap();
    std::fs::write(dir.join("data.bin"), vec![0xAA; 4096]).unwrap();
    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    std::fs::write(dir.join("subdir/nested.txt"), "nested file content\n").unwrap();
    std::fs::write(
        dir.join("subdir/large.dat"),
        vec![0x42; 32 * 1024], // 32 KiB
    )
    .unwrap();
}

/// Create a single file for simple tests.
fn create_single_file(dir: &Path, name: &str, content: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), content).unwrap();
}

/// Assert two directory trees are identical (file names and contents).
fn assert_trees_equal(expected: &Path, actual: &Path) {
    let expected_files = collect_files(expected, expected);
    let actual_files = collect_files(actual, actual);

    assert_eq!(
        expected_files.len(),
        actual_files.len(),
        "file count mismatch: expected {:?}, got {:?}",
        expected_files.keys().collect::<Vec<_>>(),
        actual_files.keys().collect::<Vec<_>>(),
    );

    for (rel_path, expected_content) in &expected_files {
        let actual_content = actual_files
            .get(rel_path)
            .unwrap_or_else(|| panic!("missing file in dest: {rel_path}"));
        assert_eq!(
            expected_content, actual_content,
            "content mismatch for {rel_path}"
        );
    }
}

/// Collect all files in a directory tree as (relative_path, contents).
fn collect_files(
    root: &Path,
    current: &Path,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    if !current.is_dir() {
        return files;
    }
    for entry in std::fs::read_dir(current).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            files.extend(collect_files(root, &path));
        } else if path.is_file() {
            files.insert(rel, std::fs::read(&path).unwrap());
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Pull tests (we are receiver, rsync --server --sender)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "test.txt", b"pull test content\n");

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "pull failed: {:?}", result.unwrap_err());
    let result = result.unwrap();
    assert!(result.stats.files_transferred >= 1,
        "expected >= 1 files, got {}", result.stats.files_transferred);

    let dest_content = std::fs::read(dst.join("test.txt")).unwrap();
    assert_eq!(dest_content, b"pull test content\n");
}

#[tokio::test]
async fn test_pull_directory_recursive() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "pull failed: {:?}", result.unwrap_err());
    let result = result.unwrap();
    assert!(result.stats.files_transferred >= 4, "expected at least 4 files, got {}", result.stats.files_transferred);

    // Verify file contents match.
    assert_eq!(
        std::fs::read(dst.join("hello.txt")).unwrap(),
        b"Hello, world!\n"
    );
    assert_eq!(
        std::fs::read(dst.join("data.bin")).unwrap(),
        vec![0xAA; 4096]
    );
    assert_eq!(
        std::fs::read(dst.join("subdir/nested.txt")).unwrap(),
        b"nested file content\n"
    );
    assert_eq!(
        std::fs::read(dst.join("subdir/large.dat")).unwrap(),
        vec![0x42; 32 * 1024]
    );
}

#[tokio::test]
async fn test_pull_preserves_times() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "timed.txt", b"timestamp test\n");

    // Set a known mtime on the source file.
    let src_file = src.join("timed.txt");
    let mtime = filetime::FileTime::from_unix_time(1_000_000, 0);
    filetime::set_file_mtime(&src_file, mtime).unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "pull failed: {:?}", result.unwrap_err());

    let dst_meta = std::fs::metadata(dst.join("timed.txt")).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(dst_meta.mtime(), 1_000_000, "mtime not preserved");
}

#[tokio::test]
async fn test_pull_preserves_permissions() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "perms.txt", b"permissions test\n");

    // Set specific permissions.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        src.join("perms.txt"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_perms(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "pull failed: {:?}", result.unwrap_err());

    let dst_meta = std::fs::metadata(dst.join("perms.txt")).unwrap();
    assert_eq!(
        dst_meta.permissions().mode() & 0o777,
        0o755,
        "permissions not preserved"
    );
}

#[tokio::test]
async fn test_pull_with_exclude() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);
    // Add an extra file that should be excluded.
    std::fs::write(src.join("secret.log"), "should be excluded").unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .exclude("*.log")
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "pull failed: {:?}", result.unwrap_err());

    // The .log file should not be in the dest.
    assert!(
        !dst.join("secret.log").exists(),
        "excluded file should not be transferred"
    );
    // But other files should be.
    assert!(dst.join("hello.txt").exists(), "hello.txt should exist");
}

// ---------------------------------------------------------------------------
// Push tests (we are sender, rsync --server as receiver)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_push_single_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "push.txt", b"push test content\n");

    let options = TransferOptions::builder()
        .preserve_times(true)
        .source(src.join("push.txt"))
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, true);
    let transport = LocalTransport::new(None, true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Push)
        .run()
        .await;

    assert!(result.is_ok(), "push failed: {:?}", result.unwrap_err());
    let result = result.unwrap();
    assert!(result.stats.files_transferred >= 1);

    let dest_content = std::fs::read(dst.join("push.txt")).unwrap();
    assert_eq!(dest_content, b"push test content\n");
}

#[tokio::test]
async fn test_push_directory_recursive() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, true);
    let transport = LocalTransport::new(None, true, &server_opts, &dst);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Push)
        .run()
        .await;

    assert!(result.is_ok(), "push failed: {:?}", result.unwrap_err());
    let result = result.unwrap();
    assert!(result.stats.files_transferred >= 4);

    assert_eq!(
        std::fs::read(dst.join("hello.txt")).unwrap(),
        b"Hello, world!\n"
    );
    assert_eq!(
        std::fs::read(dst.join("subdir/nested.txt")).unwrap(),
        b"nested file content\n"
    );
}

// ---------------------------------------------------------------------------
// Delta transfer tests (update existing files)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_delta_transfer() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    // Create a large file as source.
    let original = vec![0x55; 64 * 1024];
    create_single_file(&src, "delta.dat", &original);

    // Create a slightly different version in dest (basis file).
    let mut basis = original.clone();
    // Modify a small portion in the middle.
    for b in &mut basis[1024..2048] {
        *b = 0xAA;
    }
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("delta.dat"), &basis).unwrap();
    // Set dest mtime to a clearly older time so rsync sees a difference.
    filetime::set_file_mtime(
        dst.join("delta.dat"),
        filetime::FileTime::from_unix_time(1_000_000, 0),
    )
    .unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "delta pull failed: {:?}", result.unwrap_err());

    // Verify the file was updated to match source.
    let dest_content = std::fs::read(dst.join("delta.dat")).unwrap();
    assert_eq!(dest_content, original);
}

// ---------------------------------------------------------------------------
// Whole-file transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_whole_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "whole.txt", b"whole file transfer\n");

    let options = TransferOptions::builder()
        .recursive(true)
        .whole_file(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "whole-file pull failed: {:?}", result.unwrap_err());

    let dest_content = std::fs::read(dst.join("whole.txt")).unwrap();
    assert_eq!(dest_content, b"whole file transfer\n");
}

// ---------------------------------------------------------------------------
// Checksum mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_checksum_mode() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "checksum.txt", b"checksum mode test\n");

    let options = TransferOptions::builder()
        .recursive(true)
        .checksum_mode(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "checksum pull failed: {:?}", result.unwrap_err());

    let dest_content = std::fs::read(dst.join("checksum.txt")).unwrap();
    assert_eq!(dest_content, b"checksum mode test\n");
}

// ---------------------------------------------------------------------------
// Empty directory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_empty_directory() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "empty dir pull failed: {:?}", result.unwrap_err());
    assert_eq!(result.unwrap().stats.files_transferred, 0);
}

// ---------------------------------------------------------------------------
// Large file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_large_file() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    // 256 KiB file with varied content.
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    create_single_file(&src, "large.bin", &data);

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "large file pull failed: {:?}", result.unwrap_err());

    let dest_content = std::fs::read(dst.join("large.bin")).unwrap();
    assert_eq!(dest_content.len(), data.len());
    assert_eq!(dest_content, data);
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_dry_run() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "dry.txt", b"should not be written\n");

    let options = TransferOptions::builder()
        .recursive(true)
        .dry_run(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "dry run failed: {:?}", result.unwrap_err());
    // File should NOT exist in dest.
    assert!(
        !dst.join("dry.txt").exists(),
        "dry run should not create files"
    );
}

// ---------------------------------------------------------------------------
// Verify rsync binary is speaking the right protocol
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_handshake_against_real_rsync() {
    skip_if_no_rsync!();

    use ferrosync_core::protocol::handshake;

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    create_single_file(&src, "test.txt", b"handshake test\n");
    std::fs::create_dir_all(&dst).unwrap();

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    eprintln!("server_opts: {server_opts}");
    // Spawn rsync directly to capture stderr.
    use tokio::process::Command;
    use std::process::Stdio;
    let mut child = Command::new("rsync")
        .args(["--server", "--sender", &server_opts, ".", "."])
        .current_dir(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut writer = child.stdin.take().unwrap();
    let mut reader = child.stdout.take().unwrap();
    let mut stderr_handle = child.stderr.take().unwrap();

    let protocol = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handshake::client_handshake(&mut reader, &mut writer, false, false),
    )
    .await
    .expect("handshake timed out")
    .expect("handshake failed");

    eprintln!(
        "handshake: version={}, flags={:#x}, inc_flist={}, checksum={:?}, seed={}",
        protocol.version, protocol.compat_flags, protocol.incremental_flist,
        protocol.checksum, protocol.seed
    );

    assert_eq!(protocol.version, 31);
    assert!(protocol.varint_flist_flags);
    assert!(matches!(protocol.checksum, handshake::ChecksumType::Md5));
    assert_ne!(protocol.seed, 0);

    // Send MUX-framed empty filter list and read file list response.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // MUX header: tag=7 (MPLEX_BASE + MSG_DATA=0), length=4
    let mux_hdr: u32 = (7u32 << 24) | 4;
    writer.write_all(&mux_hdr.to_le_bytes()).await.unwrap();
    // Payload: 4-byte zero (empty filter list terminator)
    writer.write_all(&0i32.to_le_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    eprintln!("sent MUX-framed empty filter list");

    // Read ALL available data from rsync (multiple reads).
    let mut all_data = Vec::new();
    loop {
        let mut raw = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read(&mut raw),
        )
        .await;
        match n {
            Ok(Ok(0)) => { eprintln!("EOF"); break; }
            Ok(Ok(n)) => {
                eprintln!("read {n} bytes:");
                for chunk in raw[..n].chunks(32) {
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String = chunk.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
                    eprintln!("  {} | {}", hex.join(" "), ascii);
                }
                all_data.extend_from_slice(&raw[..n]);
            }
            Ok(Err(e)) => { eprintln!("read error: {e}"); break; }
            Err(_) => { eprintln!("timeout (read {} total bytes)", all_data.len()); break; }
        }
    }

    // Parse MUX frames from all_data
    eprintln!("\n--- Parsed MUX frames ---");
    let mut pos = 0;
    while pos + 4 <= all_data.len() {
        let hdr = u32::from_le_bytes(all_data[pos..pos+4].try_into().unwrap());
        let tag = hdr >> 24;
        let len = (hdr & 0x00FF_FFFF) as usize;
        let tag_name = match tag {
            7 => "MSG_DATA",
            8 => "MSG_ERROR_XFER",
            9 => "MSG_ERROR",
            10 => "MSG_WARNING",
            11 => "MSG_INFO",
            12 => "MSG_LOG",
            _ => "UNKNOWN",
        };
        let end = (pos + 4 + len).min(all_data.len());
        let payload = &all_data[pos+4..end];
        if tag >= 7 {
            eprintln!("  tag={tag} ({tag_name}), len={len}, payload_hex={:02x?}", payload);
            if tag != 7 {
                eprintln!("    text: {}", String::from_utf8_lossy(payload));
            }
        } else {
            eprintln!("  INVALID tag={tag} at pos={pos}");
            break;
        }
        pos = end;
    }
}

#[tokio::test]
async fn test_rsync_protocol_version_exchange() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    create_single_file(&src, "version.txt", b"version check\n");

    // Use LocalTransport to connect and just do the handshake.
    let options = TransferOptions::builder()
        .preserve_times(true)
        .source(src.clone())
        .dest(tmp.path().join("dst"))
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);

    let streams: std::result::Result<TransportStreams, _> = Box::new(transport).connect().await;
    assert!(streams.is_ok(), "connect failed: {:?}", streams.unwrap_err());

    let mut streams = streams.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Send our protocol version (31).
    streams.writer.write_all(&31_i32.to_le_bytes()).await.unwrap();
    streams.writer.flush().await.unwrap();

    // Read remote version.
    let mut buf = [0u8; 4];
    streams.reader.read_exact(&mut buf).await.unwrap();
    let remote_version = i32::from_le_bytes(buf);

    assert!(
        (27..=40).contains(&remote_version),
        "unexpected protocol version: {remote_version}"
    );
}

// ---------------------------------------------------------------------------
// Debug test: manual protocol drive with stderr capture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_debug_pull_stderr() {
    skip_if_no_rsync!();

    use ferrosync_core::protocol::handshake;
    use ferrosync_core::protocol::multiplex::MplexWriter;
    use ferrosync_core::protocol::varint;
    use ferrosync_core::delta::sum;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;
    use std::process::Stdio;

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    create_single_file(&src, "test.txt", b"pull test content\n");

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(tmp.path().join("dst"))
        .build();

    let server_opts = build_server_options(&options, false);
    eprintln!("server_opts: {server_opts}");
    // Add -vvvvv for maximum debug output from rsync
    let debug_opts = format!("{server_opts}vvvvv");
    eprintln!("args: --server --sender {debug_opts} . .");

    let mut child = Command::new("rsync")
        .args(["--server", "--sender", &debug_opts, ".", "."])
        .current_dir(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut writer = child.stdin.take().unwrap();
    let mut reader = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    // Handshake
    let protocol = handshake::client_handshake(&mut reader, &mut writer, false, false)
        .await
        .expect("handshake failed");
    eprintln!("protocol: version={}, checksum={:?}, seed={}", protocol.version, protocol.checksum, protocol.seed);

    // Send empty filter list (MUX-framed)
    let mut mplex = MplexWriter::new(&mut writer);
    let filter_data = 0i32.to_le_bytes();
    mplex.write_data(&filter_data).await.unwrap();
    mplex.flush().await.unwrap();
    eprintln!("filter list sent");

    // Read file list (raw MUX frames - just consume all data until we get sender's response)
    // Read all available data from rsync's file list output
    let mut all_stdout = Vec::new();
    loop {
        let mut raw = [0u8; 4096];
        match tokio::time::timeout(std::time::Duration::from_secs(2), reader.read(&mut raw)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => { all_stdout.extend_from_slice(&raw[..n]); }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    eprintln!("received {} bytes of file list data from rsync", all_stdout.len());
    // Hex dump of all file list data
    for chunk in all_stdout.chunks(32) {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
        eprintln!("  {} | {}", hex.join(" "), ascii);
    }

    // Parse MUX frames
    eprintln!("\n--- MUX frames in file list data ---");
    let mut pos = 0;
    while pos + 4 <= all_stdout.len() {
        let hdr = u32::from_le_bytes(all_stdout[pos..pos+4].try_into().unwrap());
        let tag = hdr >> 24;
        let len = (hdr & 0x00FF_FFFF) as usize;
        let end = (pos + 4 + len).min(all_stdout.len());
        let payload = &all_stdout[pos+4..end];
        let hex: Vec<String> = payload.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("  pos={pos} tag={tag} len={len} payload: {}", hex.join(" "));
        if tag == 7 {
            // Parse flist entries from MSG_DATA payload
            eprintln!("    DATA content ({} bytes)", payload.len());
        } else if tag >= 8 {
            eprintln!("    text: {}", String::from_utf8_lossy(payload));
        }
        pos = end;
    }
    eprintln!("---\n");

    // With inc_recurse=1, flist_new sets ndx_start=1. So:
    //   NDX 1 = files[0] = "." (directory)
    //   NDX 2 = files[1] = "test.txt" (regular file)
    let test_ndx = 2i32;
    eprintln!("sending NDX={test_ndx} (inc_recurse ndx_start=1, entry[1]=test.txt)");
    let mut sig_buf = Vec::new();
    let mut ndx_state = varint::NdxState::default();
    varint::write_ndx(&mut sig_buf, test_ndx, &mut ndx_state, protocol.version).await.unwrap();
    varint::write_shortint(&mut sig_buf, 0x8000).await.unwrap();
    let sigs = sum::compute_signatures(b"", protocol.seed, protocol.checksum);
    sum::write_sums(&mut sig_buf, &sigs).await.unwrap();
    let hex: Vec<String> = sig_buf.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("  sending ({} bytes): {}", sig_buf.len(), hex.join(" "));
    mplex.write_data(&sig_buf).await.unwrap();
    mplex.flush().await.unwrap();

    // Wait briefly for rsync to process
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Read stderr
    let mut stderr_buf = String::new();
    match tokio::time::timeout(std::time::Duration::from_secs(1), stderr.read_to_string(&mut stderr_buf)).await {
        Ok(Ok(_)) => eprintln!("rsync stderr: {stderr_buf}"),
        Ok(Err(e)) => eprintln!("stderr read error: {e}"),
        Err(_) => eprintln!("stderr timeout"),
    }

    // Read any remaining stdout
    let mut raw = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(1), reader.read(&mut raw)).await {
        Ok(Ok(n)) => {
            let hex: Vec<String> = raw[..n].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("remaining stdout: {n} bytes: {}", hex.join(" "));
        }
        Ok(Err(e)) => eprintln!("stdout error: {e}"),
        Err(_) => eprintln!("stdout timeout"),
    }

    // Check child status
    match child.try_wait() {
        Ok(Some(status)) => eprintln!("rsync exited: {status}"),
        Ok(None) => eprintln!("rsync still running"),
        Err(e) => eprintln!("wait error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Archive mode (full -a flag set)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_archive_mode() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_test_tree(&src);

    // Set known permissions and mtime.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        src.join("hello.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let mtime = filetime::FileTime::from_unix_time(1_500_000, 0);
    filetime::set_file_mtime(src.join("hello.txt"), mtime).unwrap();

    let options = TransferOptions::builder()
        .archive()
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "archive pull failed: {:?}", result.unwrap_err());

    // Verify content.
    assert_eq!(
        std::fs::read(dst.join("hello.txt")).unwrap(),
        b"Hello, world!\n"
    );

    // Verify mtime preserved.
    use std::os::unix::fs::MetadataExt;
    let dst_meta = std::fs::metadata(dst.join("hello.txt")).unwrap();
    assert_eq!(dst_meta.mtime(), 1_500_000);

    // Verify permissions preserved.
    assert_eq!(dst_meta.permissions().mode() & 0o777, 0o644);
}

// ---------------------------------------------------------------------------
// Multiple files in flat directory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_multiple_files_flat() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    for i in 0..10 {
        let content = format!("file {i} content\n");
        std::fs::write(src.join(format!("file_{i:02}.txt")), content.as_bytes()).unwrap();
    }

    let options = TransferOptions::builder()
        .recursive(true)
        .preserve_times(true)
        .source(src.clone())
        .dest(dst.clone())
        .build();

    let server_opts = build_server_options(&options, false);
    let transport = LocalTransport::new(None, false, &server_opts, &src);
    let fs = Box::new(UnixFileSystem::new());

    let result = SyncSession::new(transport, options, fs, SyncDirection::Pull)
        .run()
        .await;

    assert!(result.is_ok(), "multi-file pull failed: {:?}", result.unwrap_err());
    let result = result.unwrap();
    assert_eq!(result.stats.files_transferred, 10);

    for i in 0..10 {
        let expected = format!("file {i} content\n");
        let actual = std::fs::read_to_string(dst.join(format!("file_{i:02}.txt"))).unwrap();
        assert_eq!(actual, expected, "content mismatch for file_{i:02}.txt");
    }
}

// ---------------------------------------------------------------------------
// Idempotent re-sync (second run should transfer nothing)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pull_idempotent() {
    skip_if_no_rsync!();

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    create_single_file(&src, "idem.txt", b"idempotent test\n");

    // First transfer.
    let build_and_run = || async {
        let options = TransferOptions::builder()
            .recursive(true)
            .preserve_times(true)
            .source(src.clone())
            .dest(dst.clone())
            .build();

        let server_opts = build_server_options(&options, false);
        let transport = LocalTransport::new(None, false, &server_opts, &src);
        let fs = Box::new(UnixFileSystem::new());

        SyncSession::new(transport, options, fs, SyncDirection::Pull)
            .run()
            .await
    };

    let result1 = build_and_run().await;
    assert!(result1.is_ok(), "first pull failed: {:?}", result1.unwrap_err());
    assert!(result1.unwrap().stats.files_transferred >= 1);

    // Check mtimes match between src and dst
    let src_meta = std::fs::metadata(src.join("idem.txt")).unwrap();
    let dst_meta = std::fs::metadata(dst.join("idem.txt")).unwrap();
    use std::os::unix::fs::MetadataExt;
    eprintln!("src mtime: {}.{}", src_meta.mtime(), src_meta.mtime_nsec());
    eprintln!("dst mtime: {}.{}", dst_meta.mtime(), dst_meta.mtime_nsec());

    // Second transfer should be a no-op (file already up to date).
    let result2 = build_and_run().await;
    assert!(result2.is_ok(), "second pull failed: {:?}", result2.unwrap_err());
    // rsync skips files with matching size+mtime, so 0 files transferred.
    assert_eq!(
        result2.unwrap().stats.files_transferred, 0,
        "second sync should transfer 0 files"
    );
}

// ---------------------------------------------------------------------------
// Debug test: manual push protocol drive with stderr capture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_debug_push_protocol() {
    skip_if_no_rsync!();

    use ferrosync_core::protocol::handshake;
    use ferrosync_core::protocol::multiplex::MplexWriter;
    use ferrosync_core::filelist::exchange;
    use ferrosync_core::filelist::entry::{FileEntry, S_IFREG};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;
    use std::process::Stdio;

    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    // Build server options for receiver mode (no --sender)
    let options = TransferOptions::builder()
        .preserve_times(true)
        .source(tmp.path().join("dummy"))
        .dest(dst.clone())
        .build();
    let server_opts = build_server_options(&options, true);
    eprintln!("server_opts: {server_opts}");

    // Add -vv after the '-' in server_opts for verbose debugging
    let verbose_opts = format!("-vv{}", &server_opts[1..]);
    let mut child = Command::new("strace")
        .args(["-e", "trace=read,write", "-e", "read=0", "-e", "write=1",
               "-o", "/tmp/rsync_strace.log",
               "rsync", "--server", &verbose_opts, ".", "."])
        .current_dir(&dst)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut writer = child.stdin.take().unwrap();
    let mut reader = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();

    // Handshake
    let protocol = handshake::client_handshake(&mut reader, &mut writer, true, false)
        .await
        .expect("handshake failed");
    eprintln!("handshake: version={} inc_flist={} varint_flist={} checksum={:?} seed={}",
        protocol.version, protocol.incremental_flist, protocol.varint_flist_flags,
        protocol.checksum, protocol.seed);

    // Build a simple file list with one file
    let entry = FileEntry {
        name: b"test.txt".to_vec(),
        len: 5,
        mtime: 1700000000,
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    // Serialize file list
    let mut flist_buf = Vec::new();
    exchange::send_file_list(&mut flist_buf, &[entry], &protocol, &options)
        .await
        .unwrap();
    eprintln!("file list serialized: {} bytes", flist_buf.len());
    for chunk in flist_buf.chunks(32) {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("  {}", hex.join(" "));
    }

    // Build MUX-framed bytes manually
    let mut mux_buf = Vec::new();
    // Filter list: MUX DATA frame with 4-byte empty filter list
    let filter_data = 0i32.to_le_bytes();
    let filter_hdr: u32 = (7u32 << 24) | filter_data.len() as u32;
    mux_buf.extend_from_slice(&filter_hdr.to_le_bytes());
    mux_buf.extend_from_slice(&filter_data);

    // File list: MUX DATA frame
    let flist_hdr: u32 = (7u32 << 24) | flist_buf.len() as u32;
    mux_buf.extend_from_slice(&flist_hdr.to_le_bytes());
    mux_buf.extend_from_slice(&flist_buf);

    eprintln!("sending MUX-framed data: {} bytes total", mux_buf.len());
    let hex_all: Vec<String> = mux_buf.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("  {}", hex_all.join(" "));

    writer.write_all(&mux_buf).await.unwrap();
    writer.flush().await.unwrap();
    eprintln!("MUX data sent");

    // Wait for rsync to process and send response
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Read any stdout from rsync
    let mut stdout_data = Vec::new();
    loop {
        let mut raw = [0u8; 4096];
        match tokio::time::timeout(std::time::Duration::from_millis(500), reader.read(&mut raw)).await {
            Ok(Ok(0)) => { eprintln!("stdout: EOF"); break; }
            Ok(Ok(n)) => {
                let hex: Vec<String> = raw[..n].iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("stdout: {} bytes: {}", n, hex.join(" "));
                stdout_data.extend_from_slice(&raw[..n]);
            }
            Ok(Err(e)) => { eprintln!("stdout error: {e}"); break; }
            Err(_) => { eprintln!("stdout: timeout ({} total bytes read)", stdout_data.len()); break; }
        }
    }

    // Parse MUX frames from stdout
    let mut pos = 0;
    while pos + 4 <= stdout_data.len() {
        let hdr = u32::from_le_bytes(stdout_data[pos..pos+4].try_into().unwrap());
        let tag = hdr >> 24;
        let len = (hdr & 0x00FF_FFFF) as usize;
        let end = (pos + 4 + len).min(stdout_data.len());
        let payload = &stdout_data[pos+4..end];
        let hex: Vec<String> = payload.iter().map(|b| format!("{b:02x}")).collect();
        let text = String::from_utf8_lossy(payload);
        eprintln!("MUX tag={} len={} hex=[{}] text=[{}]", tag, len, hex.join(" "), text.trim());
        pos = end;
    }

    // Read stderr
    let mut stderr = stderr_handle;
    let mut stderr_buf = String::new();
    match tokio::time::timeout(std::time::Duration::from_secs(1), stderr.read_to_string(&mut stderr_buf)).await {
        Ok(Ok(_)) => eprintln!("rsync stderr:\n{}", stderr_buf.trim()),
        Ok(Err(e)) => eprintln!("stderr error: {e}"),
        Err(_) => eprintln!("stderr: timeout"),
    }

    // Wait for child to finish
    let _ = child.wait().await;

    // Read strace log
    if let Ok(strace_log) = std::fs::read_to_string("/tmp/rsync_strace.log") {
        eprintln!("\n=== STRACE LOG (fd 0 reads) ===");
        for line in strace_log.lines() {
            if line.contains("read(0,") || line.contains("write(1,") {
                eprintln!("{}", line);
            }
        }
    }
}
