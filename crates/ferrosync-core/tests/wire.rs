//! Wire conformance tests: compare ferrosync's file list encoding against
//! real rsync's output, field by field.
//!
//! These tests create files on a remote rsync server via SSH, connect as a
//! pull client, capture the raw file list bytes rsync sends, decode them
//! through the diagnostic decoder, then re-encode the decoded entries with
//! our encoder and compare. Any divergence is reported at the field level.
//!
//! Requires `FERROSYNC_SSH_TEST=1` and the Docker test container.

#![allow(dead_code)]

mod common;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use ferrosync_core::engine::session::build_server_options;
use ferrosync_core::filelist::codec::diagnostic::{compare_decoded, diagnostic_decode_all};
use ferrosync_core::filelist::codec::{
    decode_entry, encode_end_of_flist, encode_entry, DeltaState, FileListOptions, HardLinkDecoder,
    HardLinkEncoder, ReadEntryResult,
};
use ferrosync_core::filelist::entry::FileEntry;
use ferrosync_core::options::TransferOptions;
use ferrosync_core::protocol::handshake::{self, NegotiatedProtocol};
use ferrosync_core::protocol::multiplex::{start_demux, MplexWriter};
use ferrosync_core::transport::ssh::{KnownHostsPolicy, SshTransport, SshTransportConfig};
use ferrosync_core::transport::Transport;

use crate::common::ssh::{remote_cleanup, remote_tmpdir, ssh_cmd, ssh_host, ssh_test_enabled};

// ---------------------------------------------------------------------------
// SpyReader: wraps an AsyncRead and records all bytes read through it
// ---------------------------------------------------------------------------

struct SpyReader<R> {
    inner: R,
    captured: Vec<u8>,
}

impl<R> SpyReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            captured: Vec::new(),
        }
    }

    fn captured(&self) -> &[u8] {
        &self.captured
    }

    fn into_captured(self) -> Vec<u8> {
        self.captured
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SpyReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                this.captured
                    .extend_from_slice(&buf.filled()[before..after]);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create files on the remote and return the path.
async fn setup_remote_files(files: &[(&str, &str, Option<i64>)]) -> String {
    let remote_dir = remote_tmpdir().await;
    let src_dir = format!("{remote_dir}/src");
    ssh_cmd(&["mkdir", "-p", &src_dir]).await;

    for (name, content, mtime) in files {
        let path = format!("{src_dir}/{name}");

        // Create parent dirs if needed.
        if let Some(dir) = Path::new(name).parent() {
            if !dir.as_os_str().is_empty() {
                ssh_cmd(&["mkdir", "-p", &format!("{src_dir}/{}", dir.display())]).await;
            }
        }

        ssh_cmd(&["sh", "-c", &format!("printf '%s' '{content}' > {path}")]).await;
        if let Some(ts) = mtime {
            ssh_cmd(&["touch", "-d", &format!("@{ts}"), &path]).await;
        }
        // Set a known mode.
        ssh_cmd(&["chmod", "644", &path]).await;
    }

    remote_dir
}

/// Capture raw file list bytes from rsync by doing a pull handshake
/// and intercepting the demuxed data stream.
async fn capture_rsync_flist_bytes(
    remote_path: &str,
    opts: &TransferOptions,
) -> (Vec<u8>, Vec<FileEntry>, NegotiatedProtocol) {
    let server_opts = build_server_options(opts, false);
    let transport = SshTransport::new(
        test_ssh_config(),
        false,
        &server_opts,
        Path::new(remote_path),
    );

    let transport: Box<dyn Transport> = Box::new(transport);
    let mut streams = transport.connect().await.expect("SSH connect failed");

    // Handshake (non-multiplexed).
    let protocol = handshake::client_handshake(
        &mut streams.reader,
        &mut streams.writer,
        false, // am_sender = false for pull
        opts.compress(),
        opts.checksum_choice(),
        opts.compress_choice(),
    )
    .await
    .expect("handshake failed");

    // Take ownership of reader/writer.
    let reader = std::mem::replace(&mut streams.reader, Box::new(tokio::io::empty()));
    let writer = std::mem::replace(&mut streams.writer, Box::new(tokio::io::sink()));
    let _streams_guard = streams;

    // Start MUX demux.
    let (demux_read, _demux_handle) = start_demux(reader);
    let mut mplex_out = MplexWriter::new(writer);

    // Send empty filter list (4 zero bytes = int32 0 = end marker).
    let filter_data = build_empty_filter_list(opts);
    mplex_out
        .write_data(&filter_data)
        .await
        .expect("send filter list failed");
    mplex_out.flush().await.expect("flush failed");

    // Wrap demux reader in SpyReader to capture bytes.
    let mut spy = SpyReader::new(demux_read);

    // Decode entries in WIRE ORDER (no sorting) so we can re-encode
    // in the same order and compare bytes. recv_file_list sorts entries,
    // which would make the re-encoded bytes use a different entry order
    // than rsync's wire bytes.
    let flist_opts = FileListOptions::from_protocol(&protocol, opts);
    let mut entries = Vec::new();
    let mut delta_state = DeltaState::default();
    let mut hlink_decoder = HardLinkDecoder::new();

    while let ReadEntryResult::Entry(entry) = decode_entry(
        &mut spy,
        &mut delta_state,
        &flist_opts,
        &mut hlink_decoder,
        &entries,
        None,
    )
    .await
    .expect("decode_entry failed")
    {
        entries.push(*entry);
    }

    // Also consume the id lists (uid/gid names) that follow the file
    // list in batch mode. The SpyReader captures these bytes too, so we
    // need to know where the file list bytes end. We handle this by
    // using the diagnostic decoder on just the captured bytes (it stops
    // at the end-of-list marker).

    let captured = spy.into_captured();

    (captured, entries, protocol)
}

/// Build a filter list matching the options (empty for basic tests).
fn build_empty_filter_list(opts: &TransferOptions) -> Vec<u8> {
    let mut buf = Vec::new();

    // Send any exclude/include patterns from options.
    for rule in opts.filter() {
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for pattern in opts.include() {
        let rule = format!("+ {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }
    for pattern in opts.exclude() {
        let rule = format!("- {pattern}");
        buf.extend_from_slice(&(rule.len() as i32).to_le_bytes());
        buf.extend_from_slice(rule.as_bytes());
    }

    // Terminator.
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf
}

/// Re-encode entries through our encoder and return the bytes.
async fn encode_entries(entries: &[FileEntry], opts: &FileListOptions) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut state = DeltaState::default();
    let mut hlink_encoder = HardLinkEncoder::new();

    for (i, entry) in entries.iter().enumerate() {
        encode_entry(
            &mut buf,
            entry,
            &mut state,
            opts,
            &mut hlink_encoder,
            None,
            i as i32,
            None,
        )
        .await
        .unwrap();
    }
    encode_end_of_flist(&mut buf, 0, opts).await.unwrap();
    buf
}

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

/// Compare rsync's file list bytes against our encoder's output.
///
/// This is the core of the wire conformance harness:
/// 1. Diagnostic-decode rsync's bytes
/// 2. Diagnostic-decode our encoder's bytes
/// 3. Compare field-by-field
async fn assert_wire_conformance(rsync_bytes: &[u8], our_bytes: &[u8], opts: &FileListOptions) {
    let rsync_decoded = diagnostic_decode_all(rsync_bytes, opts)
        .await
        .expect("failed to diagnostic-decode rsync bytes");
    let our_decoded = diagnostic_decode_all(our_bytes, opts)
        .await
        .expect("failed to diagnostic-decode our bytes");

    if let Some(report) = compare_decoded("rsync", &rsync_decoded, "ferrosync", &our_decoded) {
        panic!(
            "Wire conformance failure!\n\n{report}\n\
             rsync bytes ({} bytes): {:02x?}\n\
             our bytes ({} bytes): {:02x?}",
            rsync_bytes.len(),
            rsync_bytes,
            our_bytes.len(),
            our_bytes,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wire_conformance_archive_basic() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    // Setup: single file on remote.
    let remote_dir = setup_remote_files(&[("hello.txt", "hello world", Some(1700000000))]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    assert!(!entries.is_empty(), "no entries received from rsync");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_archive_multiple_files() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(&[
        ("alpha.txt", "aaa", Some(1700000000)),
        ("beta.txt", "bbb", Some(1700000001)),
        ("gamma.txt", "ccc", Some(1700000002)),
    ])
    .await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    assert!(
        entries.len() >= 3,
        "expected at least 3 entries, got {}",
        entries.len()
    );

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_archive_with_subdirs() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(&[
        ("a.txt", "aaa", Some(1700000000)),
        ("subdir/b.txt", "bbb", Some(1700000001)),
    ])
    .await;
    // Create the subdir explicitly with known permissions.
    ssh_cmd(&["chmod", "755", &format!("{remote_dir}/src/subdir")]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_checksum_mode() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(&[("data.bin", "binary content", Some(1700000000))]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .checksum_mode(true)
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_no_owner_group() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(&[("simple.txt", "data", Some(1700000000))]).await;
    let remote_src = format!("{remote_dir}/src/");

    // No -o/-g: just -r -l -t -p (recursive, links, times, perms).
    let opts = TransferOptions::builder()
        .recursive(true)
        .preserve_links(true)
        .preserve_times(true)
        .preserve_perms(true)
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_numeric_ids() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(&[("num.txt", "data", Some(1700000000))]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .numeric_ids(true)
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_shared_prefix_names() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    // Files with shared prefixes to exercise prefix compression.
    let remote_dir = setup_remote_files(&[
        ("src/main.rs", "fn main() {}", Some(1700000000)),
        ("src/lib.rs", "pub mod lib;", Some(1700000001)),
        ("src/main_test.rs", "test", Some(1700000002)),
    ])
    .await;
    ssh_cmd(&["chmod", "755", &format!("{remote_dir}/src/src")]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

// ---------------------------------------------------------------------------
// Additional flag conformance tests
// ---------------------------------------------------------------------------

/// Helper to run a conformance test with given files and options.
async fn run_conformance(files: &[(&str, &str, Option<i64>)], opts: TransferOptions, label: &str) {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = setup_remote_files(files).await;
    let remote_src = format!("{remote_dir}/src/");

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .unwrap_or_else(|_| panic!("{label}: capture timed out"));

    assert!(
        !entries.is_empty(),
        "{label}: no entries received from rsync"
    );

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_archive_symlink() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = remote_tmpdir().await;
    let src_dir = format!("{remote_dir}/src");
    ssh_cmd(&["mkdir", "-p", &src_dir]).await;
    ssh_cmd(&["sh", "-c", &format!("echo target > {src_dir}/real.txt")]).await;
    ssh_cmd(&["ln", "-s", "real.txt", &format!("{src_dir}/link.txt")]).await;
    ssh_cmd(&["touch", "-d", "@1700000000", &format!("{src_dir}/real.txt")]).await;
    ssh_cmd(&["chmod", "644", &format!("{src_dir}/real.txt")]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    assert!(
        entries.len() >= 2,
        "expected >= 2 entries, got {}",
        entries.len()
    );

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
#[ignore = "non-recursive pull sends no flist in current protocol path"]
async fn test_wire_conformance_non_recursive() {
    run_conformance(
        &[("file.txt", "data", Some(1700000000))],
        TransferOptions::builder()
            .preserve_times(true)
            .dest(PathBuf::from("/tmp/unused"))
            .build(),
        "non_recursive",
    )
    .await;
}

#[tokio::test]
async fn test_wire_conformance_empty_files() {
    run_conformance(
        &[
            ("empty1.txt", "", Some(1700000000)),
            ("empty2.txt", "", Some(1700000001)),
        ],
        TransferOptions::builder()
            .archive()
            .dest(PathBuf::from("/tmp/unused"))
            .build(),
        "empty_files",
    )
    .await;
}

#[tokio::test]
async fn test_wire_conformance_same_mtime_mode() {
    run_conformance(
        &[
            ("a.txt", "aaa", Some(1700000000)),
            ("b.txt", "bbb", Some(1700000000)),
            ("c.txt", "ccc", Some(1700000000)),
        ],
        TransferOptions::builder()
            .archive()
            .dest(PathBuf::from("/tmp/unused"))
            .build(),
        "same_mtime_mode",
    )
    .await;
}

#[tokio::test]
async fn test_wire_conformance_large_filename() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = remote_tmpdir().await;
    let src_dir = format!("{remote_dir}/src");
    ssh_cmd(&["mkdir", "-p", &src_dir]).await;

    // Create a file with a name > 255 chars to exercise LONG_NAME flag.
    let long_name = "a".repeat(300);
    ssh_cmd(&["sh", "-c", &format!("echo data > {src_dir}/{long_name}")]).await;
    ssh_cmd(&[
        "touch",
        "-d",
        "@1700000000",
        &format!("{src_dir}/{long_name}"),
    ])
    .await;
    ssh_cmd(&["chmod", "644", &format!("{src_dir}/{long_name}")]).await;
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
async fn test_wire_conformance_deep_directory_tree() {
    run_conformance(
        &[
            ("a/b/c/d.txt", "deep", Some(1700000000)),
            ("a/b/e.txt", "mid", Some(1700000001)),
            ("a/f.txt", "shallow", Some(1700000002)),
        ],
        TransferOptions::builder()
            .archive()
            .dest(PathBuf::from("/tmp/unused"))
            .build(),
        "deep_directory_tree",
    )
    .await;
}

#[tokio::test]
async fn test_wire_conformance_many_files() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = remote_tmpdir().await;
    let src_dir = format!("{remote_dir}/src");
    ssh_cmd(&["mkdir", "-p", &src_dir]).await;

    // Create 50 files to exercise delta encoding across many entries.
    for i in 0..50 {
        ssh_cmd(&[
            "sh",
            "-c",
            &format!("echo file{i} > {src_dir}/file_{i:03}.txt"),
        ])
        .await;
        ssh_cmd(&[
            "touch",
            "-d",
            &format!("@{}", 1700000000 + i),
            &format!("{src_dir}/file_{i:03}.txt"),
        ])
        .await;
        ssh_cmd(&["chmod", "644", &format!("{src_dir}/file_{i:03}.txt")]).await;
    }
    let remote_src = format!("{remote_dir}/src/");

    let opts = TransferOptions::builder()
        .archive()
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    assert!(
        entries.len() >= 50,
        "expected >= 50 entries, got {}",
        entries.len()
    );

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}

#[tokio::test]
#[ignore = "wire capture needs incremental flist support for -aH"]
async fn test_wire_conformance_hardlinks() {
    if !ssh_test_enabled() {
        eprintln!("skipping: FERROSYNC_SSH_TEST not set");
        return;
    }
    common::ssh::init_tracing();

    let remote_dir = remote_tmpdir().await;
    let src_dir = format!("{remote_dir}/src");
    ssh_cmd(&["mkdir", "-p", &src_dir]).await;

    // Create hardlinked files.
    ssh_cmd(&[
        "sh",
        "-c",
        &format!(
            "echo hardlink_data > {src_dir}/original.txt && \
             ln {src_dir}/original.txt {src_dir}/linked.txt && \
             touch -d @1700000000 {src_dir}/original.txt {src_dir}/linked.txt && \
             chmod 644 {src_dir}/original.txt"
        ),
    ])
    .await;
    let remote_src = format!("{remote_dir}/src/");

    // Use non-recursive mode to get batch flist (avoids incremental
    // protocol which the capture function doesn't handle).
    let opts = TransferOptions::builder()
        .preserve_links(true)
        .preserve_perms(true)
        .preserve_times(true)
        .preserve_owner(true)
        .preserve_group(true)
        .preserve_hard_links(true)
        .dest(PathBuf::from("/tmp/unused"))
        .build();

    let (rsync_bytes, entries, protocol) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_rsync_flist_bytes(&remote_src, &opts),
    )
    .await
    .expect("capture timed out");

    assert!(
        entries.len() >= 2,
        "expected >= 2 entries, got {}",
        entries.len()
    );

    let flist_opts = FileListOptions::from_protocol(&protocol, &opts);
    let our_bytes = encode_entries(&entries, &flist_opts).await;

    assert_wire_conformance(&rsync_bytes, &our_bytes, &flist_opts).await;

    remote_cleanup(&remote_dir).await;
}
