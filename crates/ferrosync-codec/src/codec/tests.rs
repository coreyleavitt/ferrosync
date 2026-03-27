//! Unit tests for the codec module.

use super::*;
use crate::entry::{FileEntry, S_IFDIR, S_IFREG, WIRE_S_IFLNK};
use crate::xmit::XMIT_TOP_DIR;
use ferrosync_protocol::wire_format::WireFormat;
use ferrosync_types::types::{FileSize, UnixTimestamp};
use std::io::Cursor;

fn default_opts() -> FileListOptions {
    FileListOptions {
        wire: WireFormat::new(
            31,
            ferrosync_protocol::handshake::compat_flags::VARINT_FLIST_FLAGS
                | ferrosync_protocol::handshake::compat_flags::INC_RECURSE,
        ),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_roundtrip_simple_file() {
    let opts = default_opts();
    let entry = FileEntry {
        name: b"hello.txt".to_vec(),
        len: FileSize(1234),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    let result = decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap();

    match result {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.name, b"hello.txt");
            assert_eq!(decoded.len, FileSize(1234));
            assert_eq!(decoded.mtime, UnixTimestamp(1700000000));
            assert_eq!(decoded.mode, S_IFREG | 0o644);
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry, got end of list"),
    }

    // Read end of list.
    let result = decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap();
    match result {
        ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 0),
        ReadEntryResult::Entry(_) => panic!("expected end of list"),
    }
}

#[tokio::test]
async fn test_roundtrip_multiple_entries_prefix_compression() {
    let opts = default_opts();
    let entries = vec![
        FileEntry {
            name: b"src/main.rs".to_vec(),
            len: FileSize(100),
            mtime: UnixTimestamp(1700000000),
            mode: S_IFREG | 0o644,
            ..Default::default()
        },
        FileEntry {
            name: b"src/lib.rs".to_vec(),
            len: FileSize(200),
            mtime: UnixTimestamp(1700000001),
            mode: S_IFREG | 0o644,
            ..Default::default()
        },
        FileEntry {
            name: b"src/main_test.rs".to_vec(),
            len: FileSize(300),
            mtime: UnixTimestamp(1700000002),
            mode: S_IFREG | 0o644,
            ..Default::default()
        },
    ];

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    for entry in &entries {
        encode_entry(
            &mut buf,
            entry,
            &mut enc_state,
            &opts,
            &mut HardLinkEncoder::new(),
            None,
            0,
            None,
            &mut crate::acl::AclEncoder::new(),
            &mut crate::xattr::XattrEncoder::new(),
        )
        .await
        .unwrap();
    }
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    for expected in &entries {
        match decode_entry(
            &mut cursor,
            &mut dec_state,
            &opts,
            &mut HardLinkDecoder::new(),
            &[],
            None,
            &mut crate::acl::AclDecoder::new(),
            &mut crate::xattr::XattrDecoder::new(),
        )
        .await
        .unwrap()
        {
            ReadEntryResult::Entry(decoded) => {
                assert_eq!(decoded.name, expected.name);
                assert_eq!(decoded.len, expected.len);
                assert_eq!(decoded.mtime, expected.mtime);
                assert_eq!(decoded.mode, expected.mode);
            }
            ReadEntryResult::EndOfList { .. } => panic!("unexpected end of list"),
        }
    }
}

#[tokio::test]
async fn test_roundtrip_directory() {
    let opts = default_opts();
    let entry = FileEntry {
        name: b"mydir".to_vec(),
        len: FileSize(0),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFDIR | 0o755,
        flags: XMIT_TOP_DIR,
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.name, b"mydir");
            assert_eq!(decoded.mode, S_IFDIR | 0o755);
            assert!(decoded.is_dir());
            assert_eq!(decoded.flags & XMIT_TOP_DIR, XMIT_TOP_DIR);
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_roundtrip_with_uid_gid() {
    let opts = FileListOptions {
        preserve_uid: true,
        preserve_gid: true,
        ..default_opts()
    };

    let entry = FileEntry {
        name: b"owned.txt".to_vec(),
        len: FileSize(50),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        uid: 1000,
        gid: 100,
        user_name: b"alice".to_vec(),
        group_name: b"users".to_vec(),
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.uid, 1000);
            assert_eq!(decoded.gid, 100);
            assert_eq!(decoded.user_name, b"alice");
            assert_eq!(decoded.group_name, b"users");
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_roundtrip_symlink() {
    let opts = FileListOptions {
        preserve_links: true,
        ..default_opts()
    };

    let entry = FileEntry {
        name: b"link.txt".to_vec(),
        len: FileSize(0),
        mtime: UnixTimestamp(1700000000),
        mode: WIRE_S_IFLNK | 0o777,
        link_target: b"/tmp/target".to_vec(),
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert!(decoded.is_symlink());
            assert_eq!(decoded.link_target, b"/tmp/target");
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_roundtrip_with_checksum() {
    let opts = FileListOptions {
        always_checksum: true,
        checksum_len: 16,
        ..default_opts()
    };

    let checksum = vec![0xAA; 16];
    let entry = FileEntry {
        name: b"data.bin".to_vec(),
        len: FileSize(4096),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        checksum: checksum.clone(),
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.checksum, checksum);
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_roundtrip_same_mode_time() {
    let opts = default_opts();

    let entry1 = FileEntry {
        name: b"a.txt".to_vec(),
        len: FileSize(100),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };
    let entry2 = FileEntry {
        name: b"b.txt".to_vec(),
        len: FileSize(200),
        mtime: UnixTimestamp(1700000000), // Same mtime
        mode: S_IFREG | 0o644,            // Same mode
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry1,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    let size_first = buf.len();
    encode_entry(
        &mut buf,
        &entry2,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        1,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    let size_second = buf.len() - size_first;
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    // Second entry should be smaller due to delta encoding.
    assert!(
        size_second < size_first,
        "second entry ({size_second}) should be smaller than first ({size_first})"
    );

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(d) => assert_eq!(d.name, b"a.txt"),
        _ => panic!("expected entry"),
    }
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(d) => {
            assert_eq!(d.name, b"b.txt");
            assert_eq!(d.mtime, UnixTimestamp(1700000000));
            assert_eq!(d.mode, S_IFREG | 0o644);
        }
        _ => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_roundtrip_mtime_nsec() {
    let opts = default_opts();
    let entry = FileEntry {
        name: b"precise.txt".to_vec(),
        len: FileSize(42),
        mtime: UnixTimestamp(1700000000),
        mtime_nsec: 123456789,
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.mtime_nsec, 123456789);
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

#[tokio::test]
async fn test_end_of_list_with_error() {
    let opts = default_opts();

    let mut buf = Vec::new();
    encode_end_of_flist(&mut buf, 5, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 5),
        ReadEntryResult::Entry(_) => panic!("expected end of list"),
    }
}

#[tokio::test]
async fn test_end_of_list_legacy() {
    let opts = FileListOptions {
        wire: WireFormat::new(28, 0),
        ..Default::default()
    };

    let mut buf = Vec::new();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();
    assert_eq!(buf, &[0x00]); // Single zero byte.

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::EndOfList { io_error } => assert_eq!(io_error, 0),
        ReadEntryResult::Entry(_) => panic!("expected end of list"),
    }
}

#[tokio::test]
async fn test_common_prefix_len() {
    use super::flags::common_prefix_len;
    assert_eq!(common_prefix_len(b"", b""), 0);
    assert_eq!(common_prefix_len(b"abc", b"abd"), 2);
    assert_eq!(common_prefix_len(b"abc", b"abc"), 3);
    assert_eq!(common_prefix_len(b"src/main.rs", b"src/lib.rs"), 4);
}

#[tokio::test]
async fn test_roundtrip_proto27() {
    let opts = FileListOptions {
        wire: WireFormat::new(27, 0),
        ..Default::default()
    };

    let entry = FileEntry {
        name: b"old.txt".to_vec(),
        len: FileSize(500),
        mtime: UnixTimestamp(1600000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    let mut cursor = Cursor::new(&buf);
    let mut dec_state = DeltaState::default();
    match decode_entry(
        &mut cursor,
        &mut dec_state,
        &opts,
        &mut HardLinkDecoder::new(),
        &[],
        None,
        &mut crate::acl::AclDecoder::new(),
        &mut crate::xattr::XattrDecoder::new(),
    )
    .await
    .unwrap()
    {
        ReadEntryResult::Entry(decoded) => {
            assert_eq!(decoded.name, b"old.txt");
            assert_eq!(decoded.len, FileSize(500));
            assert_eq!(decoded.mtime, UnixTimestamp(1600000000));
        }
        ReadEntryResult::EndOfList { .. } => panic!("expected entry"),
    }
}

// ---------------------------------------------------------------------------
// Diagnostic decoder tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostic_roundtrip() {
    let opts = default_opts();
    let entry = FileEntry {
        name: b"test.txt".to_vec(),
        len: FileSize(100),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    // Encode.
    let mut buf = Vec::new();
    let mut enc_state = DeltaState::default();
    encode_entry(
        &mut buf,
        &entry,
        &mut enc_state,
        &opts,
        &mut HardLinkEncoder::new(),
        None,
        0,
        None,
        &mut crate::acl::AclEncoder::new(),
        &mut crate::xattr::XattrEncoder::new(),
    )
    .await
    .unwrap();
    encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

    // Diagnostic decode.
    let decoded = diagnostic::diagnostic_decode_all(&buf, &opts)
        .await
        .unwrap();
    assert_eq!(decoded.len(), 1);

    let entry_fields = &decoded[0].fields;
    // Should have at least: xmit_flags, filename, file_length, mtime, mode.
    assert!(entry_fields.len() >= 4, "got {} fields", entry_fields.len());
    assert_eq!(entry_fields[0].name, "xmit_flags");
    assert_eq!(entry_fields[1].name, "filename");
    assert_eq!(entry_fields[1].decoded_value, "test.txt");
}

// ---------------------------------------------------------------------------
// XmitFlags unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_xmit_flags_operations() {
    let mut f = XmitFlags::empty();
    assert!(f.is_empty());

    f |= XmitFlags::SAME_TIME;
    assert!(f.same_time());
    assert!(!f.same_mode());

    f |= XmitFlags::SAME_MODE;
    assert!(f.same_time());
    assert!(f.same_mode());

    let combined = XmitFlags::SAME_UID | XmitFlags::SAME_GID;
    assert!(combined.same_uid());
    assert!(combined.same_gid());
    assert!(!combined.same_time());
}

#[test]
fn test_compute_xmit_flags_basic() {
    let opts = default_opts();

    let entry = FileEntry {
        name: b"test.txt".to_vec(),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };

    // Fresh state -- nothing should match.
    let state = DeltaState::default();
    let flags = compute_xmit_flags(
        &entry,
        &entry.name,
        &state,
        &opts,
        &HardLinkAction::NotHardLinked,
    );
    assert!(!flags.same_time());
    assert!(!flags.same_mode());
    assert!(!flags.same_name());

    // After encoding one entry, the next with same mtime/mode should set flags.
    let state = DeltaState {
        prev_mtime: 1700000000,
        prev_mode: S_IFREG | 0o644,
        prev_name: b"test.txt".to_vec(),
        ..Default::default()
    };

    let entry2 = FileEntry {
        name: b"test2.txt".to_vec(),
        mtime: UnixTimestamp(1700000000),
        mode: S_IFREG | 0o644,
        ..Default::default()
    };
    let flags = compute_xmit_flags(
        &entry2,
        &entry2.name,
        &state,
        &opts,
        &HardLinkAction::NotHardLinked,
    );
    assert!(flags.same_time());
    assert!(flags.same_mode());
    assert!(flags.same_name()); // "test" prefix shared
}

// ---------------------------------------------------------------------------
// Property-based tests: codec encode/decode roundtrip for arbitrary entries
// ---------------------------------------------------------------------------

mod proptests {
    use super::*;
    use crate::entry::S_IFREG;
    use proptest::prelude::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Generate a valid FileEntry for roundtrip testing.
    fn arb_file_entry() -> impl Strategy<Value = FileEntry> {
        (
            // name: 1-64 bytes of alphanumeric + / + . + _
            proptest::collection::vec(
                proptest::sample::select(b"abcdefghijklmnopqrstuvwxyz0123456789/._".to_vec()),
                1..64,
            ),
            // len: non-negative file size
            0i64..=1_000_000_000,
            // mtime: reasonable range
            1_000_000_000i64..=2_000_000_000,
            // mtime_nsec
            0u32..=999_999_999,
            // mode: regular file with various permissions
            proptest::sample::select(vec![
                S_IFREG | 0o644,
                S_IFREG | 0o755,
                S_IFREG | 0o600,
                S_IFREG | 0o444,
            ]),
        )
            .prop_map(|(name, len, mtime, mtime_nsec, mode)| FileEntry {
                name,
                len: FileSize(len),
                mtime: UnixTimestamp(mtime),
                mtime_nsec,
                mode,
                ..Default::default()
            })
    }

    proptest! {
        #[test]
        fn codec_roundtrip_single_entry(entry in arb_file_entry()) {
            rt().block_on(async {
                let opts = FileListOptions::default();

                let mut buf = Vec::new();
                let mut enc_state = DeltaState::default();
                encode_entry(
                    &mut buf,
                    &entry,
                    &mut enc_state,
                    &opts,
                    &mut HardLinkEncoder::new(),
                    None,
                    0,
                    None,
                    &mut crate::acl::AclEncoder::new(),
                    &mut crate::xattr::XattrEncoder::new(),
                )
                .await
                .unwrap();
                encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

                let mut cursor = std::io::Cursor::new(&buf);
                let mut dec_state = DeltaState::default();
                match decode_entry(
                    &mut cursor,
                    &mut dec_state,
                    &opts,
                    &mut HardLinkDecoder::new(),
                    &[],
                    None,
                    &mut crate::acl::AclDecoder::new(),
                    &mut crate::xattr::XattrDecoder::new(),
                )
                .await
                .unwrap()
                {
                    ReadEntryResult::Entry(decoded) => {
                        prop_assert_eq!(&decoded.name, &entry.name);
                        prop_assert_eq!(decoded.len, entry.len);
                        prop_assert_eq!(decoded.mtime, entry.mtime);
                        prop_assert_eq!(decoded.mtime_nsec, entry.mtime_nsec);
                        prop_assert_eq!(decoded.mode, entry.mode);
                    }
                    ReadEntryResult::EndOfList { .. } => {
                        return Err(proptest::test_runner::TestCaseError::Fail(
                            "expected entry, got end of list".into(),
                        ));
                    }
                }
                Ok(())
            })?;
        }

        #[test]
        fn codec_roundtrip_multiple_entries(
            entries in proptest::collection::vec(arb_file_entry(), 2..10)
        ) {
            rt().block_on(async {
                let opts = FileListOptions::default();

                let mut buf = Vec::new();
                let mut enc_state = DeltaState::default();
                for (i, entry) in entries.iter().enumerate() {
                    encode_entry(
                        &mut buf,
                        entry,
                        &mut enc_state,
                        &opts,
                        &mut HardLinkEncoder::new(),
                        None,
                        i as i32,
                        None,
                        &mut crate::acl::AclEncoder::new(),
                        &mut crate::xattr::XattrEncoder::new(),
                    )
                    .await
                    .unwrap();
                }
                encode_end_of_flist(&mut buf, 0, &opts).await.unwrap();

                let mut cursor = std::io::Cursor::new(&buf);
                let mut dec_state = DeltaState::default();
                for expected in &entries {
                    match decode_entry(
                        &mut cursor,
                        &mut dec_state,
                        &opts,
                        &mut HardLinkDecoder::new(),
                        &[],
                        None,
                        &mut crate::acl::AclDecoder::new(),
                        &mut crate::xattr::XattrDecoder::new(),
                    )
                    .await
                    .unwrap()
                    {
                        ReadEntryResult::Entry(decoded) => {
                            prop_assert_eq!(&decoded.name, &expected.name);
                            prop_assert_eq!(decoded.len, expected.len);
                            prop_assert_eq!(decoded.mtime, expected.mtime);
                            prop_assert_eq!(decoded.mode, expected.mode);
                        }
                        ReadEntryResult::EndOfList { .. } => {
                            return Err(proptest::test_runner::TestCaseError::Fail(
                                "unexpected end of list".into(),
                            ));
                        }
                    }
                }
                Ok(())
            })?;
        }
    }
}
