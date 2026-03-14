//! Wire-level file list exchange.
//!
//! Provides high-level functions for sending and receiving complete file lists
//! over the rsync wire protocol. Handles both batch mode (protocol < 30) and
//! incremental mode (protocol >= 30).
//!
//! In batch mode, the entire file list is sent/received as a single block of
//! entries followed by an end-of-list marker.
//!
//! In incremental mode, the file list is sent/received as a series of sub-lists
//! (one per directory), allowing the transfer engine to start processing files
//! before the full list is built.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use tokio::io::AsyncReadExt;

use crate::error::ProtocolError;
use crate::options::TransferOptions;
use crate::protocol::handshake::NegotiatedProtocol;
use crate::protocol::varint;

use super::codec::{
    recv_file_entry, send_file_entry, write_end_of_flist, DeltaState, FileListOptions,
    ReadEntryResult,
};
use super::entry::FileEntry;
use super::incremental::{IncrementalReceiver, IncrementalSender, NDX_FLIST_EOF, NDX_FLIST_OFFSET};


type Result<T> = std::result::Result<T, ProtocolError>;

/// Send a complete file list over the wire.
///
/// For protocol < 30: sends all entries as a single batch with end-of-list marker.
/// For protocol >= 30 with incremental flist: sends entries as sub-lists per
/// directory, with NDX markers.
pub async fn send_file_list<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: &[FileEntry],
    protocol: &NegotiatedProtocol,
    opts: &TransferOptions,
) -> Result<()> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    // inc_recurse requires BOTH the capability flag AND recursive mode.
    // rsync sets inc_recurse=0 when -r is not active, even with CF_INC_RECURSE.
    if protocol.incremental_flist && protocol.version >= 30 && opts.recursive() {
        send_file_list_incremental(w, entries, &flist_opts).await
    } else {
        send_file_list_batch(w, entries, &flist_opts).await
    }
}

/// Send file list as a single batch (protocol < 30 or non-recursive).
async fn send_file_list_batch<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: &[FileEntry],
    opts: &FileListOptions,
) -> Result<()> {
    let mut delta_state = DeltaState::default();
    for entry in entries {
        send_file_entry(w, entry, &mut delta_state, opts).await?;
    }
    write_end_of_flist(w, 0, opts).await?;

    // For proto < 30 (byte-mode flags), rsync sends an io_error int after
    // the end-of-list marker. The varint-mode end-of-list (proto >= 30)
    // already includes io_error in its varint(0) + varint(io_error) sequence.
    if opts.protocol_version < 30 {
        varint::write_int(w, 0).await?;
    }

    Ok(())
}

/// Send file list incrementally (protocol >= 30).
///
/// Groups entries by directory and sends each group as a sub-flist with
/// the appropriate NDX marker.
async fn send_file_list_incremental<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: &[FileEntry],
    opts: &FileListOptions,
) -> Result<()> {
    use super::codec::{send_file_entry, write_end_of_flist, DeltaState};

    let mut sender = IncrementalSender::default();

    // First sub-flist (root directory): entries are sent directly without
    // an NDX marker prefix, matching rsync's wire behavior.
    let mut delta_state = DeltaState::default();
    for entry in entries {
        send_file_entry(w, entry, &mut delta_state, opts).await?;
        sender.next_ndx += 1;
    }
    write_end_of_flist(w, 0, opts).await?;

    // Write NDX_FLIST_EOF to signal end of all file lists.
    sender
        .write_flist_eof(w, opts.protocol_version)
        .await?;
    Ok(())
}

/// Result of receiving a file list, including per-entry NDX values.
#[derive(Debug)]
pub struct ReceivedFileList {
    /// File entries sorted in rsync canonical order.
    pub entries: Vec<FileEntry>,
    /// Absolute NDX value for each entry (parallel to `entries`).
    /// With incremental file lists, there are gaps between sub-flists,
    /// so NDX values are not necessarily contiguous.
    pub entry_ndx: Vec<i32>,
    /// The starting NDX for the first sub-flist. With inc_recurse
    /// (protocol >= 30 and CF_INC_RECURSE), this is 1; otherwise 0.
    pub ndx_start: i32,
    /// Number of sub-file-lists received (for incremental mode).
    /// Needed to compute extra NDX_DONE rounds during phase exchange.
    pub num_flists: usize,
}

/// Receive a complete file list from the wire.
///
/// For protocol < 30: reads entries until end-of-list marker.
/// For protocol >= 30 with incremental flist: reads sub-lists until
/// NDX_FLIST_EOF, collecting all entries.
///
/// Returns the entries sorted in rsync canonical order, along with the
/// NDX base offset needed to compute absolute file indices.
pub async fn recv_file_list<R: AsyncRead + Unpin>(
    r: &mut R,
    protocol: &NegotiatedProtocol,
    opts: &TransferOptions,
) -> Result<ReceivedFileList> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    let (entries, ndx_start, entry_ndx, num_flists) =
        if protocol.incremental_flist && protocol.version >= 30 && opts.recursive() {
            // Incremental: entries are already sorted per-flist with correct NDX.
            recv_file_list_incremental(r, &flist_opts).await?
        } else {
            // Batch: sort entries and assign NDX by sorted position.
            let mut entries = recv_file_list_batch(r, &flist_opts).await?;
            entries.sort_by(|a, b| super::sort::f_name_cmp(a, b));

            // Read uid/gid name lists (sent after file entries in batch mode).
            // rsync's recv_id_list reads these when preserve_uid/gid and !numeric_ids.
            recv_id_list(r, &flist_opts).await?;

            let ndx: Vec<i32> = (0..entries.len() as i32).collect();
            (entries, 0, ndx, 1)
        };

    Ok(ReceivedFileList {
        entries,
        entry_ndx,
        ndx_start,
        num_flists,
    })
}

/// Receive file list as a single batch (protocol < 30).
async fn recv_file_list_batch<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    let mut delta_state = DeltaState::default();

    while let ReadEntryResult::Entry(entry) = recv_file_entry(r, &mut delta_state, opts).await? {
        entries.push(entry);
    }

    // For proto < 30 (byte-mode flags), rsync sends an io_error int after the
    // end-of-list marker. The varint-mode end-of-list (proto >= 30) already
    // includes io_error in its varint(0) + varint(io_error) sequence.
    if opts.protocol_version < 30 {
        let _io_error = varint::read_int(r).await?;
    }

    Ok(entries)
}

/// Receive file list incrementally (protocol >= 30).
///
/// The first sub-flist (root directory) is sent by rsync without an NDX marker
/// prefix -- entries are sent directly. After the first sub-flist ends,
/// subsequent sub-flists are prefixed with NDX markers, and NDX_FLIST_EOF
/// signals the end of all file lists.
async fn recv_file_list_incremental<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
) -> Result<(Vec<FileEntry>, i32, Vec<i32>, usize)> {
    use super::codec::DeltaState;

    let mut receiver = IncrementalReceiver::default();
    let mut all_entries = Vec::new();
    let mut all_ndx = Vec::new();
    let mut num_flists: usize = 0;

    // rsync's encoder uses static delta state across ALL sub-flists.
    // We must share a single DeltaState to decode correctly.
    let mut delta_state = DeltaState::default();

    // Helper: sort a sub-flist and assign NDX based on sorted position.
    // rsync assigns NDX = flist->ndx_start + position_in_sorted_flist,
    // so NDX values depend on sorted order, not wire order.
    fn sort_and_assign(
        mut entries: Vec<FileEntry>,
        ndx_start: i32,
        all_entries: &mut Vec<FileEntry>,
        all_ndx: &mut Vec<i32>,
    ) {
        entries.sort_by(|a, b| super::sort::f_name_cmp(a, b));
        for (i, entry) in entries.into_iter().enumerate() {
            all_ndx.push(ndx_start + i as i32);
            all_entries.push(entry);
        }
    }

    // First sub-flist: read entries directly (no NDX marker prefix).
    let first_flist = receiver
        .recv_sub_flist_with_state(r, 0, opts, &mut delta_state)
        .await?;
    let ndx_start = first_flist.ndx_start;
    sort_and_assign(
        first_flist.entries,
        first_flist.ndx_start,
        &mut all_entries,
        &mut all_ndx,
    );
    num_flists += 1;

    // Read subsequent sub-flists prefixed with NDX markers.
    loop {
        let ndx = receiver.read_ndx_marker(r, opts.protocol_version).await?;
        if ndx == NDX_FLIST_EOF {
            break;
        }
        if ndx <= NDX_FLIST_OFFSET {
            let dir_ndx = NDX_FLIST_OFFSET - ndx;
            let sub_flist = receiver
                .recv_sub_flist_with_state(r, dir_ndx, opts, &mut delta_state)
                .await?;
            sort_and_assign(
                sub_flist.entries,
                sub_flist.ndx_start,
                &mut all_entries,
                &mut all_ndx,
            );
            num_flists += 1;
        } else {
            return Err(ProtocolError::Handshake {
                message: format!("unexpected NDX value {ndx} during file list reception"),
            });
        }
    }

    Ok((all_entries, ndx_start, all_ndx, num_flists))
}

/// Receive a file list incrementally and stream entries to a channel.
///
/// This allows the transfer engine to start processing files before the
/// full file list is received, reducing time-to-first-byte for large
/// directory trees.
///
/// Each entry is sent through the channel as soon as it's decoded.
/// The channel is closed when the file list is complete.
pub async fn recv_file_list_streaming<R: AsyncRead + Unpin>(
    r: &mut R,
    protocol: &NegotiatedProtocol,
    opts: &TransferOptions,
    tx: mpsc::Sender<FileEntry>,
) -> Result<()> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    if protocol.incremental_flist && protocol.version >= 30 && opts.recursive() {
        recv_file_list_incremental_streaming(r, &flist_opts, tx).await
    } else {
        recv_file_list_batch_streaming(r, &flist_opts, tx).await
    }
}

/// Stream batch file list entries to a channel.
async fn recv_file_list_batch_streaming<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
    tx: mpsc::Sender<FileEntry>,
) -> Result<()> {
    let mut delta_state = DeltaState::default();

    while let ReadEntryResult::Entry(entry) = recv_file_entry(r, &mut delta_state, opts).await? {
        if tx.send(entry).await.is_err() {
            // Receiver dropped -- transfer engine shut down.
            break;
        }
    }

    // For proto < 30, consume the io_error int after the end-of-list marker.
    if opts.protocol_version < 30 {
        let _io_error = varint::read_int(r).await?;
    }

    Ok(())
}

/// Stream incremental file list entries to a channel.
async fn recv_file_list_incremental_streaming<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
    tx: mpsc::Sender<FileEntry>,
) -> Result<()> {
    let mut receiver = IncrementalReceiver::default();

    // First sub-flist: read entries directly (no NDX marker prefix).
    let first_flist = receiver.recv_sub_flist(r, 0, opts).await?;
    for entry in first_flist.entries {
        if tx.send(entry).await.is_err() {
            return Ok(());
        }
    }

    // Subsequent sub-flists prefixed with NDX markers.
    loop {
        let ndx = receiver
            .read_ndx_marker(r, opts.protocol_version)
            .await?;

        if ndx == NDX_FLIST_EOF {
            break;
        }

        if ndx <= NDX_FLIST_OFFSET {
            let dir_ndx = NDX_FLIST_OFFSET - ndx;
            let sub_flist = receiver.recv_sub_flist(r, dir_ndx, opts).await?;
            for entry in sub_flist.entries {
                if tx.send(entry).await.is_err() {
                    return Ok(());
                }
            }
        } else {
            return Err(ProtocolError::Handshake {
                message: format!("unexpected NDX value {ndx} during file list reception"),
            });
        }
    }

    Ok(())
}

/// Read and discard uid/gid name mapping lists (batch mode only).
///
/// rsync sends these after the file entries when `preserve_uid` or
/// `preserve_gid` is active and `numeric_ids` is false. Each list is a
/// series of `(varint30 id, byte name_len, name_bytes)` terminated by
/// `varint30(0)`.
async fn recv_id_list<R: AsyncRead + Unpin>(
    r: &mut R,
    opts: &FileListOptions,
) -> Result<()> {
    // uid list
    if opts.preserve_uid {
        loop {
            let id = varint::read_varint30(r, opts.protocol_version).await?;
            if id == 0 {
                break;
            }
            let name_len = varint::read_byte(r).await? as usize;
            let mut name = vec![0u8; name_len];
            r.read_exact(&mut name).await?;
        }
    }
    // gid list
    if opts.preserve_gid {
        loop {
            let id = varint::read_varint30(r, opts.protocol_version).await?;
            if id == 0 {
                break;
            }
            let name_len = varint::read_byte(r).await? as usize;
            let mut name = vec![0u8; name_len];
            r.read_exact(&mut name).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::chunker::ChunkingStrategy;
    use crate::filelist::entry::{S_IFDIR, S_IFREG};
    use crate::protocol::handshake::{
        compat_flags, ChecksumType, CompressType, NegotiatedProtocol,
    };
    use std::io::Cursor;

    fn proto_v31() -> NegotiatedProtocol {
        NegotiatedProtocol {
            version: 31,
            compat_flags: compat_flags::DEFAULT | compat_flags::INC_RECURSE,
            incremental_flist: true,
            varint_flist_flags: true,
            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: true,
            seed: 42,
            chunking: ChunkingStrategy::default(),
        }
    }

    fn proto_v27() -> NegotiatedProtocol {
        NegotiatedProtocol {
            version: 27,
            compat_flags: 0,
            incremental_flist: false,
            varint_flist_flags: false,
            checksum: ChecksumType::Md4,
            compress: CompressType::None,
            proper_seed_order: false,
            seed: 42,
            chunking: ChunkingStrategy::default(),
        }
    }

    fn proto_v29() -> NegotiatedProtocol {
        NegotiatedProtocol {
            version: 29,
            compat_flags: 0,
            incremental_flist: false,
            varint_flist_flags: false,
            checksum: ChecksumType::Md4,
            compress: CompressType::None,
            proper_seed_order: false,
            seed: 42,
            chunking: ChunkingStrategy::default(),
        }
    }

    fn proto_v30_no_inc() -> NegotiatedProtocol {
        NegotiatedProtocol {
            version: 30,
            compat_flags: compat_flags::SAFE_FLIST | compat_flags::VARINT_FLIST_FLAGS,
            incremental_flist: false,
            varint_flist_flags: true,
            checksum: ChecksumType::Md5,
            compress: CompressType::None,
            proper_seed_order: false,
            seed: 42,
            chunking: ChunkingStrategy::default(),
        }
    }

    fn default_opts() -> TransferOptions {
        TransferOptions::default()
    }

    fn test_entries() -> Vec<FileEntry> {
        vec![
            FileEntry {
                name: b"alpha.txt".to_vec(),
                len: 100,
                mtime: 1700000000,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"beta".to_vec(),
                len: 0,
                mtime: 1700000000,
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"gamma.txt".to_vec(),
                len: 200,
                mtime: 1700000001,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ]
    }

    #[tokio::test]
    async fn test_batch_roundtrip_proto27() {
        let proto = proto_v27();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let received = recv_file_list(&mut cursor, &proto, &opts)
            .await
            .unwrap()
            .entries;

        assert_eq!(received.len(), 3);
        // Entries are sorted by sort_file_list.
        assert_eq!(received[0].name, b"alpha.txt");
        assert_eq!(received[0].len, 100);
    }

    #[tokio::test]
    async fn test_batch_roundtrip_proto29() {
        let proto = proto_v29();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let received = recv_file_list(&mut cursor, &proto, &opts)
            .await
            .unwrap()
            .entries;

        assert_eq!(received.len(), 3);
        assert_eq!(received[0].name, b"alpha.txt");
    }

    #[tokio::test]
    async fn test_batch_roundtrip_proto30_no_incremental() {
        let proto = proto_v30_no_inc();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let received = recv_file_list(&mut cursor, &proto, &opts)
            .await
            .unwrap()
            .entries;

        assert_eq!(received.len(), 3);
    }

    #[tokio::test]
    async fn test_incremental_roundtrip_proto31() {
        let proto = proto_v31();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let received = recv_file_list(&mut cursor, &proto, &opts)
            .await
            .unwrap()
            .entries;

        assert_eq!(received.len(), 3);
        assert_eq!(received[0].name, b"alpha.txt");
        assert_eq!(received[0].len, 100);
        assert_eq!(received[2].name, b"gamma.txt");
        assert_eq!(received[2].len, 200);
    }

    #[tokio::test]
    async fn test_streaming_recv_proto31() {
        let proto = proto_v31();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let mut cursor = Cursor::new(buf);

        recv_file_list_streaming(&mut cursor, &proto, &opts, tx)
            .await
            .unwrap();

        let mut received = Vec::new();
        while let Some(entry) = rx.recv().await {
            received.push(entry);
        }

        assert_eq!(received.len(), 3);
        assert_eq!(received[0].name, b"alpha.txt");
    }

    #[tokio::test]
    async fn test_streaming_recv_proto27() {
        let proto = proto_v27();
        let opts = default_opts();
        let entries = test_entries();

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let mut cursor = Cursor::new(buf);

        recv_file_list_streaming(&mut cursor, &proto, &opts, tx)
            .await
            .unwrap();

        let mut received = Vec::new();
        while let Some(entry) = rx.recv().await {
            received.push(entry);
        }

        assert_eq!(received.len(), 3);
    }

    #[tokio::test]
    async fn test_empty_file_list() {
        let proto = proto_v31();
        let opts = default_opts();
        let entries: Vec<FileEntry> = vec![];

        let mut buf = Vec::new();
        send_file_list(&mut buf, &entries, &proto, &opts)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let received = recv_file_list(&mut cursor, &proto, &opts)
            .await
            .unwrap()
            .entries;

        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_flist_options_from_protocol() {
        let proto = proto_v31();
        let opts = TransferOptions::builder()
            .archive()
            .checksum_mode(true)
            .build();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.protocol_version, 31);
        assert!(flist_opts.xfer_flags_as_varint);
        assert!(flist_opts.preserve_uid);
        assert!(flist_opts.preserve_gid);
        assert!(flist_opts.preserve_devices);
        assert!(flist_opts.preserve_specials);
        assert!(flist_opts.preserve_links);
        assert!(flist_opts.always_checksum);
        assert_eq!(flist_opts.checksum_len, 16);
    }

    #[tokio::test]
    async fn test_flist_options_from_protocol_v27() {
        let proto = proto_v27();
        let opts = TransferOptions::default();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.protocol_version, 27);
        assert!(!flist_opts.xfer_flags_as_varint);
        assert_eq!(flist_opts.checksum_len, 16); // MD4 = 16 bytes
    }

    #[tokio::test]
    async fn test_checksum_type_affects_flist_opts() {
        let mut proto = proto_v31();
        proto.checksum = ChecksumType::None;
        let opts = TransferOptions::builder().checksum_mode(true).build();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.checksum_len, 0);
    }
}
