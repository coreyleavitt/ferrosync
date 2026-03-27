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

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::options::TransferConfig;
use crate::protocol::handshake::NegotiatedProtocol;
use crate::protocol::varint;

use super::codec::{
    recv_file_entry, send_file_entry, write_end_of_flist, DeltaState, FileListOptions,
    HardLinkDecoder, HardLinkEncoder, ReadEntryResult,
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
    opts: &TransferConfig,
) -> Result<()> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    // inc_recurse requires BOTH the capability flag AND recursive mode.
    // rsync sets inc_recurse=0 when -r is not active, even with CF_INC_RECURSE.
    if protocol.wire().supports_incremental_flist && opts.recursive() {
        send_file_list_incremental(w, entries, &flist_opts).await
    } else {
        send_file_list_batch(w, entries, &flist_opts).await?;
        // C ref: send_id_lists (uidlist.c:407-414), called from flist.c:2514
        // In batch mode (!inc_recurse), uid/gid name lists are sent after the
        // file entries and end-of-list marker, inside send_file_list.
        // When --numeric-ids is active, rsync skips the name list exchange
        // entirely (uidlist.c:407: if (numeric_ids > 0) return).
        if !flist_opts.numeric_ids {
            send_id_list(w, entries, &flist_opts).await?;
        }
        Ok(())
    }
}

/// Send file list as a single batch (protocol < 30 or non-recursive).
async fn send_file_list_batch<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: &[FileEntry],
    opts: &FileListOptions,
) -> Result<()> {
    let mut delta_state = DeltaState::default();
    let mut hlink_encoder = HardLinkEncoder::new();
    let mut acl_encoder = crate::acl::AclEncoder::new();
    let mut xattr_encoder = crate::xattr::XattrEncoder::new();
    for (i, entry) in entries.iter().enumerate() {
        send_file_entry(
            w,
            entry,
            &mut delta_state,
            opts,
            &mut hlink_encoder,
            entry.hard_link_info(),
            i as i32,
            None,
            &mut acl_encoder,
            &mut xattr_encoder,
        )
        .await?;
    }
    write_end_of_flist(w, 0, opts).await?;

    // For proto < 30 (byte-mode flags), rsync sends an io_error int after
    // the end-of-list marker. The varint-mode end-of-list (proto >= 30)
    // already includes io_error in its varint(0) + varint(io_error) sequence.
    if opts.wire.trailing_io_error {
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
    use super::codec::{send_file_entry, write_end_of_flist, DeltaState, HardLinkEncoder};

    let mut sender = IncrementalSender::default();
    let mut hlink_encoder = HardLinkEncoder::new();
    let mut acl_encoder = crate::acl::AclEncoder::new();
    let mut xattr_encoder = crate::xattr::XattrEncoder::new();

    // C ref: flist.c -- inc_recurse NDX starts at 1 (flist_new() sets
    // ndx_start = flist_cnt, and flist_cnt starts at 1). Entry indices
    // used for hardlink back-references must be absolute NDX values,
    // not 0-based array positions.
    let ndx_start: i32 = 1; // inc_recurse first sub-flist always starts at 1

    // First sub-flist (root directory): entries are sent directly without
    // an NDX marker prefix, matching rsync's wire behavior.
    let mut delta_state = DeltaState::default();
    for (i, entry) in entries.iter().enumerate() {
        send_file_entry(
            w,
            entry,
            &mut delta_state,
            opts,
            &mut hlink_encoder,
            entry.hard_link_info(),
            ndx_start + i as i32,
            None,
            &mut acl_encoder,
            &mut xattr_encoder,
        )
        .await?;
        sender.next_ndx += 1;
    }
    write_end_of_flist(w, 0, opts).await?;

    // Write NDX_FLIST_EOF to signal end of all file lists.
    sender.write_flist_eof(w, opts.wire.int_codec).await?;
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
    opts: &TransferConfig,
) -> Result<ReceivedFileList> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    let (entries, ndx_start, entry_ndx, num_flists) =
        if protocol.wire().supports_incremental_flist && opts.recursive() {
            // Incremental: entries are already sorted per-flist with correct NDX.
            recv_file_list_incremental(r, &flist_opts).await?
        } else {
            // Batch: sort entries and assign NDX by sorted position.
            let mut entries = recv_file_list_batch(r, &flist_opts).await?;
            entries.sort_by(super::sort::f_name_cmp);

            // Read uid/gid name lists (sent after file entries in batch mode).
            // rsync's recv_id_list reads these when preserve_uid/gid and !numeric_ids.
            // When --numeric-ids is active, the sender skips sending them.
            if !flist_opts.numeric_ids {
                recv_id_list(r, &flist_opts).await?;
            }

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
    let mut hlink_decoder = HardLinkDecoder::new();
    let mut acl_decoder = crate::acl::AclDecoder::new();
    let mut xattr_decoder = crate::xattr::XattrDecoder::new();

    while let ReadEntryResult::Entry(entry) = recv_file_entry(
        r,
        &mut delta_state,
        opts,
        &mut hlink_decoder,
        &entries,
        None,
        &mut acl_decoder,
        &mut xattr_decoder,
    )
    .await?
    {
        entries.push(*entry);
    }

    // For proto < 30 (byte-mode flags), rsync sends an io_error int after the
    // end-of-list marker. The varint-mode end-of-list (proto >= 30) already
    // includes io_error in its varint(0) + varint(io_error) sequence.
    if opts.wire.trailing_io_error {
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
        entries.sort_by(super::sort::f_name_cmp);
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
        let ndx = receiver.read_ndx_marker(r, opts.wire.int_codec).await?;
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
    opts: &TransferConfig,
    tx: mpsc::Sender<FileEntry>,
) -> Result<()> {
    let flist_opts = FileListOptions::from_protocol(protocol, opts);

    if protocol.wire().supports_incremental_flist && opts.recursive() {
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
    let mut hlink_decoder = HardLinkDecoder::new();
    let mut acl_decoder = crate::acl::AclDecoder::new();
    let mut xattr_decoder = crate::xattr::XattrDecoder::new();
    let mut entries = Vec::new();

    #[allow(clippy::while_let_loop)]
    loop {
        match recv_file_entry(
            r,
            &mut delta_state,
            opts,
            &mut hlink_decoder,
            &entries,
            None,
            &mut acl_decoder,
            &mut xattr_decoder,
        )
        .await?
        {
            ReadEntryResult::Entry(entry) => {
                let entry = *entry;
                entries.push(entry.clone());
                if tx.send(entry).await.is_err() {
                    // Receiver dropped -- transfer engine shut down.
                    break;
                }
            }
            ReadEntryResult::EndOfList { .. } => break,
        }
    }

    // For proto < 30, consume the io_error int after the end-of-list marker.
    if opts.wire.trailing_io_error {
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
        let ndx = receiver.read_ndx_marker(r, opts.wire.int_codec).await?;

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

/// Write uid/gid name mapping lists (batch mode only).
///
/// C ref: send_id_lists (uidlist.c:407-414), send_one_list (uidlist.c:388)
///
/// Each list is a series of `(varint30 id, byte name_len, name_bytes)` entries
/// for all unique non-zero ids. The list is terminated differently depending
/// on xmit_id0_names (compat_flags & ID0_NAMES):
///
/// - With xmit_id0_names: send `(varint30(0), byte(name_len), name_bytes)`
///   as the name for uid/gid 0 (e.g., "root"/"root")
/// - Without xmit_id0_names: send just `varint30(0)` as terminator
async fn send_id_list<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: &[FileEntry],
    opts: &FileListOptions,
) -> Result<()> {
    use std::collections::BTreeMap;

    // uid list
    if opts.preserve_uid {
        let mut uid_names: BTreeMap<u32, &[u8]> = BTreeMap::new();
        for entry in entries {
            if !entry.user_name.is_empty() && !uid_names.contains_key(&entry.uid) {
                uid_names.insert(entry.uid, &entry.user_name);
            }
        }
        // Send non-zero id entries.
        for (&uid, name) in &uid_names {
            if uid == 0 {
                continue; // id 0 is handled specially below
            }
            varint::write_varint30(w, uid, opts.wire.int_codec).await?;
            let name_len = name.len().min(255) as u8;
            varint::write_byte(w, name_len).await?;
            w.write_all(&name[..name_len as usize]).await?;
        }
        // Terminator / id-0 entry.
        if opts.xmit_id0_names {
            // Modern rsync: send id=0 as the terminator, followed by the name
            // for uid 0 (e.g., "root"). The recv side reads varint30(0) to exit
            // the loop, then reads one more recv_user_name(f, 0).
            varint::write_varint30(w, 0, opts.wire.int_codec).await?;
            let id0_name = uid_names.get(&0).copied().unwrap_or(b"root");
            let name_len = id0_name.len().min(255) as u8;
            varint::write_byte(w, name_len).await?;
            w.write_all(&id0_name[..name_len as usize]).await?;
        } else {
            varint::write_varint30(w, 0, opts.wire.int_codec).await?;
        }
    }

    // gid list
    if opts.preserve_gid {
        let mut gid_names: BTreeMap<u32, &[u8]> = BTreeMap::new();
        for entry in entries {
            if !entry.group_name.is_empty() && !gid_names.contains_key(&entry.gid) {
                gid_names.insert(entry.gid, &entry.group_name);
            }
        }
        for (&gid, name) in &gid_names {
            if gid == 0 {
                continue;
            }
            varint::write_varint30(w, gid, opts.wire.int_codec).await?;
            let name_len = name.len().min(255) as u8;
            varint::write_byte(w, name_len).await?;
            w.write_all(&name[..name_len as usize]).await?;
        }
        if opts.xmit_id0_names {
            varint::write_varint30(w, 0, opts.wire.int_codec).await?;
            let id0_name = gid_names.get(&0).copied().unwrap_or(b"root");
            let name_len = id0_name.len().min(255) as u8;
            varint::write_byte(w, name_len).await?;
            w.write_all(&id0_name[..name_len as usize]).await?;
        } else {
            varint::write_varint30(w, 0, opts.wire.int_codec).await?;
        }
    }

    Ok(())
}

/// Read and discard uid/gid name mapping lists (batch mode only).
///
/// C ref: recv_id_list (uidlist.c:460-479)
///
/// rsync sends these after the file entries when `preserve_uid` or
/// `preserve_gid` is active and `numeric_ids` is false. Each list is a
/// series of `(varint30 id, byte name_len, name_bytes)` terminated by
/// `varint30(0)`. When `xmit_id0_names` is true, an additional name
/// entry for id=0 follows the terminator.
async fn recv_id_list<R: AsyncRead + Unpin>(r: &mut R, opts: &FileListOptions) -> Result<()> {
    // uid list
    if opts.preserve_uid {
        loop {
            let id = varint::read_varint30(r, opts.wire.int_codec).await?;
            if id == 0 {
                break;
            }
            let name_len = varint::read_byte(r).await? as usize;
            let mut name = vec![0u8; name_len];
            r.read_exact(&mut name).await?;
        }
        // C ref: uidlist.c:469 -- with xmit_id0_names, read the name for uid 0.
        if opts.xmit_id0_names {
            let name_len = varint::read_byte(r).await? as usize;
            let mut name = vec![0u8; name_len];
            r.read_exact(&mut name).await?;
        }
    }
    // gid list
    if opts.preserve_gid {
        loop {
            let id = varint::read_varint30(r, opts.wire.int_codec).await?;
            if id == 0 {
                break;
            }
            let name_len = varint::read_byte(r).await? as usize;
            let mut name = vec![0u8; name_len];
            r.read_exact(&mut name).await?;
        }
        if opts.xmit_id0_names {
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
    use crate::protocol::wire_format::{FlagsCodec, IntCodec, WireFormat};
    use crate::types::{FileSize, UnixTimestamp};
    use std::io::Cursor;

    fn proto_v31() -> NegotiatedProtocol {
        NegotiatedProtocol::new(
            31,
            compat_flags::DEFAULT | compat_flags::INC_RECURSE,
            ChecksumType::Md5,
            CompressType::None,
            true,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(31, compat_flags::DEFAULT | compat_flags::INC_RECURSE),
        )
    }

    fn proto_v27() -> NegotiatedProtocol {
        NegotiatedProtocol::new(
            27,
            0,
            ChecksumType::Md4,
            CompressType::None,
            false,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(27, 0),
        )
    }

    fn proto_v29() -> NegotiatedProtocol {
        NegotiatedProtocol::new(
            29,
            0,
            ChecksumType::Md4,
            CompressType::None,
            false,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(29, 0),
        )
    }

    fn proto_v30_no_inc() -> NegotiatedProtocol {
        NegotiatedProtocol::new(
            30,
            compat_flags::SAFE_FLIST | compat_flags::VARINT_FLIST_FLAGS,
            ChecksumType::Md5,
            CompressType::None,
            false,
            42,
            ChunkingStrategy::default(),
            WireFormat::new(
                30,
                compat_flags::SAFE_FLIST | compat_flags::VARINT_FLIST_FLAGS,
            ),
        )
    }

    fn default_opts() -> TransferConfig {
        TransferConfig::default()
    }

    fn test_entries() -> Vec<FileEntry> {
        vec![
            FileEntry {
                name: b"alpha.txt".to_vec(),
                len: FileSize(100),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"beta".to_vec(),
                len: FileSize(0),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"gamma.txt".to_vec(),
                len: FileSize(200),
                mtime: UnixTimestamp(1700000001),
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
        assert_eq!(received[0].len, FileSize(100));
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
        // With rsync's canonical sort (proto >= 29), files sort before dirs:
        // alpha.txt, gamma.txt, beta (dir).
        assert_eq!(received[0].name, b"alpha.txt");
        assert_eq!(received[0].len, FileSize(100));
        assert_eq!(received[1].name, b"gamma.txt");
        assert_eq!(received[1].len, FileSize(200));
        assert_eq!(received[2].name, b"beta");
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
        let opts = TransferConfig::builder()
            .archive()
            .checksum_mode(true)
            .build();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.wire.int_codec, IntCodec::Compact);
        assert_eq!(flist_opts.wire.flags_codec, FlagsCodec::Varint);
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
        let opts = TransferConfig::default();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.wire.int_codec, IntCodec::Fixed);
        assert_eq!(flist_opts.wire.flags_codec, FlagsCodec::Byte);
        assert_eq!(flist_opts.checksum_len, 16); // MD4 = 16 bytes
    }

    #[tokio::test]
    async fn test_checksum_type_affects_flist_opts() {
        let mut proto = proto_v31();
        proto.checksum = ChecksumType::None;
        let opts = TransferConfig::builder().checksum_mode(true).build();

        let flist_opts = FileListOptions::from_protocol(&proto, &opts);
        assert_eq!(flist_opts.checksum_len, 0);
    }
}
