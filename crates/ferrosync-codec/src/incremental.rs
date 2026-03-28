//! Incremental file list exchange (protocol >= 30).
//!
//! In incremental recursion mode, the sender does not send the entire file
//! tree at once. Instead, it sends sub-flists on demand as directories are
//! descended into.
//!
//! NDX markers signal transitions between file lists:
//! - `NDX_FLIST_OFFSET - dir_ndx`: here comes a flist for directory at `dir_ndx`
//! - `NDX_FLIST_EOF`: all flists are done
//! - `NDX_DONE`: end of a transfer phase

use tokio::io::{AsyncRead, AsyncWrite};

use ferrosync_protocol::varint::{self, NdxState};
use ferrosync_protocol::wire_format::IntCodec;
use ferrosync_types::error::ProtocolError;

use crate::codec::{
    recv_file_entry, send_file_entry, write_end_of_flist, DeltaState, FileListOptions,
    HardLinkDecoder, HardLinkEncoder, ReadEntryResult,
};
use crate::entry::{FileEntry, S_IFDIR, S_IFMT};

type Result<T> = std::result::Result<T, ProtocolError>;

/// Special NDX values for incremental file list signaling.
pub const NDX_FLIST_OFFSET: i32 = -101;
pub const NDX_FLIST_EOF: i32 = -2;

/// A sub-file-list received during incremental recursion.
#[derive(Debug)]
pub struct SubFileList {
    /// The directory index this sub-list belongs to.
    pub dir_ndx: i32,
    /// Starting index for entries in this sub-list (global offset).
    pub ndx_start: i32,
    /// The file entries in this sub-list.
    pub entries: Vec<FileEntry>,
    /// I/O error code from the end-of-list marker (0 = no error).
    pub io_error: i32,
}

/// State for receiving incremental file lists.
#[derive(Debug)]
pub struct IncrementalReceiver {
    /// NDX encoding state for reading file list index markers.
    pub ndx_state: NdxState,
    /// Next global file index to assign.
    pub next_ndx: i32,
}

impl Default for IncrementalReceiver {
    fn default() -> Self {
        Self::new(true)
    }
}

impl IncrementalReceiver {
    /// Create a new receiver. When `inc_recurse` is true (protocol >= 30
    /// with CF_INC_RECURSE), the first flist starts at ndx_start=1 to match
    /// rsync's `flist_new()` behavior.
    pub fn new(inc_recurse: bool) -> Self {
        Self {
            ndx_state: NdxState::default(),
            next_ndx: if inc_recurse { 1 } else { 0 },
        }
    }

    /// Read the next NDX marker from the stream.
    ///
    /// Returns the raw NDX value. Callers should check:
    /// - `NDX_FLIST_EOF`: all file lists are done
    /// - `val <= NDX_FLIST_OFFSET`: a sub-flist for `NDX_FLIST_OFFSET - val`
    /// - `NDX_DONE` / other: phase/transfer control
    pub async fn read_ndx_marker<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        codec: IntCodec,
    ) -> Result<i32> {
        varint::read_ndx(r, &mut self.ndx_state, codec).await
    }

    /// Receive a complete sub-file-list from the stream.
    ///
    /// Call this after receiving an NDX marker indicating a new sub-flist.
    /// Reads entries until the end-of-list marker.
    pub async fn recv_sub_flist<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        dir_ndx: i32,
        opts: &FileListOptions,
    ) -> Result<SubFileList> {
        let mut delta_state = DeltaState::default();
        self.recv_sub_flist_with_state(r, dir_ndx, opts, &mut delta_state)
            .await
    }

    /// Receive a sub-file-list using an external delta state.
    ///
    /// rsync's encoder uses static delta state that carries across all
    /// sub-flists. When reading from a real rsync sender, use a single
    /// `DeltaState` across all sub-flist reads.
    pub async fn recv_sub_flist_with_state<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        dir_ndx: i32,
        opts: &FileListOptions,
        delta_state: &mut DeltaState,
    ) -> Result<SubFileList> {
        let ndx_start = self.next_ndx;
        delta_state.ndx_start = ndx_start;
        let mut entries = Vec::new();
        let mut hlink_decoder = HardLinkDecoder::new();
        let mut acl_decoder = crate::acl::AclDecoder::new();
        let mut xattr_decoder = crate::xattr::XattrDecoder::new();

        loop {
            match recv_file_entry(
                r,
                delta_state,
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
                    self.next_ndx += 1;
                    entries.push(*entry);
                }
                ReadEntryResult::EndOfList { io_error } => {
                    // Add +1 gap to match rsync's flist_new:
                    // next flist ndx_start = prev.ndx_start + prev.used + 1
                    self.next_ndx += 1;
                    return Ok(SubFileList {
                        dir_ndx,
                        ndx_start,
                        entries,
                        io_error,
                    });
                }
            }
        }
    }
}

/// State for sending incremental file lists.
#[derive(Debug, Default)]
pub struct IncrementalSender {
    /// NDX encoding state for writing file list index markers.
    pub ndx_state: NdxState,
    /// Next global file index.
    pub next_ndx: i32,
}

impl IncrementalSender {
    /// Write an NDX marker indicating a new sub-flist for the given directory.
    pub async fn write_sub_flist_marker<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        dir_ndx: i32,
        codec: IntCodec,
    ) -> Result<()> {
        let ndx_val = NDX_FLIST_OFFSET - dir_ndx;
        varint::write_ndx(w, ndx_val, &mut self.ndx_state, codec).await
    }

    /// Send a complete sub-file-list with shared delta state.
    #[allow(clippy::too_many_arguments)]
    ///
    /// rsync's encoder uses static delta state that carries across all
    /// sub-flists. Callers must pass a single `DeltaState` shared across
    /// all `send_sub_flist_with_state` calls to produce wire-compatible output.
    ///
    /// Writes the NDX marker, all entries, and the end-of-list marker.
    /// After writing end-of-list, increments `next_ndx` by 1 to match
    /// rsync's `flist_new()` gap between sub-flists.
    pub async fn send_sub_flist_with_state<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        dir_ndx: i32,
        entries: &[FileEntry],
        opts: &FileListOptions,
        delta_state: &mut DeltaState,
        hlink_encoder: &mut HardLinkEncoder,
        acl_encoder: &mut crate::acl::AclEncoder,
        xattr_encoder: &mut crate::xattr::XattrEncoder,
    ) -> Result<()> {
        // Write the sub-flist marker.
        self.write_sub_flist_marker(w, dir_ndx, opts.wire.int_codec)
            .await?;

        // Write entries. Entry indices must be absolute NDX values (not
        // 0-based) so hardlink back-references point to the correct entry
        // in rsync's receiver. self.next_ndx tracks the current absolute NDX.
        let ndx_start = self.next_ndx;
        delta_state.ndx_start = ndx_start;
        for (i, entry) in entries.iter().enumerate() {
            send_file_entry(
                w,
                entry,
                delta_state,
                opts,
                hlink_encoder,
                entry.hard_link_info(),
                ndx_start + i as i32,
                None,
                acl_encoder,
                xattr_encoder,
            )
            .await?;
            self.next_ndx += 1;
        }

        // Write end-of-list.
        write_end_of_flist(w, 0, opts).await?;

        // Add +1 gap to match rsync's flist_new():
        // next flist ndx_start = prev.ndx_start + prev.used + 1
        self.next_ndx += 1;
        Ok(())
    }

    /// Send a complete sub-file-list (convenience wrapper with fresh state).
    ///
    /// Creates fresh delta/hlink/acl/xattr state for this sub-flist.
    /// For wire-compatible encoding with rsync, prefer `send_sub_flist_with_state`
    /// with shared state across all sub-flists.
    pub async fn send_sub_flist<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        dir_ndx: i32,
        entries: &[FileEntry],
        opts: &FileListOptions,
    ) -> Result<()> {
        let mut delta_state = DeltaState::default();
        let mut hlink_encoder = HardLinkEncoder::new();
        let mut acl_encoder = crate::acl::AclEncoder::new();
        let mut xattr_encoder = crate::xattr::XattrEncoder::new();
        self.send_sub_flist_with_state(
            w,
            dir_ndx,
            entries,
            opts,
            &mut delta_state,
            &mut hlink_encoder,
            &mut acl_encoder,
            &mut xattr_encoder,
        )
        .await
    }

    /// Encode a sub-flist's entries to the writer.
    ///
    /// Writes all entries followed by end-of-list marker. Advances
    /// `next_ndx` by entry count + 1 gap (matching rsync's `flist_new()`).
    ///
    /// Used by both root sub-flist sending (`send_file_list_incremental`)
    /// and deferred sub-flist sending (`PendingSubFlists::send_pending`).
    /// Single encoding loop eliminates duplication.
    #[allow(clippy::too_many_arguments)]
    pub async fn encode_sub_flist_entries<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        entries: &[FileEntry],
        entry_indices: &[usize],
        delta_state: &mut DeltaState,
        opts: &FileListOptions,
        hlink_encoder: &mut HardLinkEncoder,
        acl_encoder: &mut crate::acl::AclEncoder,
        xattr_encoder: &mut crate::xattr::XattrEncoder,
    ) -> Result<()> {
        let ndx_start = self.next_ndx;
        delta_state.ndx_start = ndx_start;
        for (pos, &entry_idx) in entry_indices.iter().enumerate() {
            let entry = &entries[entry_idx];
            send_file_entry(
                w,
                entry,
                delta_state,
                opts,
                hlink_encoder,
                entry.hard_link_info(),
                ndx_start + pos as i32,
                None,
                acl_encoder,
                xattr_encoder,
            )
            .await?;
            self.next_ndx += 1;
        }
        write_end_of_flist(w, 0, opts).await?;
        self.next_ndx += 1; // +1 gap matching rsync's flist_new()
        Ok(())
    }

    /// Write the NDX_FLIST_EOF marker indicating all file lists are done.
    pub async fn write_flist_eof<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        codec: IntCodec,
    ) -> Result<()> {
        varint::write_ndx(w, NDX_FLIST_EOF, &mut self.ndx_state, codec).await
    }
}

/// A group of entries belonging to a single directory in the incremental
/// file list.
#[derive(Debug)]
pub struct DirGroup {
    /// dir_flist index of the parent directory. -1 for the root group.
    ///
    /// In inc_recurse mode, rsync separates directories into `dir_flist`
    /// with their own numbering (0, 1, 2, ...). Sub-flist NDX markers
    /// reference these dir_flist indices, NOT positions in the full
    /// entry list.
    pub dir_ndx: i32,
    /// Indices into the original entries slice for this group's members.
    pub entry_indices: Vec<usize>,
}

/// Tree structure extracted from a sorted entry list for incremental
/// file list encoding.
///
/// Separates the flat sorted entries into per-directory groups. The root
/// group contains top-level entries. Each subdirectory gets its own group
/// with a `dir_ndx` referencing the dir_flist index (directory-only
/// numbering, matching rsync's `dir_flist` separation).
///
/// Groups are ordered root-first, then depth-first matching rsync's
/// traversal in `send_extra_file_list()`.
pub struct DirectoryTree {
    /// Groups in send order: root at [0], then depth-first subdirectories.
    pub groups: Vec<DirGroup>,
}

impl DirectoryTree {
    /// Build from canonically-sorted entries.
    ///
    /// Uses `FileEntry::dirname()` for parent-child relationships.
    pub fn from_sorted_entries(entries: &[FileEntry]) -> Self {
        if entries.is_empty() {
            return Self {
                groups: vec![DirGroup {
                    dir_ndx: -1,
                    entry_indices: vec![],
                }],
            };
        }

        // Root group: entries with no dirname (top-level).
        let root_indices: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.dirname().is_none())
            .map(|(i, _)| i)
            .collect();

        let mut groups = vec![DirGroup {
            dir_ndx: -1,
            entry_indices: root_indices,
        }];

        // Assign dir_flist indices to directories. rsync numbers directories
        // separately from regular files in its dir_flist.
        let mut dir_flist_ndx: Vec<i32> = vec![-1; entries.len()];
        let mut dir_counter: i32 = 0;
        for &idx in &groups[0].entry_indices {
            if entries[idx].mode & S_IFMT == S_IFDIR {
                dir_flist_ndx[idx] = dir_counter;
                dir_counter += 1;
            }
        }

        // BFS queue: (entry_index, directory_name_bytes) for directories to descend.
        let mut queue: Vec<(usize, Vec<u8>)> = groups[0]
            .entry_indices
            .iter()
            .filter(|&&idx| entries[idx].mode & S_IFMT == S_IFDIR && entries[idx].name != b".")
            .map(|&idx| (idx, entries[idx].name.clone()))
            .collect();

        let mut pos = 0;
        while pos < queue.len() {
            let (dir_entry_idx, dir_name) = queue[pos].clone();
            pos += 1;

            // Collect direct children using FileEntry::dirname().
            let child_indices: Vec<usize> = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.dirname() == Some(dir_name.as_slice()))
                .map(|(i, _)| i)
                .collect();

            groups.push(DirGroup {
                dir_ndx: dir_flist_ndx[dir_entry_idx],
                entry_indices: child_indices.clone(),
            });

            // Queue child directories and assign their dir_flist indices.
            for &idx in &child_indices {
                if entries[idx].mode & S_IFMT == S_IFDIR {
                    dir_flist_ndx[idx] = dir_counter;
                    dir_counter += 1;
                    queue.push((idx, entries[idx].name.clone()));
                }
            }
        }

        Self { groups }
    }

    /// The root group (top-level entries).
    pub fn root(&self) -> &DirGroup {
        &self.groups[0]
    }

    /// Whether there are subdirectory groups beyond the root.
    pub fn has_subdirs(&self) -> bool {
        self.groups.len() > 1
    }

    /// Consume the tree and return only the non-root groups (for deferred sending).
    pub fn into_pending_groups(self) -> Vec<DirGroup> {
        self.groups.into_iter().skip(1).collect()
    }
}

// Backward-compatible alias for callers that used the old function name.
pub fn group_entries_by_directory(entries: &[FileEntry]) -> Vec<DirGroup> {
    DirectoryTree::from_sorted_entries(entries).groups
}

// ---------------------------------------------------------------------------
// PendingSubFlists -- deferred sub-flist state for sender loop injection
// ---------------------------------------------------------------------------

/// Holds deferred sub-flist groups for injection during the sender loop.
///
/// rsync sends sub-flists interleaved with file data transfer, not all
/// upfront. This struct captures the pending groups (everything after the
/// root sub-flist) and the shared encoder state needed to send them on
/// demand from the sender loop.
pub struct PendingSubFlists {
    /// Groups to send (excludes root group which was already sent).
    groups: Vec<DirGroup>,
    /// Next group index to send.
    cursor: usize,
    /// All entries (for indexing by DirGroup.entry_indices).
    entries: Vec<FileEntry>,
    /// Shared delta state across all sub-flists.
    delta_state: DeltaState,
    /// Shared hard-link encoder.
    hlink_encoder: HardLinkEncoder,
    /// Shared ACL encoder.
    acl_encoder: crate::acl::AclEncoder,
    /// Shared xattr encoder.
    xattr_encoder: crate::xattr::XattrEncoder,
    /// Incremental sender with shared NdxState for markers.
    inc_sender: IncrementalSender,
    /// Wire format options.
    flist_opts: FileListOptions,
    /// Whether NDX_FLIST_EOF has been written.
    eof_sent: bool,
}

impl PendingSubFlists {
    /// Create from remaining groups (everything after root).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        groups: Vec<DirGroup>,
        entries: Vec<FileEntry>,
        delta_state: DeltaState,
        hlink_encoder: HardLinkEncoder,
        acl_encoder: crate::acl::AclEncoder,
        xattr_encoder: crate::xattr::XattrEncoder,
        inc_sender: IncrementalSender,
        flist_opts: FileListOptions,
    ) -> Self {
        Self {
            groups,
            cursor: 0,
            entries,
            delta_state,
            hlink_encoder,
            acl_encoder,
            xattr_encoder,
            inc_sender,
            flist_opts,
            eof_sent: false,
        }
    }

    /// Send pending sub-flists to the writer.
    ///
    /// Sends up to `count` sub-flists. When all groups are exhausted,
    /// writes `NDX_FLIST_EOF`. Matches rsync's `send_extra_file_list()`
    /// pattern where sub-flists are injected during the sender loop.
    pub async fn send_pending<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        count: usize,
    ) -> Result<()> {
        if self.eof_sent {
            return Ok(());
        }

        let mut sent = 0;
        while sent < count && self.cursor < self.groups.len() {
            let group = &self.groups[self.cursor];
            let dir_ndx = group.dir_ndx;

            // Write NDX marker for this sub-flist.
            self.inc_sender
                .write_sub_flist_marker(w, dir_ndx, self.flist_opts.wire.int_codec)
                .await?;

            // Encode entries via the shared helper (eliminates duplication
            // with send_file_list_incremental's root encoding).
            self.inc_sender
                .encode_sub_flist_entries(
                    w,
                    &self.entries,
                    &group.entry_indices,
                    &mut self.delta_state,
                    &self.flist_opts,
                    &mut self.hlink_encoder,
                    &mut self.acl_encoder,
                    &mut self.xattr_encoder,
                )
                .await?;

            self.cursor += 1;
            sent += 1;
        }

        // All groups exhausted -- write EOF.
        if self.cursor >= self.groups.len() && !self.eof_sent {
            self.inc_sender
                .write_flist_eof(w, self.flist_opts.wire.int_codec)
                .await?;
            self.eof_sent = true;
        }

        Ok(())
    }

    /// Whether all sub-flists and EOF have been sent.
    pub fn is_done(&self) -> bool {
        self.eof_sent
    }

    /// Number of sub-flists remaining to send.
    pub fn remaining(&self) -> usize {
        self.groups.len() - self.cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{S_IFDIR, S_IFREG};
    use ferrosync_protocol::wire_format::WireFormat;
    use ferrosync_types::types::{FileSize, UnixTimestamp};
    use std::io::Cursor;

    fn test_opts() -> FileListOptions {
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
    async fn test_incremental_roundtrip() {
        let opts = test_opts();

        let root_entries = vec![
            FileEntry {
                name: b"file.txt".to_vec(),
                len: FileSize(100),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"subdir".to_vec(),
                len: FileSize(0),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
        ];

        let sub_entries = vec![FileEntry {
            name: b"inner.txt".to_vec(),
            len: FileSize(50),
            mtime: UnixTimestamp(1700000001),
            mode: S_IFREG | 0o644,
            ..Default::default()
        }];

        // Encode.
        let mut buf = Vec::new();
        let mut sender = IncrementalSender::default();

        // Send root flist (index 0 = dir for root).
        sender
            .send_sub_flist(&mut buf, 0, &root_entries, &opts)
            .await
            .unwrap();
        // Send sub-flist for directory at index 1.
        sender
            .send_sub_flist(&mut buf, 1, &sub_entries, &opts)
            .await
            .unwrap();
        // EOF.
        sender
            .write_flist_eof(&mut buf, opts.wire.int_codec)
            .await
            .unwrap();

        // Decode.
        let mut cursor = Cursor::new(&buf);
        let mut receiver = IncrementalReceiver::default();

        // Read first marker.
        let ndx = receiver
            .read_ndx_marker(&mut cursor, opts.wire.int_codec)
            .await
            .unwrap();
        assert!(ndx <= NDX_FLIST_OFFSET);
        let dir_ndx = NDX_FLIST_OFFSET - ndx;
        assert_eq!(dir_ndx, 0);

        let sub_flist = receiver
            .recv_sub_flist(&mut cursor, dir_ndx, &opts)
            .await
            .unwrap();
        assert_eq!(sub_flist.entries.len(), 2);
        assert_eq!(sub_flist.entries[0].name, b"file.txt");
        assert_eq!(sub_flist.entries[1].name, b"subdir");

        // Read second marker.
        let ndx = receiver
            .read_ndx_marker(&mut cursor, opts.wire.int_codec)
            .await
            .unwrap();
        let dir_ndx = NDX_FLIST_OFFSET - ndx;
        assert_eq!(dir_ndx, 1);

        let sub_flist = receiver
            .recv_sub_flist(&mut cursor, dir_ndx, &opts)
            .await
            .unwrap();
        assert_eq!(sub_flist.entries.len(), 1);
        assert_eq!(sub_flist.entries[0].name, b"inner.txt");

        // Read EOF.
        let ndx = receiver
            .read_ndx_marker(&mut cursor, opts.wire.int_codec)
            .await
            .unwrap();
        assert_eq!(ndx, NDX_FLIST_EOF);
    }

    #[tokio::test]
    async fn test_ndx_tracking_with_gap() {
        let opts = test_opts();

        let entries = vec![
            FileEntry {
                name: b"a.txt".to_vec(),
                len: FileSize(10),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"b.txt".to_vec(),
                len: FileSize(20),
                mtime: UnixTimestamp(1700000000),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];

        let mut sender = IncrementalSender::default();
        assert_eq!(sender.next_ndx, 0);

        let mut buf = Vec::new();
        sender
            .send_sub_flist(&mut buf, 0, &entries, &opts)
            .await
            .unwrap();
        // 2 entries + 1 gap = 3
        assert_eq!(sender.next_ndx, 3);
    }

    #[test]
    fn test_group_flat_files_only() {
        let entries = vec![
            FileEntry {
                name: b"a.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"b.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];
        let groups = group_entries_by_directory(&entries);
        assert_eq!(groups.len(), 1); // root only
        assert_eq!(groups[0].dir_ndx, -1);
        assert_eq!(groups[0].entry_indices, vec![0, 1]);
    }

    #[test]
    fn test_group_mixed_files_and_dirs() {
        let entries = vec![
            FileEntry {
                name: b"file.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"subdir".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"subdir/inner.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];
        let groups = group_entries_by_directory(&entries);
        assert_eq!(groups.len(), 2); // root + subdir
        assert_eq!(groups[0].entry_indices, vec![0, 1]); // file.txt, subdir
        assert_eq!(groups[1].dir_ndx, 0); // subdir is dir_flist[0] (first directory)
        assert_eq!(groups[1].entry_indices, vec![2]); // inner.txt
    }

    #[test]
    fn test_group_nested_three_levels() {
        let entries = vec![
            FileEntry {
                name: b".".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"a".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"a/b".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"a/b/c.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"top.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];
        let groups = group_entries_by_directory(&entries);
        // root: [., a, top.txt], a: [b], a/b: [c.txt]
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].entry_indices, vec![0, 1, 4]); // ., a, top.txt
        assert_eq!(groups[1].entry_indices, vec![2]); // a/b
        assert_eq!(groups[2].entry_indices, vec![3]); // a/b/c.txt
    }

    #[test]
    fn test_group_empty_directory() {
        let entries = vec![
            FileEntry {
                name: b"empty_dir".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"file.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];
        let groups = group_entries_by_directory(&entries);
        // root: [empty_dir, file.txt], empty_dir: [] (no children)
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].entry_indices, vec![0, 1]);
        assert_eq!(groups[1].entry_indices.len(), 0); // empty subdir group
    }

    #[test]
    fn test_dir_flist_indexing() {
        // Regression test for the bug that caused interop failure:
        // dir_ndx must use dir_flist numbering (directories only), NOT
        // positions in the full entry list.
        let entries = vec![
            FileEntry {
                name: b"file.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"dir_a".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"dir_a/child.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"dir_b".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
        ];
        let tree = DirectoryTree::from_sorted_entries(&entries);
        // Root: [file.txt, dir_a, dir_b]
        assert_eq!(tree.groups.len(), 3); // root + dir_a + dir_b
        assert_eq!(tree.groups[0].entry_indices, vec![0, 1, 3]);

        // dir_a is the first directory -> dir_flist[0]
        assert_eq!(tree.groups[1].dir_ndx, 0);
        assert_eq!(tree.groups[1].entry_indices, vec![2]); // child.txt

        // dir_b is the second directory -> dir_flist[1]
        assert_eq!(tree.groups[2].dir_ndx, 1);
        assert_eq!(tree.groups[2].entry_indices.len(), 0); // empty
    }

    #[test]
    fn test_directory_tree_api() {
        let entries = vec![
            FileEntry {
                name: b"a.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"sub".to_vec(),
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
            FileEntry {
                name: b"sub/b.txt".to_vec(),
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
        ];
        let tree = DirectoryTree::from_sorted_entries(&entries);
        assert!(tree.has_subdirs());
        assert_eq!(tree.root().dir_ndx, -1);
        assert_eq!(tree.root().entry_indices.len(), 2); // a.txt, sub

        let pending = tree.into_pending_groups();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].dir_ndx, 0);
    }
}
