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

use crate::error::ProtocolError;
use crate::protocol::varint::{self, NdxState};
use crate::protocol::wire_format::IntCodec;

use super::codec::{
    recv_file_entry, send_file_entry, write_end_of_flist, DeltaState, FileListOptions,
    HardLinkDecoder, HardLinkEncoder, ReadEntryResult,
};
use super::entry::FileEntry;

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

        loop {
            match recv_file_entry(r, delta_state, opts, &mut hlink_decoder, &entries, None).await? {
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

    /// Send a complete sub-file-list.
    ///
    /// Writes all entries followed by the end-of-list marker.
    pub async fn send_sub_flist<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        dir_ndx: i32,
        entries: &[FileEntry],
        opts: &FileListOptions,
    ) -> Result<()> {
        // Write the sub-flist marker.
        self.write_sub_flist_marker(w, dir_ndx, opts.wire.int_codec)
            .await?;

        // Write entries. Entry indices must be absolute NDX values (not
        // 0-based) so hardlink back-references point to the correct entry
        // in rsync's receiver. self.next_ndx tracks the current absolute NDX.
        let mut delta_state = DeltaState::default();
        let mut hlink_encoder = HardLinkEncoder::new();
        let ndx_start = self.next_ndx;
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
            )
            .await?;
            self.next_ndx += 1;
        }

        // Write end-of-list.
        write_end_of_flist(w, 0, opts).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filelist::entry::{S_IFDIR, S_IFREG};
    use crate::protocol::wire_format::WireFormat;
    use std::io::Cursor;

    fn test_opts() -> FileListOptions {
        FileListOptions {
            wire: WireFormat::new(
                31,
                crate::protocol::handshake::compat_flags::VARINT_FLIST_FLAGS
                    | crate::protocol::handshake::compat_flags::INC_RECURSE,
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
                len: 100,
                mtime: 1700000000,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"subdir".to_vec(),
                len: 0,
                mtime: 1700000000,
                mode: S_IFDIR | 0o755,
                ..Default::default()
            },
        ];

        let sub_entries = vec![FileEntry {
            name: b"inner.txt".to_vec(),
            len: 50,
            mtime: 1700000001,
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
    async fn test_ndx_tracking() {
        let opts = test_opts();

        let entries = vec![
            FileEntry {
                name: b"a.txt".to_vec(),
                len: 10,
                mtime: 1700000000,
                mode: S_IFREG | 0o644,
                ..Default::default()
            },
            FileEntry {
                name: b"b.txt".to_vec(),
                len: 20,
                mtime: 1700000000,
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
        assert_eq!(sender.next_ndx, 2);
    }
}
