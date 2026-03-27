//! Version-dependent wire format decisions, resolved once at handshake time.
//!
//! All encoding, field-presence, and behavioral differences between protocol
//! versions 27-31 are captured here. Codec and transfer code matches on
//! `WireFormat` fields -- raw version numbers never escape the handshake.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use ferrosync_types::protocol::{DeviceCodec, FlagsCodec, IntCodec};

use crate::handshake::compat_flags;
use crate::multiplex::MplexWriter;
use crate::varint;
use ferrosync_types::error::ProtocolError;
use ferrosync_types::stats::TransferStats;

/// All version-dependent wire format decisions, resolved at handshake time.
///
/// Constructed once from `(version, compat_flags)` at the end of the
/// handshake. Adding a new protocol version means updating `WireFormat::new`;
/// the compiler enforces exhaustive matching on any new enum variants.
#[derive(Debug, Clone)]
pub struct WireFormat {
    // -- Encoding --
    /// Integer/varint encoding strategy.
    pub int_codec: IntCodec,
    /// XMIT flag encoding in file list entries.
    pub flags_codec: FlagsCodec,
    /// Device number encoding.
    pub device_codec: DeviceCodec,

    // -- Field presence --
    /// Proto >= 30: uid/gid carry inline username/group strings.
    pub has_inline_names: bool,
    /// Proto >= 31: mtime_nsec field present in file entries.
    pub has_nanoseconds: bool,
    /// Proto < 31: special files carry rdev.
    pub special_rdev: bool,

    // -- Behavior --
    /// Number of transfer phases: 1 (< 29) or 2 (>= 29).
    pub phase_count: u8,
    /// Proto >= 29: iflags sent alongside NDX in sender/receiver loops.
    pub has_iflags: bool,
    /// Proto >= 31: extra NDX_DONE goodbye exchange.
    pub has_error_exit_sync: bool,
    /// Proto >= 30 + CF_INC_RECURSE: incremental recursive file list.
    pub supports_incremental_flist: bool,
    /// Proto < 30: io_error sent after end-of-list marker.
    pub trailing_io_error: bool,

    // -- Diagnostics only --
    /// Kept for handshake logging and error messages. Not for branching.
    #[allow(dead_code)]
    pub negotiated_version: u8,
}

impl WireFormat {
    /// Resolve all wire format decisions from the negotiated version and
    /// compatibility flags. This is the **only** place that knows about
    /// raw protocol version numbers.
    pub fn new(version: u8, compat_flags: u32) -> Self {
        let varint_flist = compat_flags & compat_flags::VARINT_FLIST_FLAGS != 0;

        Self {
            int_codec: if version >= 30 {
                IntCodec::Compact
            } else {
                IntCodec::Fixed
            },
            flags_codec: if varint_flist {
                FlagsCodec::Varint
            } else if version >= 28 {
                FlagsCodec::ByteExtended
            } else {
                FlagsCodec::Byte
            },
            device_codec: if version < 28 {
                DeviceCodec::SingleInt
            } else {
                DeviceCodec::MajorMinor {
                    varint_minor: version >= 30,
                }
            },
            has_inline_names: version >= 30,
            has_nanoseconds: version >= 31,
            special_rdev: version < 31,
            phase_count: if version >= 29 { 2 } else { 1 },
            has_iflags: version >= 29,
            has_error_exit_sync: version >= 31,
            supports_incremental_flist: version >= 30
                && (compat_flags & compat_flags::INC_RECURSE != 0),
            trailing_io_error: version < 30,
            negotiated_version: version,
        }
    }

    // -----------------------------------------------------------------
    // iflags helpers
    // -----------------------------------------------------------------

    /// Read iflags + optional trailing fields (basis_type, xname) from
    /// a sender/generator response. Returns the iflags value, or 0 if
    /// the protocol version predates iflags.
    pub async fn read_iflags<R: AsyncRead + Unpin>(
        &self,
        r: &mut R,
    ) -> std::result::Result<u16, ProtocolError> {
        if !self.has_iflags {
            return Ok(0);
        }
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).await?;
        let iflags = u16::from_le_bytes(buf);
        // ITEM_BASIS_TYPE_FOLLOWS (1<<11 = 0x0800)
        if iflags & 0x0800 != 0 {
            let mut bt = [0u8; 1];
            r.read_exact(&mut bt).await?;
        }
        // ITEM_XNAME_FOLLOWS (1<<12 = 0x1000)
        if iflags & 0x1000 != 0 {
            let name_len = varint::read_varint(r).await?;
            if name_len > 0x10000 {
                return Err(ProtocolError::WireValueOutOfRange {
                    field: "xname_len",
                    value: name_len as i64,
                    max: 0x10000,
                });
            }
            let mut name_buf = vec![0u8; name_len as usize];
            r.read_exact(&mut name_buf).await?;
        }
        Ok(iflags)
    }

    /// Write iflags value. No-op if the protocol predates iflags.
    pub async fn write_iflags<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        iflags: u16,
    ) -> std::result::Result<(), ProtocolError> {
        if !self.has_iflags {
            return Ok(());
        }
        varint::write_shortint(w, iflags).await?;
        Ok(())
    }

    /// Write an echo response for non-transfer iflags (hardlink duplicate,
    /// up-to-date file). Echoes iflags + empty basis_type and xname when
    /// those trailing fields are flagged.
    pub async fn write_iflags_echo<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        iflags: u16,
    ) -> std::result::Result<(), ProtocolError> {
        if !self.has_iflags {
            return Ok(());
        }
        varint::write_shortint(w, iflags).await?;
        if iflags & 0x0800 != 0 {
            w.write_all(&[0]).await?; // empty basis_type
        }
        if iflags & 0x1000 != 0 {
            varint::write_varint(w, 0).await?; // empty xname
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Stats helpers
    // -----------------------------------------------------------------

    /// Write transfer stats (3 or 5 varlong30 values depending on version).
    pub async fn write_stats<W: AsyncWrite + Unpin + Send>(
        &self,
        mplex_out: &mut MplexWriter<W>,
        stats: &TransferStats,
    ) -> std::result::Result<(), ProtocolError> {
        let codec = self.int_codec;
        let mut buf = Vec::new();
        varint::write_varlong30(&mut buf, 0, 3, codec).await?;
        varint::write_varlong30(&mut buf, stats.bytes_sent as i64, 3, codec).await?;
        varint::write_varlong30(&mut buf, stats.total_size as i64, 3, codec).await?;
        if self.has_iflags {
            varint::write_varlong30(&mut buf, 0, 3, codec).await?;
            varint::write_varlong30(&mut buf, 0, 3, codec).await?;
        }
        mplex_out.write_data(&buf).await?;
        mplex_out.flush().await?;
        Ok(())
    }

    /// Read transfer stats from the sender (3 or 5 varlong30 values).
    pub async fn read_stats<R: AsyncRead + Unpin + Send>(
        &self,
        demux_read: &mut R,
    ) -> std::result::Result<(), ProtocolError> {
        let codec = self.int_codec;
        let _total_read = varint::read_varlong30(demux_read, 3, codec).await?;
        let _total_written = varint::read_varlong30(demux_read, 3, codec).await?;
        let _total_size = varint::read_varlong30(demux_read, 3, codec).await?;
        if self.has_iflags {
            let _flist_buildtime = varint::read_varlong30(demux_read, 3, codec).await?;
            let _flist_xfertime = varint::read_varlong30(demux_read, 3, codec).await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Goodbye helpers
    // -----------------------------------------------------------------

    /// Sender goodbye exchange (proto >= 24).
    ///
    /// C ref: read_final_goodbye (main.c:875-905)
    ///
    /// For proto >= 31 the receiver sends an NDX_DONE, the sender
    /// acknowledges with its own NDX_DONE, then reads one more NDX_DONE
    /// (error-exit sync). For proto 24-30, just reads the final NDX_DONE.
    pub async fn sender_goodbye<R, W>(
        &self,
        demux_read: &mut R,
        mplex_out: &mut MplexWriter<W>,
    ) -> std::result::Result<(), ProtocolError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let codec = self.int_codec;
        let mut read_state = varint::NdxState::default();
        let mut write_state = varint::NdxState::default();

        if self.has_error_exit_sync {
            let _ = varint::read_ndx(demux_read, &mut read_state, codec).await;
            write_goodbye_done(mplex_out, &mut write_state, codec).await;
            let _ = varint::read_ndx(demux_read, &mut read_state, codec).await;
        } else {
            let _ = varint::read_ndx(demux_read, &mut read_state, codec).await;
        }
        Ok(())
    }

    /// Receiver goodbye exchange (proto >= 24).
    ///
    /// Sends goodbye NDX_DONEs that the sender expects to read.
    pub async fn receiver_goodbye<R, W>(
        &self,
        demux_read: &mut R,
        mplex_out: &mut MplexWriter<W>,
    ) -> std::result::Result<(), ProtocolError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let codec = self.int_codec;
        let mut gen_ndx_state = varint::NdxState::default();
        let mut recv_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut gen_ndx_state, codec).await;
        let _ = varint::read_ndx(demux_read, &mut recv_ndx_state, codec).await;
        write_goodbye_done(mplex_out, &mut gen_ndx_state, codec).await;

        if self.has_error_exit_sync {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, codec).await;
        }
        Ok(())
    }

    /// Server-side sender goodbye exchange (proto >= 24).
    ///
    /// The server sender writes a goodbye NDX_DONE and reads goodbyes
    /// from the receiver.
    pub async fn server_sender_goodbye<R, W>(
        &self,
        demux_read: &mut R,
        mplex_out: &mut MplexWriter<W>,
    ) -> std::result::Result<(), ProtocolError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let codec = self.int_codec;
        let mut send_ndx_state = varint::NdxState::default();
        let mut gen_ndx_state = varint::NdxState::default();

        write_goodbye_done(mplex_out, &mut send_ndx_state, codec).await;

        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, codec).await;
        let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, codec).await;
        if self.has_error_exit_sync {
            let _ = varint::read_ndx(demux_read, &mut gen_ndx_state, codec).await;
        }
        Ok(())
    }

    /// Server-side receiver goodbye exchange (proto >= 24).
    pub async fn server_receiver_goodbye<W: AsyncWrite + Unpin + Send>(
        &self,
        mplex_out: &mut MplexWriter<W>,
    ) -> std::result::Result<(), ProtocolError> {
        let codec = self.int_codec;
        let mut gen_ndx_state = varint::NdxState::default();
        write_goodbye_done(mplex_out, &mut gen_ndx_state, codec).await;
        if self.has_error_exit_sync {
            write_goodbye_done(mplex_out, &mut gen_ndx_state, codec).await;
        }
        Ok(())
    }
}

/// Write a best-effort NDX_DONE to the MUX output.
///
/// Used during goodbye exchanges where the remote may have already
/// disconnected. Errors are silently ignored.
async fn write_goodbye_done<W: AsyncWrite + Unpin>(
    out: &mut MplexWriter<W>,
    st: &mut varint::NdxState,
    codec: IntCodec,
) {
    let mut buf = Vec::new();
    let _ = varint::write_ndx(&mut buf, varint::NDX_DONE, st, codec).await;
    let _ = out.write_data(&buf).await;
    let _ = out.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto27_all_fixed() {
        let wf = WireFormat::new(27, 0);
        assert_eq!(wf.int_codec, IntCodec::Fixed);
        assert_eq!(wf.flags_codec, FlagsCodec::Byte);
        assert_eq!(wf.device_codec, DeviceCodec::SingleInt);
        assert!(!wf.has_inline_names);
        assert!(!wf.has_nanoseconds);
        assert!(wf.special_rdev);
        assert_eq!(wf.phase_count, 1);
        assert!(!wf.has_iflags);
        assert!(!wf.has_error_exit_sync);
        assert!(!wf.supports_incremental_flist);
        assert!(wf.trailing_io_error);
    }

    #[test]
    fn proto28_extended_flags_and_major_minor() {
        let wf = WireFormat::new(28, 0);
        assert_eq!(wf.int_codec, IntCodec::Fixed);
        assert_eq!(wf.flags_codec, FlagsCodec::ByteExtended);
        assert_eq!(
            wf.device_codec,
            DeviceCodec::MajorMinor {
                varint_minor: false
            }
        );
        assert_eq!(wf.phase_count, 1);
        assert!(!wf.has_iflags);
    }

    #[test]
    fn proto29_iflags_and_two_phases() {
        let wf = WireFormat::new(29, 0);
        assert_eq!(wf.phase_count, 2);
        assert!(wf.has_iflags);
        assert!(!wf.has_error_exit_sync);
    }

    #[test]
    fn proto30_compact_with_varint_flist() {
        let flags = compat_flags::VARINT_FLIST_FLAGS | compat_flags::INC_RECURSE;
        let wf = WireFormat::new(30, flags);
        assert_eq!(wf.int_codec, IntCodec::Compact);
        assert_eq!(wf.flags_codec, FlagsCodec::Varint);
        assert_eq!(
            wf.device_codec,
            DeviceCodec::MajorMinor { varint_minor: true }
        );
        assert!(wf.has_inline_names);
        assert!(!wf.has_nanoseconds);
        assert!(wf.special_rdev);
        assert!(wf.supports_incremental_flist);
        assert!(!wf.trailing_io_error);
    }

    #[test]
    fn proto30_without_inc_recurse() {
        let flags = compat_flags::VARINT_FLIST_FLAGS;
        let wf = WireFormat::new(30, flags);
        assert!(!wf.supports_incremental_flist);
    }

    #[test]
    fn proto31_nanoseconds_and_goodbye() {
        let flags = compat_flags::VARINT_FLIST_FLAGS | compat_flags::INC_RECURSE;
        let wf = WireFormat::new(31, flags);
        assert!(wf.has_nanoseconds);
        assert!(!wf.special_rdev);
        assert!(wf.has_error_exit_sync);
        assert_eq!(wf.phase_count, 2);
    }
}
