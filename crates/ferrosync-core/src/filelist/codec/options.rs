//! Transfer options that affect the file list wire format.

use crate::protocol::wire_format::WireFormat;

/// Options that control which fields are present in the file list wire format.
#[derive(Debug, Clone)]
pub struct FileListOptions {
    /// Wire format descriptor capturing version-dependent encoding choices.
    pub wire: WireFormat,
    /// True if uid is preserved (-o).
    pub preserve_uid: bool,
    /// True if gid is preserved (-g).
    pub preserve_gid: bool,
    /// True if device files are preserved (--devices).
    pub preserve_devices: bool,
    /// True if special files are preserved (--specials).
    pub preserve_specials: bool,
    /// True if symlinks are preserved (-l).
    pub preserve_links: bool,
    /// True if hard links are preserved (-H).
    pub preserve_hard_links: bool,
    /// True if always computing checksums (-c).
    pub always_checksum: bool,
    /// Length of the file-level checksum (typically 16 for MD4/MD5).
    pub checksum_len: usize,
    /// Whether to send/expect uid 0/gid 0 name entries after the id list
    /// terminator (compat_flags & ID0_NAMES).
    pub xmit_id0_names: bool,
    /// True if `--numeric-ids` is active. When set, uid/gid name lists
    /// are not exchanged on the wire.
    pub numeric_ids: bool,
}

impl Default for FileListOptions {
    fn default() -> Self {
        Self {
            wire: WireFormat::new(
                31,
                crate::protocol::handshake::compat_flags::VARINT_FLIST_FLAGS
                    | crate::protocol::handshake::compat_flags::INC_RECURSE,
            ),
            preserve_uid: false,
            preserve_gid: false,
            preserve_devices: false,
            preserve_specials: false,
            preserve_links: false,
            preserve_hard_links: false,
            always_checksum: false,
            checksum_len: 16,
            xmit_id0_names: true,
            numeric_ids: false,
        }
    }
}

impl FileListOptions {
    /// Create codec options from a negotiated protocol and transfer options.
    ///
    /// This bridges the handshake output to the file list codec, ensuring
    /// protocol version-specific behavior is correctly applied.
    pub fn from_protocol(
        proto: &crate::protocol::handshake::NegotiatedProtocol,
        opts: &crate::options::TransferConfig,
    ) -> Self {
        Self {
            wire: proto.wire().clone(),
            preserve_uid: opts.preserve_owner(),
            preserve_gid: opts.preserve_group() || opts.preserve_owner(),
            preserve_devices: opts.preserve_devices(),
            preserve_specials: opts.preserve_specials(),
            preserve_links: opts.preserve_links(),
            preserve_hard_links: opts.preserve_hard_links(),
            always_checksum: opts.checksum_mode(),
            checksum_len: proto.checksum.digest_len(),
            xmit_id0_names: proto.compat_flags()
                & crate::protocol::handshake::compat_flags::ID0_NAMES
                != 0,
            numeric_ids: opts.numeric_ids(),
        }
    }

    /// Create codec options from a negotiated protocol and transfer options.
    ///
    /// Alias for [`from_protocol`] for backward compatibility.
    pub fn from_protocol_legacy(
        proto: &crate::protocol::handshake::NegotiatedProtocol,
        opts: &crate::options::TransferOptions,
    ) -> Self {
        Self::from_protocol(proto, opts)
    }
}
