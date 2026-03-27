//! Field visitor pattern for the codec.
//!
//! Defines the canonical field traversal order in a single function
//! (`traverse_fields`) and a `FieldVisitor` trait with one async method
//! per wire field. Three concrete visitors implement the trait:
//!
//! - [`Encoder`] -- writes field values to an `AsyncWrite` sink
//! - [`Decoder`] -- reads field values from an `AsyncRead` source
//! - [`DiagnosticDecoder`] -- reads field values and records byte positions
//!
//! Adding a new wire field requires adding one method to `FieldVisitor`.
//! The compiler forces all three visitors to implement it. Field order
//! is defined once in `traverse_fields` -- divergence is structurally
//! impossible.
//!
//! # Adding a new field
//!
//! 1. Add `encode_X` / `decode_X` to `fields.rs`
//! 2. Add field to `FieldValues`
//! 3. Add `async fn visit_X(...)` to `FieldVisitor` trait
//! 4. Implement `visit_X` in `Encoder`, `Decoder`, and `DiagnosticDecoder`
//! 5. Add the `visitor.visit_X(ctx).await?;` call in `traverse_fields`
//! 6. Update `compute_xmit_flags()` in `flags.rs` if delta-encoded
//! 7. Update `DeltaState` and `update_delta_state()` in `state.rs`

use std::io::Cursor;

use tokio::io::{AsyncRead, AsyncWrite};

use ferrosync_types::entry::{Acl, ExtendedAttributes};
use ferrosync_types::error::ProtocolError;

use super::diagnostic::DecodedField;
use super::fields;
use super::flags::XmitFlags;
use super::options::FileListOptions;
use super::state::DeltaState;
use crate::entry::FileEntry;

type Result<T> = std::result::Result<T, ProtocolError>;

// ---------------------------------------------------------------------------
// FieldValues -- shared mutable accumulator
// ---------------------------------------------------------------------------

/// Mutable accumulator for field values during traversal.
///
/// The encoder populates this from a `FileEntry` before traversal.
/// The decoder populates this during traversal, then constructs a
/// `FileEntry` from it after traversal.
#[derive(Debug, Clone, Default)]
pub struct FieldValues {
    pub wire_name: Vec<u8>,
    pub name: Vec<u8>,
    pub len: i64,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub link_target: Vec<u8>,
    pub checksum: Vec<u8>,
    pub user_name: Vec<u8>,
    pub group_name: Vec<u8>,
    pub raw_flags: u32,
    pub acl: Option<Acl>,
    pub xattrs: Option<ExtendedAttributes>,
    pub hlink_source: Option<Vec<u8>>,
}

impl FieldValues {
    /// Populate from a FileEntry (for encoding).
    pub fn from_entry(entry: &FileEntry, wire_name: Vec<u8>) -> Self {
        Self {
            wire_name,
            name: entry.name.clone(),
            len: entry.len.bytes(),
            mtime: entry.mtime.secs(),
            mtime_nsec: entry.mtime_nsec,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            rdev: entry.rdev,
            link_target: entry.link_target.clone(),
            checksum: entry.checksum.clone(),
            user_name: entry.user_name.clone(),
            group_name: entry.group_name.clone(),
            raw_flags: entry.flags,
            acl: entry.acl.clone(),
            xattrs: entry.xattrs.clone(),
            hlink_source: entry.hlink_source.clone(),
        }
    }

    /// Construct a FileEntry from decoded values.
    pub fn into_entry(self, flags: XmitFlags) -> FileEntry {
        FileEntry {
            name: self.name,
            len: ferrosync_types::types::FileSize(self.len),
            mtime: ferrosync_types::types::UnixTimestamp(self.mtime),
            mtime_nsec: self.mtime_nsec,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            link_target: self.link_target,
            checksum: self.checksum,
            flags: flags.raw(),
            user_name: self.user_name,
            group_name: self.group_name,
            hlink_source: self.hlink_source,
            hard_link_info: None,
            acl: self.acl,
            xattrs: self.xattrs,
        }
    }

    /// Update delta state from these values.
    pub fn update_state(&self, state: &mut DeltaState) {
        state.prev_name.clone_from(&self.name);
        state.prev_mtime = self.mtime;
        state.prev_mode = self.mode;
        state.prev_uid = self.uid;
        state.prev_gid = self.gid;
        state.prev_rdev = self.rdev;
        state.prev_rdev_major = (self.rdev >> 8) as u32;
        state.prev_user_name.clone_from(&self.user_name);
        state.prev_group_name.clone_from(&self.group_name);
    }
}

// ---------------------------------------------------------------------------
// VisitControl -- hlink early-return
// ---------------------------------------------------------------------------

/// Control flow returned by `visit_hlink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisitControl {
    /// Continue with remaining fields.
    Continue,
    /// Abbreviated duplicate -- skip remaining fields.
    Abbreviated,
}

// ---------------------------------------------------------------------------
// FieldContext -- shared context for visitor methods
// ---------------------------------------------------------------------------

/// Context passed to every field visitor method.
pub struct FieldContext<'a> {
    pub flags: XmitFlags,
    pub state: &'a mut DeltaState,
    pub opts: &'a FileListOptions,
    pub values: &'a mut FieldValues,
}

// ---------------------------------------------------------------------------
// FieldVisitor trait
// ---------------------------------------------------------------------------

/// Trait defining the per-field operations for codec traversal.
///
/// Three implementations exist:
/// - `Encoder<W>` writes values to a writer
/// - `Decoder<R>` reads values from a reader
/// - `DiagnosticDecoder` reads values and records byte positions
///
/// Adding a new wire field requires adding one method here. The compiler
/// forces all implementations to provide it.
#[allow(unused_variables, async_fn_in_trait)]
pub trait FieldVisitor {
    async fn visit_len(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_mtime(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_mtime_nsec(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_mode(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_uid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_gid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_rdev(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_symlink(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_checksum(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_acl(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
    async fn visit_xattr(&mut self, ctx: &mut FieldContext<'_>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// traverse_fields -- THE single source of truth for field order
// ---------------------------------------------------------------------------

/// Traverse all metadata fields in the canonical wire order.
///
/// This function defines the field order ONCE. It is called by all three
/// visitors (Encoder, Decoder, DiagnosticDecoder). Adding a field here
/// without implementing it on the trait is a compile error.
///
/// Fields that are handled outside this traversal (flags, filename, hlink)
/// are managed by the encode_entry/decode_entry wrappers because they have
/// special control-flow requirements (end-of-list detection, prefix
/// compression, abbreviated entry early-return).
pub async fn traverse_fields<V: FieldVisitor>(
    visitor: &mut V,
    ctx: &mut FieldContext<'_>,
) -> Result<()> {
    visitor.visit_len(ctx).await?;
    visitor.visit_mtime(ctx).await?;
    visitor.visit_mtime_nsec(ctx).await?;
    visitor.visit_mode(ctx).await?;
    visitor.visit_uid(ctx).await?;
    visitor.visit_gid(ctx).await?;
    visitor.visit_rdev(ctx).await?;
    visitor.visit_symlink(ctx).await?;
    visitor.visit_checksum(ctx).await?;
    visitor.visit_acl(ctx).await?;
    visitor.visit_xattr(ctx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encoder visitor
// ---------------------------------------------------------------------------

/// Encodes field values to an async writer.
///
/// Each `visit_X` reads from `ctx.values` and calls the corresponding
/// `fields::encode_X()` function.
pub struct Encoder<'a, W> {
    pub writer: &'a mut W,
    pub acl_encoder: &'a mut crate::acl::AclEncoder,
    pub xattr_encoder: &'a mut crate::xattr::XattrEncoder,
}

impl<W: AsyncWrite + Unpin> FieldVisitor for Encoder<'_, W> {
    async fn visit_len(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_file_length(&mut self.writer, ctx.values.len, ctx.opts).await
    }

    async fn visit_mtime(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_mtime(&mut self.writer, ctx.values.mtime, ctx.flags, ctx.opts).await
    }

    async fn visit_mtime_nsec(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_mtime_nsec(&mut self.writer, ctx.values.mtime_nsec, ctx.flags, ctx.opts)
            .await
    }

    async fn visit_mode(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_mode(&mut self.writer, ctx.values.mode, ctx.flags).await
    }

    async fn visit_uid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_uid(
            &mut self.writer,
            ctx.values.uid,
            &ctx.values.user_name,
            ctx.flags,
            ctx.opts,
        )
        .await
    }

    async fn visit_gid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_gid(
            &mut self.writer,
            ctx.values.gid,
            &ctx.values.group_name,
            ctx.flags,
            ctx.opts,
        )
        .await
    }

    async fn visit_rdev(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let entry_rdev_major = (ctx.values.rdev >> 8) as u32;
        let entry_rdev_minor = (ctx.values.rdev & 0xFF) as u32;
        fields::encode_rdev(
            &mut self.writer,
            ctx.values.mode,
            ctx.values.rdev,
            entry_rdev_major,
            entry_rdev_minor,
            ctx.flags,
            ctx.opts,
        )
        .await
    }

    async fn visit_symlink(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_symlink(
            &mut self.writer,
            ctx.values.mode,
            &ctx.values.link_target,
            ctx.opts,
        )
        .await
    }

    async fn visit_checksum(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        fields::encode_checksum(
            &mut self.writer,
            ctx.values.mode,
            &ctx.values.checksum,
            ctx.opts,
        )
        .await
    }

    async fn visit_acl(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let is_symlink = (ctx.values.mode & crate::entry::S_IFMT) == crate::entry::WIRE_S_IFLNK;
        if ctx.opts.preserve_acls && !is_symlink {
            crate::acl::encode_acl(
                &mut self.writer,
                &ctx.values.acl,
                ctx.values.mode,
                self.acl_encoder,
            )
            .await?;
        }
        Ok(())
    }

    async fn visit_xattr(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        if ctx.opts.preserve_xattrs {
            crate::xattr::encode_xattrs(&mut self.writer, &ctx.values.xattrs, self.xattr_encoder)
                .await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Decoder visitor
// ---------------------------------------------------------------------------

/// Decodes field values from an async reader.
///
/// Each `visit_X` calls the corresponding `fields::decode_X()` function
/// and writes the result to `ctx.values`.
pub struct Decoder<'a, R> {
    pub reader: &'a mut R,
    pub acl_decoder: &'a mut crate::acl::AclDecoder,
    pub xattr_decoder: &'a mut crate::xattr::XattrDecoder,
}

impl<R: AsyncRead + Unpin> FieldVisitor for Decoder<'_, R> {
    async fn visit_len(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.len = fields::decode_file_length(&mut self.reader, ctx.opts).await?;
        Ok(())
    }

    async fn visit_mtime(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.mtime =
            fields::decode_mtime(&mut self.reader, ctx.state, ctx.flags, ctx.opts).await?;
        Ok(())
    }

    async fn visit_mtime_nsec(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.mtime_nsec =
            fields::decode_mtime_nsec(&mut self.reader, ctx.flags, ctx.opts).await?;
        Ok(())
    }

    async fn visit_mode(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.mode = fields::decode_mode(&mut self.reader, ctx.state, ctx.flags).await?;
        Ok(())
    }

    async fn visit_uid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let (uid, user_name) =
            fields::decode_uid(&mut self.reader, ctx.state, ctx.flags, ctx.opts).await?;
        ctx.values.uid = uid;
        ctx.values.user_name = user_name;
        Ok(())
    }

    async fn visit_gid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let (gid, group_name) =
            fields::decode_gid(&mut self.reader, ctx.state, ctx.flags, ctx.opts).await?;
        ctx.values.gid = gid;
        ctx.values.group_name = group_name;
        Ok(())
    }

    async fn visit_rdev(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.rdev = fields::decode_rdev(
            &mut self.reader,
            ctx.values.mode,
            ctx.state,
            ctx.flags,
            ctx.opts,
        )
        .await?;
        Ok(())
    }

    async fn visit_symlink(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.link_target =
            fields::decode_symlink(&mut self.reader, ctx.values.mode, ctx.opts).await?;
        Ok(())
    }

    async fn visit_checksum(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.checksum =
            fields::decode_checksum(&mut self.reader, ctx.values.mode, ctx.opts).await?;
        Ok(())
    }

    async fn visit_acl(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let is_symlink = (ctx.values.mode & crate::entry::S_IFMT) == crate::entry::WIRE_S_IFLNK;
        ctx.values.acl = if ctx.opts.preserve_acls && !is_symlink {
            crate::acl::decode_acl(&mut self.reader, ctx.values.mode, self.acl_decoder).await?
        } else {
            None
        };
        Ok(())
    }

    async fn visit_xattr(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        ctx.values.xattrs = if ctx.opts.preserve_xattrs {
            crate::xattr::decode_xattrs(&mut self.reader, self.xattr_decoder).await?
        } else {
            None
        };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DiagnosticDecoder visitor
// ---------------------------------------------------------------------------

/// Decodes field values from a byte buffer and records byte positions.
///
/// Used by wire conformance tests to compare our encoding against rsync's
/// output at the field level. Each `visit_X` creates a `Cursor` over the
/// remaining data, calls `fields::decode_X()`, measures consumed bytes,
/// and pushes a `DecodedField`.
pub struct DiagnosticDecoder<'a> {
    pub data: &'a [u8],
    pub offset: usize,
    pub fields: Vec<DecodedField>,
}

impl DiagnosticDecoder<'_> {
    /// Record a decoded field with byte position tracking.
    pub fn record(&mut self, name: &'static str, consumed: usize, start: usize, value: String) {
        if consumed > 0 {
            self.fields.push(DecodedField {
                name,
                offset: start,
                length: consumed,
                raw_bytes: self.data[start..start + consumed].to_vec(),
                decoded_value: value,
            });
        }
        self.offset += consumed;
    }

    /// Create a cursor at the current offset.
    fn cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(&self.data[self.offset..])
    }
}

impl FieldVisitor for DiagnosticDecoder<'_> {
    async fn visit_len(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_file_length(&mut c, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record("file_length", consumed, start, format!("{v}"));
        ctx.values.len = v;
        Ok(())
    }

    async fn visit_mtime(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_mtime(&mut c, ctx.state, ctx.flags, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record("mtime", consumed, start, format!("{v}"));
        ctx.values.mtime = v;
        Ok(())
    }

    async fn visit_mtime_nsec(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_mtime_nsec(&mut c, ctx.flags, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record("mtime_nsec", consumed, start, format!("{v}"));
        ctx.values.mtime_nsec = v;
        Ok(())
    }

    async fn visit_mode(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_mode(&mut c, ctx.state, ctx.flags).await?;
        let consumed = c.position() as usize;
        self.record("mode", consumed, start, format!("0o{v:06o}"));
        ctx.values.mode = v;
        Ok(())
    }

    async fn visit_uid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let (uid, user_name) = fields::decode_uid(&mut c, ctx.state, ctx.flags, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record(
            "uid",
            consumed,
            start,
            format!("{uid} ({})", String::from_utf8_lossy(&user_name)),
        );
        ctx.values.uid = uid;
        ctx.values.user_name = user_name;
        Ok(())
    }

    async fn visit_gid(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let (gid, group_name) =
            fields::decode_gid(&mut c, ctx.state, ctx.flags, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record(
            "gid",
            consumed,
            start,
            format!("{gid} ({})", String::from_utf8_lossy(&group_name)),
        );
        ctx.values.gid = gid;
        ctx.values.group_name = group_name;
        Ok(())
    }

    async fn visit_rdev(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v =
            fields::decode_rdev(&mut c, ctx.values.mode, ctx.state, ctx.flags, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record("rdev", consumed, start, format!("{v}"));
        ctx.values.rdev = v;
        Ok(())
    }

    async fn visit_symlink(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_symlink(&mut c, ctx.values.mode, ctx.opts).await?;
        let consumed = c.position() as usize;
        self.record(
            "symlink_target",
            consumed,
            start,
            String::from_utf8_lossy(&v).to_string(),
        );
        ctx.values.link_target = v;
        Ok(())
    }

    async fn visit_checksum(&mut self, ctx: &mut FieldContext<'_>) -> Result<()> {
        let start = self.offset;
        let mut c = self.cursor();
        let v = fields::decode_checksum(&mut c, ctx.values.mode, ctx.opts).await?;
        let consumed = c.position() as usize;
        let hex_str: String = v.iter().map(|b| format!("{b:02x}")).collect();
        self.record("checksum", consumed, start, hex_str);
        ctx.values.checksum = v;
        Ok(())
    }

    async fn visit_acl(&mut self, _ctx: &mut FieldContext<'_>) -> Result<()> {
        // ACL diagnostic decoding is not field-level tracked in the current
        // wire conformance tests. Skip for now.
        Ok(())
    }

    async fn visit_xattr(&mut self, _ctx: &mut FieldContext<'_>) -> Result<()> {
        // Xattr diagnostic decoding is not field-level tracked in the current
        // wire conformance tests. Skip for now.
        Ok(())
    }
}
