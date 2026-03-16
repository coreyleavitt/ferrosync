use std::path::PathBuf;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Protocol errors
// ---------------------------------------------------------------------------

/// Errors originating from rsync wire-protocol encoding/decoding.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version {version} (supported: {min}..={max})")]
    UnsupportedVersion { version: u8, min: u8, max: u8 },

    #[error("protocol version negotiation failed: local={local}, remote={remote}")]
    NegotiationFailed { local: u8, remote: u8 },

    #[error("invalid multiplex tag {tag:#x}")]
    InvalidMplexTag { tag: u32 },

    #[error("multiplex frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u32, max: u32 },

    #[error("unexpected message type: {msg_type}")]
    UnexpectedMessageType { msg_type: u8 },

    #[error("invalid varint encoding")]
    InvalidVarint,

    #[error("wire value out of range: {field} = {value} (max {max})")]
    WireValueOutOfRange {
        field: &'static str,
        value: i64,
        max: i64,
    },

    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("unsupported checksum algorithm: {algorithm}")]
    UnsupportedChecksum { algorithm: String },

    #[error("unsupported compression algorithm: {algorithm}")]
    UnsupportedCompression { algorithm: String },

    #[error("handshake error: {message}")]
    Handshake { message: String },

    #[error("protocol I/O error: {0}")]
    Io(Arc<std::io::Error>),
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

// ---------------------------------------------------------------------------
// Transport errors
// ---------------------------------------------------------------------------

/// Errors from the transport layer (local subprocess, SSH, daemon).
#[derive(Debug, Clone, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("remote process exited with code {code}")]
    RemoteExit { code: i32 },

    #[error("remote process exited with signal")]
    RemoteSignal,

    #[error("authentication failed: {message}")]
    AuthFailed { message: String },

    #[error("daemon module not found: {module}")]
    ModuleNotFound { module: String },

    #[error("command not found: {command}")]
    CommandNotFound { command: String },

    #[error("host key verification failed for {host}")]
    HostKeyMismatch { host: String },

    #[error("host key not found for {host} (strict mode)")]
    HostKeyNotFound { host: String },

    #[error("transport I/O error: {0}")]
    Io(Arc<std::io::Error>),
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

// ---------------------------------------------------------------------------
// Filesystem errors
// ---------------------------------------------------------------------------

/// Errors from filesystem operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FsError {
    #[error("path not found: {path}")]
    NotFound { path: PathBuf },

    #[error("permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    #[error("not a directory: {path}")]
    NotADirectory { path: PathBuf },

    #[error("symlink loop detected: {path}")]
    SymlinkLoop { path: PathBuf },

    #[error("path outside transfer root: {path}")]
    PathTraversal { path: PathBuf },

    #[error("unsupported file type at {path}: {file_type}")]
    UnsupportedFileType { path: PathBuf, file_type: String },

    #[error("filesystem I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: Arc<std::io::Error>,
    },
}

// ---------------------------------------------------------------------------
// Filter errors
// ---------------------------------------------------------------------------

/// Errors from filter/exclude/include rule processing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FilterError {
    #[error("invalid filter rule: {rule}")]
    InvalidRule { rule: String },

    #[error("failed to read filter file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: Arc<std::io::Error>,
    },

    #[error("invalid glob pattern: {pattern}: {message}")]
    InvalidPattern { pattern: String, message: String },
}

// ---------------------------------------------------------------------------
// Top-level error
// ---------------------------------------------------------------------------

/// Top-level error type composing all subsystem errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FerrosyncError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    Fs(#[from] FsError),

    #[error(transparent)]
    Filter(#[from] FilterError),
}
