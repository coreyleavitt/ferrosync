//! Local subprocess transport.
//!
//! Spawns `rsync --server` as a child process and communicates via
//! stdin (our write) / stdout (our read) pipes. Used for local-to-local
//! transfers where the other side is a real rsync binary.

use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Spawns a local `rsync --server` subprocess.
pub struct LocalTransport {
    /// Path to the rsync binary.
    rsync_path: String,
    /// Arguments to pass to `rsync --server`.
    args: Vec<String>,
    /// Working directory for the subprocess.
    cwd: Option<std::path::PathBuf>,
}

impl LocalTransport {
    /// Create a new local transport.
    ///
    /// - `rsync_path`: path to the rsync binary (defaults to "rsync").
    /// - `am_sender`: if true, we are sending to the remote (remote is receiver).
    /// - `options`: the server-mode option string (e.g., "-logDtprze.iLsfxCIvu").
    /// - `path`: the source or destination path. For server mode, rsync requires
    ///   relative paths; the CWD is set to the parent directory.
    pub fn new(rsync_path: Option<&str>, am_sender: bool, options: &str, path: &Path) -> Self {
        let mut args = vec!["--server".to_string()];
        if !am_sender {
            // We are receiving: the remote should be the sender.
            args.push("--sender".to_string());
        }
        args.push(options.to_string());
        args.push(".".to_string());

        // rsync --server rejects absolute paths. Use "." and set CWD instead.
        let cwd = if path.is_absolute() {
            args.push(".".to_string());
            Some(path.to_path_buf())
        } else {
            args.push(path.display().to_string());
            None
        };

        Self {
            rsync_path: rsync_path.unwrap_or("rsync").to_string(),
            args,
            cwd,
        }
    }

    /// Create a transport from raw args (for testing or custom invocations).
    pub fn with_args(rsync_path: &str, args: Vec<String>) -> Self {
        Self {
            rsync_path: rsync_path.to_string(),
            args,
            cwd: None,
        }
    }
}

impl Transport for LocalTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let mut cmd = Command::new(&self.rsync_path);
            cmd.args(&self.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            if let Some(ref cwd) = self.cwd {
                cmd.current_dir(cwd);
            }

            let mut child = cmd.spawn().map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TransportError::CommandNotFound {
                        command: self.rsync_path.clone(),
                    }
                } else {
                    TransportError::ConnectionFailed {
                        message: format!("failed to spawn {}: {e}", self.rsync_path),
                    }
                }
            })?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| TransportError::ConnectionFailed {
                    message: "failed to open stdin pipe".to_string(),
                })?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| TransportError::ConnectionFailed {
                    message: "failed to open stdout pipe".to_string(),
                })?;

            // Spawn a background task to reap the child process and capture stderr.
            let monitor_handle = tokio::spawn(monitor_child(child));

            Ok(TransportStreams {
                reader: Box::new(stdout),
                writer: Box::new(stdin),
                background_task: Some(monitor_handle),
            })
        })
    }
}

/// Monitor the child process in the background, logging stderr on exit.
async fn monitor_child(mut child: Child) {
    let status = child.wait().await;
    match status {
        Ok(s) if s.success() => {
            tracing::debug!("rsync subprocess exited successfully");
        }
        Ok(s) => {
            // Read any stderr output for diagnostics.
            let stderr = if let Some(mut stderr) = child.stderr.take() {
                let mut buf = String::new();
                use tokio::io::AsyncReadExt;
                let _ = stderr.read_to_string(&mut buf).await;
                buf
            } else {
                String::new()
            };
            eprintln!(
                "[rsync] exit code={:?}, stderr: {}",
                s.code(),
                stderr.trim()
            );
            tracing::warn!(
                code = s.code(),
                stderr = %stderr.trim(),
                "rsync subprocess exited with non-zero status"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to wait for rsync subprocess");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)] // Uses Unix absolute paths
    fn test_local_transport_args_sender() {
        let t = LocalTransport::new(
            None,
            true, // we are sender, remote is receiver
            "-logDtprze.iLsfxCIvu",
            Path::new("/tmp/dest"),
        );
        assert_eq!(t.rsync_path, "rsync");
        assert_eq!(t.args[0], "--server");
        // When we are sender, --sender is NOT in args (remote is receiver).
        assert!(!t.args.contains(&"--sender".to_string()));
        assert!(t.args.contains(&".".to_string()));
        // Absolute paths use "." with cwd set instead.
        assert_eq!(t.cwd.as_deref(), Some(Path::new("/tmp/dest")));
    }

    #[test]
    #[cfg(unix)] // Uses Unix absolute paths
    fn test_local_transport_args_receiver() {
        let t = LocalTransport::new(
            None,
            false, // we are receiver, remote is sender
            "-logDtprze.iLsfxCIvu",
            Path::new("/tmp/source"),
        );
        assert_eq!(t.args[0], "--server");
        assert_eq!(t.args[1], "--sender"); // remote should send
        assert_eq!(t.cwd.as_deref(), Some(Path::new("/tmp/source")));
    }

    #[test]
    fn test_local_transport_relative_path() {
        let t = LocalTransport::new(None, true, "-r", Path::new("relative/path"));
        assert!(t.args.contains(&"relative/path".to_string()));
        assert!(t.cwd.is_none());
    }

    #[tokio::test]
    async fn test_connect_missing_binary() {
        let t = Box::new(LocalTransport::with_args(
            "/nonexistent/rsync",
            vec!["--server".to_string()],
        ));
        let result = t.connect().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::CommandNotFound { command } => {
                assert_eq!(command, "/nonexistent/rsync");
            }
            other => panic!("expected CommandNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_connect_real_rsync() {
        // Skip if rsync is not available.
        if std::process::Command::new("rsync")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: rsync not found");
            return;
        }

        // Create a real temp directory as the rsync source.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), "hello").unwrap();

        // We are pulling: remote is sender (--sender is added).
        let t = Box::new(LocalTransport::new(
            None,
            false,
            "-re.iLsfxCIvu",
            tmp.path(),
        ));

        let streams = t.connect().await;
        assert!(
            streams.is_ok(),
            "connect failed: {:?}",
            streams.unwrap_err()
        );

        // The remote rsync expects the client to send its protocol version
        // first (both sides send, but the server may buffer reads).
        let mut streams = streams.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send our protocol version.
        streams
            .writer
            .write_all(&31_i32.to_le_bytes())
            .await
            .unwrap();
        streams.writer.flush().await.unwrap();

        // Now read the server's version.
        let mut version_buf = [0u8; 4];
        let read_result = streams.reader.read_exact(&mut version_buf).await;
        assert!(
            read_result.is_ok(),
            "failed to read version: {:?}",
            read_result.unwrap_err()
        );

        let remote_version = i32::from_le_bytes(version_buf);
        assert!(
            (27..=40).contains(&remote_version),
            "unexpected rsync protocol version: {remote_version}"
        );
    }
}
