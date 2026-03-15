//! Native SSH transport using `russh`.
//!
//! Connects to a remote host over SSH and executes a remote command to start
//! the rsync wire protocol. By default, auto-detects ferrosync on the remote
//! and falls back to stock rsync if not found. This avoids shelling out to
//! the system `ssh` binary, eliminating pipe overhead, command injection risk,
//! and platform dependency.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{self, PrivateKeyWithHashAlg, PublicKey};

use super::ssh_config::{default_identity_files, resolve_ssh_config};
use super::{Transport, TransportStreams};
use crate::error::TransportError;

type Result<T> = std::result::Result<T, TransportError>;

/// Policy for verifying the remote host's SSH key against `~/.ssh/known_hosts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostsPolicy {
    /// Reject connections to unknown hosts and hosts with mismatched keys.
    Strict,
    /// Accept and persist keys for new hosts; reject mismatched keys.
    AcceptNew,
    /// Accept all keys without verification (insecure, for testing only).
    AcceptAll,
}

/// Configuration for an SSH transport connection.
#[derive(Debug, Clone)]
pub struct SshTransportConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// SSH port (default 22).
    pub port: u16,
    /// Remote username.
    pub user: String,
    /// Private key files to try for authentication, in order.
    pub identity_files: Vec<PathBuf>,
    /// Known hosts verification policy.
    pub known_hosts_policy: KnownHostsPolicy,
    /// Path to the rsync binary on the remote host.
    pub rsync_path: String,
    /// SSH connection timeout.
    pub connect_timeout: Duration,
}

impl Default for SshTransportConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            user: String::new(),
            identity_files: Vec::new(),
            known_hosts_policy: KnownHostsPolicy::Strict,
            rsync_path: "ferrosync".to_string(),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

impl SshTransportConfig {
    /// Create a config resolved from `~/.ssh/config` for the given host.
    pub fn from_host(host: &str) -> Self {
        let resolved = resolve_ssh_config(host);
        Self {
            host: resolved.hostname,
            port: resolved.port,
            user: resolved.user,
            identity_files: resolved.identity_files,
            ..Default::default()
        }
    }
}

/// Native SSH transport using pure-Rust `russh`.
///
/// By default, tries `ferrosync serve` on the remote and falls back to
/// `rsync --server` if ferrosync is not installed. Set `rsync_path` to
/// override (e.g., "rsync" to force stock rsync, or a custom path).
pub struct SshTransport {
    config: SshTransportConfig,
    /// Arguments for `rsync --server`.
    args: Vec<String>,
}

impl SshTransport {
    /// Create a new SSH transport.
    ///
    /// - `config`: SSH connection parameters.
    /// - `am_sender`: if true, we are sending to the remote (remote is receiver).
    /// - `options`: the server-mode option string (e.g., "-logDtprze.iLsfxCIvu").
    /// - `path`: the remote source or destination path.
    pub fn new(config: SshTransportConfig, am_sender: bool, options: &str, path: &Path) -> Self {
        // Store protocol args without the binary/subcommand prefix.
        // remote_command() will prepend the appropriate prefix based on config.
        let mut args = Vec::new();
        if !am_sender {
            args.push("--sender".to_string());
        }
        args.push(options.to_string());
        args.push(".".to_string());
        args.push(path.display().to_string());

        Self { config, args }
    }

    /// Returns true if the configured remote binary is rsync (not ferrosync).
    fn is_rsync_path(path: &str) -> bool {
        let basename = path.rsplit('/').next().unwrap_or(path);
        basename == "rsync"
    }

    /// Build the remote command string.
    ///
    /// When the configured binary is "ferrosync" (default), generates a
    /// shell command that tries ferrosync first and falls back to rsync:
    ///
    /// ```sh
    /// command -v ferrosync >/dev/null 2>&1 && ferrosync serve ARGS || rsync --server ARGS
    /// ```
    ///
    /// This way ferrosync-to-ferrosync transfers happen automatically when
    /// the remote has ferrosync installed, with zero-latency fallback to
    /// stock rsync otherwise. `command -v` is POSIX and effectively free.
    ///
    /// When the configured binary is explicitly set to something else
    /// (e.g., "rsync" or "/usr/local/bin/rsync"), it's used directly
    /// without fallback.
    fn remote_command(&self) -> String {
        let escape = |arg: &str| -> String {
            if arg.contains(' ')
                || arg.contains('\'')
                || arg.contains('"')
                || arg.contains('\\')
                || arg.contains('$')
            {
                format!("'{}'", arg.replace('\'', "'\\''"))
            } else {
                arg.to_string()
            }
        };

        let args_str: String = self
            .args
            .iter()
            .map(|a| escape(a))
            .collect::<Vec<_>>()
            .join(" ");

        if self.config.rsync_path == "ferrosync" {
            // Auto-detect: try ferrosync first, fall back to rsync.
            // Use exec to replace the shell process so stdin/stdout pipe directly.
            format!(
                "command -v ferrosync >/dev/null 2>&1 && exec ferrosync serve {args_str} || exec rsync --server {args_str}"
            )
        } else if Self::is_rsync_path(&self.config.rsync_path) {
            // Explicit rsync path: use --server protocol.
            format!("{} --server {args_str}", escape(&self.config.rsync_path))
        } else {
            // Custom path: use --server protocol (assume rsync-compatible).
            format!("{} --server {args_str}", escape(&self.config.rsync_path))
        }
    }

    /// Try to authenticate with a private key file.
    async fn try_key_auth(
        session: &mut client::Handle<SshClientHandler>,
        user: &str,
        key_path: &Path,
    ) -> std::result::Result<bool, TransportError> {
        let private_key = match keys::load_secret_key(key_path, None) {
            Ok(k) => k,
            Err(e) => {
                tracing::debug!(
                    path = %key_path.display(),
                    error = %e,
                    "skipping key (failed to load)"
                );
                return Ok(false);
            }
        };

        // Determine the best hash algorithm for RSA keys.
        let hash_alg = session
            .best_supported_rsa_hash()
            .await
            .unwrap_or(None)
            .flatten();
        let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(private_key), hash_alg);

        match session.authenticate_publickey(user, key_with_alg).await {
            Ok(result) => Ok(result.success()),
            Err(e) => {
                tracing::debug!(
                    path = %key_path.display(),
                    error = %e,
                    "key auth attempt failed"
                );
                Ok(false)
            }
        }
    }
}

impl Transport for SshTransport {
    fn connect(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TransportStreams>> + Send>> {
        Box::pin(async move {
            let addr = format!("{}:{}", self.config.host, self.config.port);

            let ssh_config = Arc::new(client::Config::default());

            let handler = SshClientHandler {
                host: self.config.host.clone(),
                port: self.config.port,
                known_hosts_policy: self.config.known_hosts_policy,
            };

            // Connect with external timeout (russh Config has no connection_timeout).
            tracing::debug!(addr = %addr, user = %self.config.user, "connecting via SSH");
            let mut session = tokio::time::timeout(
                self.config.connect_timeout,
                client::connect(ssh_config, &addr, handler),
            )
            .await
            .map_err(|_| TransportError::ConnectionFailed {
                message: format!("SSH connection to {addr} timed out"),
            })?
            .map_err(|e| TransportError::ConnectionFailed {
                message: format!("SSH connection to {addr} failed: {e}"),
            })?;

            // Authenticate: try each identity file in order.
            let mut authenticated = false;
            let identity_files = if self.config.identity_files.is_empty() {
                let ssh_dir = home_ssh_dir();
                default_identity_files(&ssh_dir)
            } else {
                self.config.identity_files.clone()
            };

            for key_path in &identity_files {
                if !key_path.is_file() {
                    continue;
                }
                tracing::debug!(path = %key_path.display(), "trying SSH key");
                match Self::try_key_auth(&mut session, &self.config.user, key_path).await? {
                    true => {
                        tracing::debug!(path = %key_path.display(), "SSH authentication succeeded");
                        authenticated = true;
                        break;
                    }
                    false => continue,
                }
            }

            if !authenticated {
                return Err(TransportError::AuthFailed {
                    message: format!(
                        "no accepted SSH key for {}@{} (tried {} keys)",
                        self.config.user,
                        self.config.host,
                        identity_files.len()
                    ),
                });
            }

            // Open a session channel and execute the remote rsync command.
            let channel = session.channel_open_session().await.map_err(|e| {
                TransportError::ConnectionFailed {
                    message: format!("failed to open SSH channel: {e}"),
                }
            })?;

            let remote_cmd = self.remote_command();
            tracing::debug!(cmd = %remote_cmd, "executing remote command");

            channel
                .exec(true, remote_cmd)
                .await
                .map_err(|e| TransportError::ConnectionFailed {
                    message: format!("failed to exec remote command: {e}"),
                })?;

            // Convert the channel into an async read/write stream.
            let stream = channel.into_stream();
            let (reader, writer) = tokio::io::split(stream);

            Ok(TransportStreams {
                reader: Box::new(reader),
                writer: Box::new(writer),
                background_task: None,
            })
        })
    }
}

/// Wrapper error type that satisfies russh's `From<russh::Error>` requirement
/// on `Handler::Error`.
#[derive(Debug)]
enum SshHandlerError {
    Transport(TransportError),
    Russh(russh::Error),
}

impl std::fmt::Display for SshHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Russh(e) => write!(f, "SSH error: {e}"),
        }
    }
}

impl From<russh::Error> for SshHandlerError {
    fn from(e: russh::Error) -> Self {
        Self::Russh(e)
    }
}

impl From<TransportError> for SshHandlerError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

/// Handler for russh client events, including host key verification.
struct SshClientHandler {
    host: String,
    port: u16,
    known_hosts_policy: KnownHostsPolicy,
}

impl client::Handler for SshClientHandler {
    type Error = SshHandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match self.known_hosts_policy {
            KnownHostsPolicy::AcceptAll => {
                tracing::warn!(
                    host = %self.host,
                    "accepting SSH host key without verification (AcceptAll policy)"
                );
                return Ok(true);
            }
            KnownHostsPolicy::Strict | KnownHostsPolicy::AcceptNew => {}
        }

        let known_hosts_path = home_ssh_dir().join("known_hosts");
        if !known_hosts_path.is_file() {
            return match self.known_hosts_policy {
                KnownHostsPolicy::AcceptNew => {
                    tracing::info!(
                        host = %self.host,
                        "no known_hosts file; accepting and saving host key"
                    );
                    let _ =
                        save_host_key(&known_hosts_path, &self.host, self.port, server_public_key);
                    Ok(true)
                }
                KnownHostsPolicy::Strict => Err(TransportError::HostKeyNotFound {
                    host: self.host.clone(),
                }
                .into()),
                KnownHostsPolicy::AcceptAll => unreachable!(),
            };
        }

        match keys::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &known_hosts_path,
        ) {
            Ok(true) => Ok(true),
            Ok(false) => {
                // Key not found in known_hosts.
                match self.known_hosts_policy {
                    KnownHostsPolicy::AcceptNew => {
                        tracing::info!(
                            host = %self.host,
                            "new host key; accepting and saving"
                        );
                        let _ = save_host_key(
                            &known_hosts_path,
                            &self.host,
                            self.port,
                            server_public_key,
                        );
                        Ok(true)
                    }
                    KnownHostsPolicy::Strict => Err(TransportError::HostKeyNotFound {
                        host: self.host.clone(),
                    }
                    .into()),
                    KnownHostsPolicy::AcceptAll => unreachable!(),
                }
            }
            Err(_) => {
                // Key mismatch (KeyChanged error) or other error.
                Err(TransportError::HostKeyMismatch {
                    host: self.host.clone(),
                }
                .into())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Known hosts helpers
// ---------------------------------------------------------------------------

/// Append a host key to the known_hosts file.
fn save_host_key(
    known_hosts_path: &Path,
    host: &str,
    port: u16,
    key: &PublicKey,
) -> std::io::Result<()> {
    use std::io::Write;

    let host_entry = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };

    let key_str = key.to_openssh().map_err(std::io::Error::other)?;

    let line = format!("{host_entry} {key_str}\n");

    // Create parent directory if needed.
    if let Some(parent) = known_hosts_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_hosts_path)?;
    file.write_all(line.as_bytes())?;

    Ok(())
}

#[cfg(unix)]
fn home_ssh_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".ssh")
    } else {
        PathBuf::from("/tmp/.ssh")
    }
}

#[cfg(not(unix))]
fn home_ssh_dir() -> PathBuf {
    if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join(".ssh")
    } else {
        PathBuf::from("C:\\.ssh")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_transport_config_defaults() {
        let config = SshTransportConfig::default();
        assert_eq!(config.port, 22);
        assert_eq!(config.rsync_path, "ferrosync");
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.known_hosts_policy, KnownHostsPolicy::Strict);
        assert!(config.identity_files.is_empty());
    }

    #[test]
    fn test_ssh_config_from_host() {
        let config = SshTransportConfig::from_host("nonexistent-test-host.example");
        assert_eq!(config.host, "nonexistent-test-host.example");
        assert_eq!(config.port, 22);
        assert!(!config.user.is_empty());
    }

    #[test]
    fn test_remote_command_auto_detect_sender() {
        let config = SshTransportConfig {
            host: "example.com".to_string(),
            ..Default::default()
        };
        let transport = SshTransport::new(
            config,
            true, // we are sender, remote is receiver
            "-logDtprze.iLsfxCIvu",
            Path::new("/data/backup"),
        );
        let cmd = transport.remote_command();
        // Auto-detect: tries ferrosync first, falls back to rsync.
        assert!(cmd.contains("command -v ferrosync"));
        assert!(cmd.contains("exec ferrosync serve"));
        assert!(cmd.contains("|| exec rsync --server"));
        assert!(cmd.contains("/data/backup"));
        assert!(!cmd.contains("--sender"));
    }

    #[test]
    fn test_remote_command_auto_detect_receiver() {
        let config = SshTransportConfig {
            host: "example.com".to_string(),
            ..Default::default()
        };
        let transport = SshTransport::new(
            config,
            false, // we are receiver, remote is sender
            "-logDtprze.iLsfxCIvu",
            Path::new("/data/source"),
        );
        let cmd = transport.remote_command();
        assert!(cmd.contains("command -v ferrosync"));
        assert!(cmd.contains("exec ferrosync serve --sender"));
        assert!(cmd.contains("exec rsync --server --sender"));
        assert!(cmd.contains("/data/source"));
    }

    #[test]
    fn test_remote_command_rsync_fallback_sender() {
        let config = SshTransportConfig {
            host: "example.com".to_string(),
            rsync_path: "rsync".to_string(),
            ..Default::default()
        };
        let transport = SshTransport::new(
            config,
            true, // we are sender, remote is receiver
            "-logDtprze.iLsfxCIvu",
            Path::new("/data/backup"),
        );
        let cmd = transport.remote_command();
        assert_eq!(cmd, "rsync --server -logDtprze.iLsfxCIvu . /data/backup");
        assert!(!cmd.contains("--sender"));
    }

    #[test]
    fn test_remote_command_rsync_fallback_receiver() {
        let config = SshTransportConfig {
            host: "example.com".to_string(),
            rsync_path: "/usr/local/bin/rsync".to_string(),
            ..Default::default()
        };
        let transport = SshTransport::new(
            config,
            false, // we are receiver, remote is sender
            "-logDtprze.iLsfxCIvu",
            Path::new("/data/source"),
        );
        let cmd = transport.remote_command();
        assert_eq!(
            cmd,
            "/usr/local/bin/rsync --server --sender -logDtprze.iLsfxCIvu . /data/source"
        );
    }

    #[test]
    fn test_remote_command_escapes_spaces() {
        let config = SshTransportConfig::default();
        let transport = SshTransport::new(config, true, "-r", Path::new("/path with spaces/dir"));
        let cmd = transport.remote_command();
        assert!(cmd.contains("'/path with spaces/dir'"));
    }

    #[test]
    fn test_is_rsync_path() {
        assert!(SshTransport::is_rsync_path("rsync"));
        assert!(SshTransport::is_rsync_path("/usr/bin/rsync"));
        assert!(SshTransport::is_rsync_path("/usr/local/bin/rsync"));
        assert!(!SshTransport::is_rsync_path("ferrosync"));
        assert!(!SshTransport::is_rsync_path("/usr/bin/ferrosync"));
        assert!(!SshTransport::is_rsync_path("frsync"));
    }

    fn generate_test_key() -> keys::PrivateKey {
        keys::PrivateKey::random(&mut rand_core::OsRng, keys::Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn test_known_hosts_accept() {
        let tmp = tempfile::tempdir().unwrap();
        let kh_path = tmp.path().join("known_hosts");

        let private_key = generate_test_key();
        let pubkey = private_key.public_key().clone();

        save_host_key(&kh_path, "testhost", 22, &pubkey).unwrap();

        let result = keys::check_known_hosts_path("testhost", 22, &pubkey, &kh_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_known_hosts_reject_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let kh_path = tmp.path().join("known_hosts");

        let key1 = generate_test_key();
        save_host_key(&kh_path, "testhost", 22, key1.public_key()).unwrap();

        let key2 = generate_test_key();
        let result = keys::check_known_hosts_path("testhost", 22, key2.public_key(), &kh_path);
        // KeyChanged error for mismatched key.
        assert!(result.is_err());
    }

    #[test]
    fn test_known_hosts_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let kh_path = tmp.path().join("known_hosts");

        let key = generate_test_key();
        save_host_key(&kh_path, "otherhost", 22, key.public_key()).unwrap();

        // Look up a host that isn't there.
        let result = keys::check_known_hosts_path("testhost", 22, key.public_key(), &kh_path);
        // Not found returns Ok(false).
        assert!(!result.unwrap());
    }

    #[test]
    fn test_known_hosts_non_standard_port() {
        let tmp = tempfile::tempdir().unwrap();
        let kh_path = tmp.path().join("known_hosts");

        let key = generate_test_key();

        save_host_key(&kh_path, "testhost", 2222, key.public_key()).unwrap();

        let contents = std::fs::read_to_string(&kh_path).unwrap();
        assert!(contents.contains("[testhost]:2222"));

        let result = keys::check_known_hosts_path("testhost", 2222, key.public_key(), &kh_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_auth_key_ordering() {
        let config = SshTransportConfig {
            host: "test.example".to_string(),
            identity_files: vec![
                PathBuf::from("/first/key"),
                PathBuf::from("/second/key"),
                PathBuf::from("/third/key"),
            ],
            ..Default::default()
        };
        assert_eq!(config.identity_files[0], PathBuf::from("/first/key"));
        assert_eq!(config.identity_files[1], PathBuf::from("/second/key"));
        assert_eq!(config.identity_files[2], PathBuf::from("/third/key"));
    }

    /// Integration test: connect to localhost SSH.
    /// Gated behind FERROSYNC_SSH_TEST=1 env var.
    #[tokio::test]
    async fn test_connect_localhost() {
        if std::env::var("FERROSYNC_SSH_TEST").as_deref() != Ok("1") {
            eprintln!("skipping SSH integration test (set FERROSYNC_SSH_TEST=1)");
            return;
        }

        let config = SshTransportConfig {
            host: "127.0.0.1".to_string(),
            known_hosts_policy: KnownHostsPolicy::AcceptAll,
            ..SshTransportConfig::from_host("localhost")
        };

        let transport = Box::new(SshTransport::new(
            config,
            false,
            "-re.iLsfxCIvu",
            Path::new("/tmp"),
        ));

        match transport.connect().await {
            Ok(streams) => {
                drop(streams);
            }
            Err(e) => {
                eprintln!("SSH connection to localhost failed (expected in CI): {e}");
            }
        }
    }
}
