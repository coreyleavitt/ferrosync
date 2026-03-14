//! SSH config resolution helper.
//!
//! Parses `~/.ssh/config` to resolve host aliases, ports, usernames, and
//! identity files. Falls back to sensible defaults when no config exists
//! or no matching host is found.

use std::path::{Path, PathBuf};

/// Resolved SSH connection parameters from `~/.ssh/config`.
#[derive(Debug, Clone)]
pub struct ResolvedSshConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
}

/// Resolve SSH connection parameters for `host` by parsing `~/.ssh/config`.
///
/// Falls back to defaults if the config file doesn't exist or the host
/// isn't matched:
/// - hostname = host as given
/// - port = 22
/// - user = current OS user
/// - identity_files = default key paths
pub fn resolve_ssh_config(host: &str) -> ResolvedSshConfig {
    let ssh_dir = home_ssh_dir();
    let config_path = ssh_dir.join("config");

    let (hostname, port, user, identity_files) = if config_path.is_file() {
        match parse_config_for_host(&config_path, host) {
            Some(resolved) => resolved,
            None => defaults_for(host, &ssh_dir),
        }
    } else {
        defaults_for(host, &ssh_dir)
    };

    ResolvedSshConfig {
        hostname,
        port,
        user,
        identity_files,
    }
}

/// Return the default identity file paths to try.
pub fn default_identity_files(ssh_dir: &Path) -> Vec<PathBuf> {
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|p| p.is_file())
        .collect()
}

fn home_ssh_dir() -> PathBuf {
    dirs_ssh()
}

#[cfg(unix)]
fn dirs_ssh() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".ssh")
    } else {
        PathBuf::from("/tmp/.ssh")
    }
}

#[cfg(not(unix))]
fn dirs_ssh() -> PathBuf {
    if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join(".ssh")
    } else {
        PathBuf::from("C:\\.ssh")
    }
}

fn current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

fn defaults_for(host: &str, ssh_dir: &Path) -> (String, u16, String, Vec<PathBuf>) {
    (
        host.to_string(),
        22,
        current_username(),
        default_identity_files(ssh_dir),
    )
}

fn parse_config_for_host(
    config_path: &Path,
    host: &str,
) -> Option<(String, u16, String, Vec<PathBuf>)> {
    use ssh2_config::{ParseRule, SshConfig};
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(config_path).ok()?;
    let mut reader = BufReader::new(file);
    let config = SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
        .ok()?;

    let params = config.query(host);

    let hostname = params.host_name.unwrap_or_else(|| host.to_string());

    let port = params.port.unwrap_or(22);

    let user = params.user.unwrap_or_else(current_username);

    let ssh_dir = home_ssh_dir();
    let identity_files = if let Some(files) = params.identity_file {
        files
            .iter()
            .map(|p| {
                PathBuf::from(
                    p.to_string_lossy()
                        .replace('~', &ssh_dir.parent().unwrap_or(&ssh_dir).to_string_lossy()),
                )
            })
            .collect()
    } else {
        default_identity_files(&ssh_dir)
    };

    Some((hostname, port, user, identity_files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_for_unknown_host() {
        let ssh_dir = PathBuf::from("/nonexistent/.ssh");
        let (hostname, port, _user, identity_files) = defaults_for("example.com", &ssh_dir);
        assert_eq!(hostname, "example.com");
        assert_eq!(port, 22);
        // No identity files exist at /nonexistent/.ssh
        assert!(identity_files.is_empty());
    }

    #[test]
    fn test_resolve_ssh_config_no_config_file() {
        // Even without a config file, we should get sensible defaults.
        let resolved = resolve_ssh_config("some-random-host.test");
        assert_eq!(resolved.hostname, "some-random-host.test");
        assert_eq!(resolved.port, 22);
        assert!(!resolved.user.is_empty());
    }

    #[test]
    fn test_default_identity_files_filters_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh_dir = tmp.path();
        // Create only one key file.
        std::fs::write(ssh_dir.join("id_ed25519"), "fake key").unwrap();

        let files = default_identity_files(ssh_dir);
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("id_ed25519"));
    }
}
