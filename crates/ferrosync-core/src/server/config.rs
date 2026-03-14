//! Parser for `rsyncd.conf` configuration files.
//!
//! The configuration format is INI-like with `[section]` headers and
//! `key = value` pairs. The special `[global]` section sets server-wide
//! defaults. All other sections define named modules that clients can
//! connect to.
//!
//! This parser is modeled after rsync's `loadparm.c`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

// TODO: wire up after Phase 0b -- use proper error types
/// Config-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("parse error at {path}:{line}: {message}")]
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("module '{name}' has no path configured")]
    MissingPath { name: String },
}

/// Server-wide (global) configuration.
#[derive(Debug, Clone)]
pub struct GlobalConfig {
    /// Address to bind to (default: all interfaces).
    pub bind_address: Option<IpAddr>,
    /// Port to listen on (default: 873).
    pub port: u16,
    /// Path to the MOTD file shown to clients on connect.
    pub motd_file: Option<PathBuf>,
    /// Path to the PID file for the daemon process.
    pub pid_file: Option<PathBuf>,
    /// Path to the log file (if not using syslog).
    pub log_file: Option<PathBuf>,
    /// Maximum global connections (0 = unlimited).
    pub max_connections: u32,
    /// Default timeout in seconds (0 = no timeout).
    pub timeout: u32,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            bind_address: None,
            port: 873,
            motd_file: None,
            pid_file: None,
            log_file: None,
            max_connections: 0,
            timeout: 0,
        }
    }
}

/// Per-module configuration.
#[derive(Debug, Clone)]
pub struct ModuleConfig {
    /// Module name (the `[section]` header).
    pub name: String,
    /// Filesystem path to serve.
    pub path: PathBuf,
    /// Human-readable description shown in module listings.
    pub comment: String,
    /// If true, clients cannot upload files.
    pub read_only: bool,
    /// If true, this module appears in `#list` responses.
    pub list: bool,
    /// Comma-separated list of authorized users (empty = anonymous).
    pub auth_users: String,
    /// Path to the secrets file (`user:password` per line).
    pub secrets_file: Option<PathBuf>,
    /// Comma-separated allowed host patterns.
    pub hosts_allow: Vec<String>,
    /// Comma-separated denied host patterns.
    pub hosts_deny: Vec<String>,
    /// Maximum simultaneous connections to this module (0 = unlimited).
    pub max_connections: u32,
    /// Connection timeout in seconds (0 = use global default).
    pub timeout: u32,
    /// UID to run as when serving this module.
    pub uid: Option<String>,
    /// GID to run as when serving this module.
    pub gid: Option<String>,
    /// Whether to chroot into the module path.
    pub use_chroot: bool,
    /// Path to the module-specific log file.
    pub log_file: Option<PathBuf>,
    /// Exclude patterns.
    pub exclude: Vec<String>,
    /// Include patterns.
    pub include: Vec<String>,
    /// Filter rules.
    pub filter: Vec<String>,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: PathBuf::new(),
            comment: String::new(),
            read_only: true,
            list: true,
            auth_users: String::new(),
            secrets_file: None,
            hosts_allow: Vec::new(),
            hosts_deny: Vec::new(),
            max_connections: 0,
            timeout: 0,
            uid: None,
            gid: None,
            use_chroot: true,
            log_file: None,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
        }
    }
}

/// Complete rsyncd configuration.
#[derive(Debug, Clone)]
pub struct RsyncdConfig {
    /// Global (server-wide) settings.
    pub global: GlobalConfig,
    /// Per-module configurations.
    pub modules: Vec<ModuleConfig>,
}

impl RsyncdConfig {
    /// Look up a module by name (case-insensitive).
    pub fn find_module(&self, name: &str) -> Option<&ModuleConfig> {
        self.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }
}

/// Parse an `rsyncd.conf` file from the given path.
pub fn parse_config(path: &Path) -> Result<RsyncdConfig, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_config_str(&content, path)
}

/// Parse configuration from a string (for testing and embedded configs).
pub fn parse_config_str(content: &str, source_path: &Path) -> Result<RsyncdConfig, ConfigError> {
    let mut global = GlobalConfig::default();
    let mut modules = Vec::new();
    let mut current_module: Option<ModuleConfig> = None;
    let mut in_global = false;

    // Accumulate global key-values before applying them.
    let mut global_kvs: HashMap<String, String> = HashMap::new();

    for (line_num, raw_line) in content.lines().enumerate() {
        let line_num = line_num + 1; // 1-based
        let line = raw_line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header.
        if line.starts_with('[') {
            if let Some(end) = line.find(']') {
                let section_name = line[1..end].trim();

                // Finalize previous module.
                if let Some(module) = current_module.take() {
                    modules.push(module);
                }

                if section_name.eq_ignore_ascii_case("global") {
                    in_global = true;
                } else {
                    in_global = false;
                    current_module = Some(ModuleConfig {
                        name: section_name.to_string(),
                        ..Default::default()
                    });
                }
            } else {
                return Err(ConfigError::Parse {
                    path: source_path.to_path_buf(),
                    line: line_num,
                    message: "unterminated section header".to_string(),
                });
            }
            continue;
        }

        // Key = value pair.
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (normalize_key(k.trim()), v.trim().to_string()),
            None => {
                return Err(ConfigError::Parse {
                    path: source_path.to_path_buf(),
                    line: line_num,
                    message: format!("expected 'key = value', got: {line}"),
                });
            }
        };

        if in_global {
            global_kvs.insert(key, value);
        } else if let Some(ref mut module) = current_module {
            apply_module_param(module, &key, &value, source_path, line_num)?;
        } else {
            // Key-value before any section -- treat as global.
            global_kvs.insert(key, value);
        }
    }

    // Finalize last module.
    if let Some(module) = current_module.take() {
        modules.push(module);
    }

    // Apply global key-values.
    apply_global_params(&mut global, &global_kvs, source_path)?;

    Ok(RsyncdConfig { global, modules })
}

/// Normalize a config key: lowercase, replace spaces with underscores.
fn normalize_key(key: &str) -> String {
    key.to_ascii_lowercase().replace(' ', "_")
}

/// Apply global parameters from collected key-value pairs.
fn apply_global_params(
    global: &mut GlobalConfig,
    kvs: &HashMap<String, String>,
    _source_path: &Path,
) -> Result<(), ConfigError> {
    if let Some(v) = kvs.get("port") {
        global.port = v.parse().unwrap_or(873);
    }
    if let Some(v) = kvs.get("address") {
        if let Ok(addr) = v.parse() {
            global.bind_address = Some(addr);
        }
    }
    if let Some(v) = kvs.get("motd_file") {
        global.motd_file = Some(PathBuf::from(v));
    }
    if let Some(v) = kvs.get("pid_file") {
        global.pid_file = Some(PathBuf::from(v));
    }
    if let Some(v) = kvs.get("log_file") {
        global.log_file = Some(PathBuf::from(v));
    }
    if let Some(v) = kvs.get("max_connections") {
        global.max_connections = v.parse().unwrap_or(0);
    }
    if let Some(v) = kvs.get("timeout") {
        global.timeout = v.parse().unwrap_or(0);
    }
    Ok(())
}

/// Apply a single key-value pair to a module config.
fn apply_module_param(
    module: &mut ModuleConfig,
    key: &str,
    value: &str,
    source_path: &Path,
    line: usize,
) -> Result<(), ConfigError> {
    match key {
        "path" => module.path = PathBuf::from(value),
        "comment" => module.comment = value.to_string(),
        "read_only" | "readonly" => module.read_only = parse_bool(value, true),
        "list" => module.list = parse_bool(value, true),
        "auth_users" | "auth users" => module.auth_users = value.to_string(),
        "secrets_file" | "secrets file" => {
            module.secrets_file = Some(PathBuf::from(value));
        }
        "hosts_allow" | "hosts allow" => {
            module.hosts_allow = split_list(value);
        }
        "hosts_deny" | "hosts deny" => {
            module.hosts_deny = split_list(value);
        }
        "max_connections" | "max connections" => {
            module.max_connections = value.parse().unwrap_or(0);
        }
        "timeout" => module.timeout = value.parse().unwrap_or(0),
        "uid" => module.uid = Some(value.to_string()),
        "gid" => module.gid = Some(value.to_string()),
        "use_chroot" | "use chroot" => module.use_chroot = parse_bool(value, true),
        "log_file" | "log file" => module.log_file = Some(PathBuf::from(value)),
        "exclude" => module.exclude.push(value.to_string()),
        "include" => module.include.push(value.to_string()),
        "filter" => module.filter.push(value.to_string()),
        _ => {
            // Unknown keys are logged but not fatal (matches rsync behavior).
            tracing::warn!(
                path = %source_path.display(),
                line,
                key,
                "unknown config parameter, ignoring"
            );
        }
    }
    Ok(())
}

/// Parse a boolean value from a config string.
///
/// Accepts: yes/no, true/false, 1/0 (case-insensitive).
fn parse_bool(value: &str, default: bool) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => true,
        "no" | "false" | "0" => false,
        _ => default,
    }
}

/// Split a comma/space-separated list into individual items.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
# Global settings
[global]
port = 8873
motd file = /etc/rsyncd.motd
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log
max connections = 100

[backup]
path = /data/backup
comment = Daily backups
read only = yes
list = yes
auth users = admin, backup_user
secrets file = /etc/rsyncd.secrets
hosts allow = 192.168.1.0/24, 10.0.0.0/8
hosts deny = *
max connections = 10
timeout = 300
uid = nobody
gid = nogroup
use chroot = yes

[public]
path = /srv/public
comment = Public files
read only = yes
list = yes
use chroot = no

[upload]
path = /data/incoming
comment = Upload area
read only = no
auth users = uploader
secrets file = /etc/rsyncd.secrets
exclude = *.tmp
exclude = .hidden
filter = - *.bak
"#;

    #[test]
    fn test_parse_sample_config() {
        let config = parse_config_str(SAMPLE_CONFIG, Path::new("test.conf")).unwrap();

        // Global settings.
        assert_eq!(config.global.port, 8873);
        assert_eq!(
            config.global.motd_file,
            Some(PathBuf::from("/etc/rsyncd.motd"))
        );
        assert_eq!(
            config.global.pid_file,
            Some(PathBuf::from("/var/run/rsyncd.pid"))
        );
        assert_eq!(
            config.global.log_file,
            Some(PathBuf::from("/var/log/rsyncd.log"))
        );
        assert_eq!(config.global.max_connections, 100);

        // Should have 3 modules.
        assert_eq!(config.modules.len(), 3);
    }

    #[test]
    fn test_parse_backup_module() {
        let config = parse_config_str(SAMPLE_CONFIG, Path::new("test.conf")).unwrap();
        let backup = config.find_module("backup").unwrap();

        assert_eq!(backup.name, "backup");
        assert_eq!(backup.path, PathBuf::from("/data/backup"));
        assert_eq!(backup.comment, "Daily backups");
        assert!(backup.read_only);
        assert!(backup.list);
        assert_eq!(backup.auth_users, "admin, backup_user");
        assert_eq!(
            backup.secrets_file,
            Some(PathBuf::from("/etc/rsyncd.secrets"))
        );
        assert_eq!(backup.hosts_allow, vec!["192.168.1.0/24", "10.0.0.0/8"]);
        assert_eq!(backup.hosts_deny, vec!["*"]);
        assert_eq!(backup.max_connections, 10);
        assert_eq!(backup.timeout, 300);
        assert_eq!(backup.uid, Some("nobody".to_string()));
        assert_eq!(backup.gid, Some("nogroup".to_string()));
        assert!(backup.use_chroot);
    }

    #[test]
    fn test_parse_public_module() {
        let config = parse_config_str(SAMPLE_CONFIG, Path::new("test.conf")).unwrap();
        let public = config.find_module("public").unwrap();

        assert_eq!(public.path, PathBuf::from("/srv/public"));
        assert!(public.read_only);
        assert!(public.list);
        assert!(!public.use_chroot);
        assert!(public.auth_users.is_empty());
    }

    #[test]
    fn test_parse_upload_module() {
        let config = parse_config_str(SAMPLE_CONFIG, Path::new("test.conf")).unwrap();
        let upload = config.find_module("upload").unwrap();

        assert!(!upload.read_only);
        assert_eq!(upload.exclude, vec!["*.tmp", ".hidden"]);
        assert_eq!(upload.filter, vec!["- *.bak"]);
    }

    #[test]
    fn test_find_module_case_insensitive() {
        let config = parse_config_str(SAMPLE_CONFIG, Path::new("test.conf")).unwrap();

        assert!(config.find_module("BACKUP").is_some());
        assert!(config.find_module("Backup").is_some());
        assert!(config.find_module("backup").is_some());
        assert!(config.find_module("nonexistent").is_none());
    }

    #[test]
    fn test_parse_empty_config() {
        let config = parse_config_str("", Path::new("empty.conf")).unwrap();
        assert_eq!(config.modules.len(), 0);
        assert_eq!(config.global.port, 873);
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let content = r#"
# This is a comment
; This is also a comment

[test]
path = /tmp/test
# inline comment style not supported in values
"#;
        let config = parse_config_str(content, Path::new("test.conf")).unwrap();
        assert_eq!(config.modules.len(), 1);
        assert_eq!(config.modules[0].path, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_parse_bool_values() {
        assert!(parse_bool("yes", false));
        assert!(parse_bool("YES", false));
        assert!(parse_bool("true", false));
        assert!(parse_bool("1", false));
        assert!(!parse_bool("no", true));
        assert!(!parse_bool("NO", true));
        assert!(!parse_bool("false", true));
        assert!(!parse_bool("0", true));
        assert!(parse_bool("invalid", true));
        assert!(!parse_bool("invalid", false));
    }

    #[test]
    fn test_split_list() {
        assert_eq!(
            split_list("192.168.1.0/24, 10.0.0.0/8"),
            vec!["192.168.1.0/24", "10.0.0.0/8"]
        );
        assert_eq!(split_list("single"), vec!["single"]);
        assert_eq!(split_list("a b c"), vec!["a", "b", "c"]);
        assert!(split_list("").is_empty());
        assert!(split_list("  ").is_empty());
    }

    #[test]
    fn test_normalize_key() {
        assert_eq!(normalize_key("Read Only"), "read_only");
        assert_eq!(normalize_key("auth users"), "auth_users");
        assert_eq!(normalize_key("PATH"), "path");
        assert_eq!(normalize_key("use chroot"), "use_chroot");
    }

    #[test]
    fn test_parse_error_unterminated_section() {
        let content = "[broken\npath = /tmp\n";
        let result = parse_config_str(content, Path::new("bad.conf"));
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Parse { line, message, .. } => {
                assert_eq!(line, 1);
                assert!(message.contains("unterminated"));
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_error_missing_equals() {
        let content = "[module]\npath /tmp\n";
        let result = parse_config_str(content, Path::new("bad.conf"));
        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Parse { line, message, .. } => {
                assert_eq!(line, 2);
                assert!(message.contains("key = value"));
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn test_global_defaults() {
        let config = parse_config_str("[test]\npath = /tmp\n", Path::new("t.conf")).unwrap();
        assert_eq!(config.global.port, 873);
        assert!(config.global.bind_address.is_none());
        assert!(config.global.motd_file.is_none());
        assert_eq!(config.global.max_connections, 0);
        assert_eq!(config.global.timeout, 0);
    }

    #[test]
    fn test_module_defaults() {
        let config =
            parse_config_str("[minimal]\npath = /tmp/minimal\n", Path::new("t.conf")).unwrap();
        let m = &config.modules[0];
        assert!(m.read_only);
        assert!(m.list);
        assert!(m.use_chroot);
        assert!(m.auth_users.is_empty());
        assert!(m.secrets_file.is_none());
        assert!(m.hosts_allow.is_empty());
        assert!(m.hosts_deny.is_empty());
        assert_eq!(m.max_connections, 0);
        assert_eq!(m.timeout, 0);
    }

    #[test]
    fn test_keys_before_any_section_are_global() {
        let content = "port = 9999\n[mod]\npath = /tmp\n";
        let config = parse_config_str(content, Path::new("t.conf")).unwrap();
        assert_eq!(config.global.port, 9999);
    }
}
