//! Module registry for the rsync daemon.
//!
//! Each module represents a named filesystem export that clients can connect
//! to. The registry manages module lookup, access control (host allow/deny),
//! and authentication requirements.
//!
//! Modeled after rsync's `clientserver.c` module handling.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use super::config::ModuleConfig;

/// A loaded, ready-to-serve rsync module.
#[derive(Debug, Clone)]
pub struct Module {
    /// Module name (used in the daemon protocol for selection).
    pub name: String,
    /// Filesystem root path for this module.
    pub path: PathBuf,
    /// Whether clients are restricted to read-only access.
    pub read_only: bool,
    /// Whether this module appears in `#list` responses.
    pub list: bool,
    /// Human-readable description/comment.
    pub comment: String,
    /// Authentication configuration.
    pub auth: ModuleAuth,
    /// Access control rules.
    pub access: AccessControl,
    /// Maximum simultaneous connections (0 = unlimited).
    pub max_connections: u32,
    /// Connection timeout in seconds (0 = no timeout).
    pub timeout: u32,
    /// Exclude patterns applied to this module.
    pub exclude: Vec<String>,
    /// Include patterns applied to this module.
    pub include: Vec<String>,
    /// Filter rules applied to this module.
    pub filter: Vec<String>,
}

/// Authentication requirements for a module.
#[derive(Debug, Clone)]
pub struct ModuleAuth {
    /// Comma-separated list of authorized usernames. Empty means anonymous.
    pub auth_users: String,
    /// Path to the secrets file (user:password per line).
    pub secrets_file: Option<PathBuf>,
}

impl ModuleAuth {
    /// Returns true if this module requires authentication.
    pub fn requires_auth(&self) -> bool {
        !self.auth_users.is_empty()
    }

    /// Returns the list of authorized usernames.
    pub fn user_list(&self) -> Vec<&str> {
        if self.auth_users.is_empty() {
            return Vec::new();
        }
        self.auth_users
            .split(|c: char| c == ',' || c.is_ascii_whitespace())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// Host-based access control for a module.
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    /// Allowed host/network patterns (empty = allow all).
    pub hosts_allow: Vec<String>,
    /// Denied host/network patterns (empty = deny none).
    pub hosts_deny: Vec<String>,
}

impl AccessControl {
    /// Check whether a client address is allowed to access this module.
    ///
    /// The logic follows rsync's allow/deny model:
    /// - If hosts_allow is set, the address must match at least one allow pattern.
    /// - If hosts_deny is set, the address must not match any deny pattern.
    /// - If both are set, allow is checked first (an explicit allow overrides deny).
    /// - If neither is set, access is granted.
    pub fn check_host(&self, addr: &IpAddr) -> bool {
        let addr_str = addr.to_string();

        if !self.hosts_allow.is_empty() {
            if self.hosts_allow.iter().any(|p| host_matches(p, &addr_str)) {
                return true;
            }
            // hosts_allow is set but address didn't match -- deny.
            return false;
        }

        if !self.hosts_deny.is_empty() {
            if self.hosts_deny.iter().any(|p| host_matches(p, &addr_str)) {
                return false;
            }
        }

        true
    }
}

/// Simple host pattern matching.
///
/// Supports:
/// - `*` matches everything
/// - Exact IP address match
/// - CIDR prefix match (e.g., `192.168.1.0/24`)
///
/// For a production implementation, this should support full glob patterns
/// and hostname matching, but this covers the common cases.
fn host_matches(pattern: &str, addr: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Exact match.
    if pattern == addr {
        return true;
    }

    // CIDR prefix match (simplified: just check if the address string
    // starts with the network portion).
    if let Some((network, prefix_len_str)) = pattern.split_once('/') {
        if let Ok(prefix_len) = prefix_len_str.parse::<u8>() {
            return cidr_match(network, prefix_len, addr);
        }
    }

    false
}

/// Check if an IP address matches a CIDR range.
fn cidr_match(network: &str, prefix_len: u8, addr: &str) -> bool {
    // Parse both as IPv4 for now.
    let net_octets: Vec<u8> = network
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let addr_octets: Vec<u8> = addr.split('.').filter_map(|s| s.parse().ok()).collect();

    if net_octets.len() != 4 || addr_octets.len() != 4 {
        return false;
    }

    let net_u32 = u32::from_be_bytes([net_octets[0], net_octets[1], net_octets[2], net_octets[3]]);
    let addr_u32 = u32::from_be_bytes([
        addr_octets[0],
        addr_octets[1],
        addr_octets[2],
        addr_octets[3],
    ]);

    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };

    (net_u32 & mask) == (addr_u32 & mask)
}

/// Registry of available modules.
///
/// Provides O(1) lookup by module name and supports listing modules
/// that are visible to clients.
#[derive(Debug)]
pub struct ModuleRegistry {
    modules: HashMap<String, Module>,
    /// Ordered list of module names (preserves config file order for listing).
    order: Vec<String>,
}

impl ModuleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Build a registry from parsed module configs.
    pub fn from_configs(configs: &[ModuleConfig]) -> Self {
        let mut registry = Self::new();
        for config in configs {
            registry.register(Module::from_config(config));
        }
        registry
    }

    /// Register a module. Replaces any existing module with the same name.
    pub fn register(&mut self, module: Module) {
        let key = module.name.to_ascii_lowercase();
        if !self.modules.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.modules.insert(key, module);
    }

    /// Resolve a module by name (case-insensitive).
    pub fn resolve_module(&self, name: &str) -> Option<&Module> {
        self.modules.get(&name.to_ascii_lowercase())
    }

    /// List all modules that are visible to clients (`list = true`).
    pub fn list_visible(&self) -> Vec<&Module> {
        self.order
            .iter()
            .filter_map(|name| {
                let m = self.modules.get(name)?;
                if m.list {
                    Some(m)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the total number of registered modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Return true if no modules are registered.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Module {
    /// Build a `Module` from a parsed `ModuleConfig`.
    pub fn from_config(config: &ModuleConfig) -> Self {
        Self {
            name: config.name.clone(),
            path: config.path.clone(),
            read_only: config.read_only,
            list: config.list,
            comment: config.comment.clone(),
            auth: ModuleAuth {
                auth_users: config.auth_users.clone(),
                secrets_file: config.secrets_file.clone(),
            },
            access: AccessControl {
                hosts_allow: config.hosts_allow.clone(),
                hosts_deny: config.hosts_deny.clone(),
            },
            max_connections: config.max_connections,
            timeout: config.timeout,
            exclude: config.exclude.clone(),
            include: config.include.clone(),
            filter: config.filter.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_test_module(name: &str, list: bool) -> Module {
        Module {
            name: name.to_string(),
            path: PathBuf::from(format!("/srv/{name}")),
            read_only: true,
            list,
            comment: format!("{name} module"),
            auth: ModuleAuth {
                auth_users: String::new(),
                secrets_file: None,
            },
            access: AccessControl::default(),
            max_connections: 0,
            timeout: 0,
            exclude: Vec::new(),
            include: Vec::new(),
            filter: Vec::new(),
        }
    }

    #[test]
    fn test_registry_resolve() {
        let mut registry = ModuleRegistry::new();
        registry.register(make_test_module("backup", true));
        registry.register(make_test_module("data", true));

        assert!(registry.resolve_module("backup").is_some());
        assert!(registry.resolve_module("BACKUP").is_some());
        assert!(registry.resolve_module("Backup").is_some());
        assert!(registry.resolve_module("data").is_some());
        assert!(registry.resolve_module("missing").is_none());
    }

    #[test]
    fn test_registry_list_visible() {
        let mut registry = ModuleRegistry::new();
        registry.register(make_test_module("visible1", true));
        registry.register(make_test_module("hidden", false));
        registry.register(make_test_module("visible2", true));

        let visible = registry.list_visible();
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].name, "visible1");
        assert_eq!(visible[1].name, "visible2");
    }

    #[test]
    fn test_registry_len() {
        let mut registry = ModuleRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(make_test_module("a", true));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);

        registry.register(make_test_module("b", true));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_registry_replace() {
        let mut registry = ModuleRegistry::new();
        let mut m = make_test_module("test", true);
        m.comment = "original".to_string();
        registry.register(m);

        let mut m2 = make_test_module("test", true);
        m2.comment = "replaced".to_string();
        registry.register(m2);

        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.resolve_module("test").unwrap().comment,
            "replaced"
        );
    }

    #[test]
    fn test_registry_from_configs() {
        let configs = vec![
            ModuleConfig {
                name: "mod1".to_string(),
                path: PathBuf::from("/tmp/1"),
                ..Default::default()
            },
            ModuleConfig {
                name: "mod2".to_string(),
                path: PathBuf::from("/tmp/2"),
                list: false,
                ..Default::default()
            },
        ];
        let registry = ModuleRegistry::from_configs(&configs);
        assert_eq!(registry.len(), 2);
        assert!(registry.resolve_module("mod1").is_some());
        assert!(registry.resolve_module("mod2").is_some());
        assert_eq!(registry.list_visible().len(), 1);
    }

    #[test]
    fn test_module_auth_requires_auth() {
        let anon = ModuleAuth {
            auth_users: String::new(),
            secrets_file: None,
        };
        assert!(!anon.requires_auth());

        let authed = ModuleAuth {
            auth_users: "admin, user".to_string(),
            secrets_file: Some(PathBuf::from("/etc/secrets")),
        };
        assert!(authed.requires_auth());
    }

    #[test]
    fn test_module_auth_user_list() {
        let auth = ModuleAuth {
            auth_users: "admin, backup_user, reader".to_string(),
            secrets_file: None,
        };
        let users = auth.user_list();
        assert_eq!(users, vec!["admin", "backup_user", "reader"]);
    }

    #[test]
    fn test_module_auth_user_list_empty() {
        let auth = ModuleAuth {
            auth_users: String::new(),
            secrets_file: None,
        };
        assert!(auth.user_list().is_empty());
    }

    #[test]
    fn test_access_control_allow_all() {
        let ac = AccessControl::default();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(ac.check_host(&addr));
    }

    #[test]
    fn test_access_control_hosts_allow() {
        let ac = AccessControl {
            hosts_allow: vec!["192.168.1.0/24".to_string()],
            hosts_deny: Vec::new(),
        };

        let allowed = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let denied = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(ac.check_host(&allowed));
        assert!(!ac.check_host(&denied));
    }

    #[test]
    fn test_access_control_hosts_deny() {
        let ac = AccessControl {
            hosts_allow: Vec::new(),
            hosts_deny: vec!["10.0.0.0/8".to_string()],
        };

        let allowed = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let denied = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(ac.check_host(&allowed));
        assert!(!ac.check_host(&denied));
    }

    #[test]
    fn test_access_control_deny_all_except_allow() {
        let ac = AccessControl {
            hosts_allow: vec!["192.168.1.100".to_string()],
            hosts_deny: vec!["*".to_string()],
        };

        let allowed = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let denied = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
        assert!(ac.check_host(&allowed));
        assert!(!ac.check_host(&denied));
    }

    #[test]
    fn test_access_control_wildcard_deny() {
        let ac = AccessControl {
            hosts_allow: Vec::new(),
            hosts_deny: vec!["*".to_string()],
        };

        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!ac.check_host(&addr));
    }

    #[test]
    fn test_host_matches_exact() {
        assert!(host_matches("192.168.1.1", "192.168.1.1"));
        assert!(!host_matches("192.168.1.1", "192.168.1.2"));
    }

    #[test]
    fn test_host_matches_wildcard() {
        assert!(host_matches("*", "anything"));
        assert!(host_matches("*", "192.168.1.1"));
    }

    #[test]
    fn test_cidr_match_24() {
        assert!(cidr_match("192.168.1.0", 24, "192.168.1.1"));
        assert!(cidr_match("192.168.1.0", 24, "192.168.1.254"));
        assert!(!cidr_match("192.168.1.0", 24, "192.168.2.1"));
    }

    #[test]
    fn test_cidr_match_16() {
        assert!(cidr_match("10.0.0.0", 16, "10.0.1.1"));
        assert!(cidr_match("10.0.0.0", 16, "10.0.255.255"));
        assert!(!cidr_match("10.0.0.0", 16, "10.1.0.1"));
    }

    #[test]
    fn test_cidr_match_8() {
        assert!(cidr_match("10.0.0.0", 8, "10.1.2.3"));
        assert!(cidr_match("10.0.0.0", 8, "10.255.255.255"));
        assert!(!cidr_match("10.0.0.0", 8, "11.0.0.1"));
    }

    #[test]
    fn test_cidr_match_32() {
        assert!(cidr_match("192.168.1.1", 32, "192.168.1.1"));
        assert!(!cidr_match("192.168.1.1", 32, "192.168.1.2"));
    }

    #[test]
    fn test_module_from_config() {
        let config = ModuleConfig {
            name: "test".to_string(),
            path: PathBuf::from("/srv/test"),
            comment: "Test module".to_string(),
            read_only: false,
            list: true,
            auth_users: "admin".to_string(),
            secrets_file: Some(PathBuf::from("/etc/secrets")),
            hosts_allow: vec!["192.168.0.0/16".to_string()],
            hosts_deny: vec!["*".to_string()],
            max_connections: 5,
            timeout: 120,
            exclude: vec!["*.tmp".to_string()],
            include: vec!["*.rs".to_string()],
            filter: vec!["- .git".to_string()],
            ..Default::default()
        };

        let module = Module::from_config(&config);
        assert_eq!(module.name, "test");
        assert_eq!(module.path, PathBuf::from("/srv/test"));
        assert!(!module.read_only);
        assert!(module.auth.requires_auth());
        assert_eq!(module.auth.user_list(), vec!["admin"]);
        assert_eq!(module.access.hosts_allow, vec!["192.168.0.0/16"]);
        assert_eq!(module.max_connections, 5);
        assert_eq!(module.exclude, vec!["*.tmp"]);
    }
}
