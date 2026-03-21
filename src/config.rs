use serde::{Deserialize, Serialize};

/// Mesh network configuration — loaded from `[mesh]` section in agent.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Enable mesh networking (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Bind address for the mesh peer-to-peer listener (default: "0.0.0.0:8790")
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Known peers to connect to
    #[serde(default)]
    pub peers: Vec<PeerEntry>,

    /// How often to tick (check expirations, sync state) in seconds (default: 30)
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,

    /// Automatically broadcast local block decisions to peers (default: true)
    #[serde(default = "default_true")]
    pub auto_broadcast: bool,

    /// Maximum signals per hour from a single peer before quarantine (default: 50)
    #[serde(default = "default_max_signals_per_hour")]
    pub max_signals_per_hour: usize,

    /// Maximum entries in the staging pool (default: 10000)
    #[serde(default = "default_max_staged")]
    pub max_staged: usize,
}

/// A peer entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    /// HTTPS endpoint (e.g., "https://10.0.1.5:8790")
    pub endpoint: String,
    /// Ed25519 public key hex (64 chars) — verifies this peer's identity
    pub public_key: String,
    /// Human-friendly label (optional)
    #[serde(default)]
    pub label: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_bind(),
            peers: vec![],
            poll_secs: default_poll_secs(),
            auto_broadcast: true,
            max_signals_per_hour: default_max_signals_per_hour(),
            max_staged: default_max_staged(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:8790".to_string()
}
fn default_poll_secs() -> u64 {
    30
}
fn default_true() -> bool {
    true
}
fn default_max_signals_per_hour() -> usize {
    50
}
fn default_max_staged() -> usize {
    10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = MeshConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.bind, "0.0.0.0:8790");
        assert!(cfg.peers.is_empty());
        assert_eq!(cfg.poll_secs, 30);
        assert!(cfg.auto_broadcast);
        assert_eq!(cfg.max_signals_per_hour, 50);
    }

    #[test]
    fn deserialize_toml() {
        let toml = r#"
            enabled = true
            bind = "0.0.0.0:9999"
            poll_secs = 15
            auto_broadcast = false
            max_signals_per_hour = 100

            [[peers]]
            endpoint = "https://10.0.1.5:8790"
            public_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            label = "prod-eu"

            [[peers]]
            endpoint = "https://10.0.2.5:8790"
            public_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        "#;
        let cfg: MeshConfig = toml::from_str(toml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bind, "0.0.0.0:9999");
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].label.as_deref(), Some("prod-eu"));
        assert!(cfg.peers[1].label.is_none());
        assert!(!cfg.auto_broadcast);
        assert_eq!(cfg.max_signals_per_hour, 100);
    }
}
