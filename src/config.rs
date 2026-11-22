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

    /// Initial trust for peers defined in config (default: 0.5).
    /// Pre-approved peers start with higher trust so their signals
    /// are immediately actionable without needing confirmation history.
    #[serde(default = "default_initial_trust")]
    pub initial_trust: f32,

    /// PEM certificate the listener answers with. With `tls_key`; both
    /// absent, the node makes and keeps a self-signed pair in its data
    /// directory (`tls::listener_cert_paths`), whose SHA-256 its peers pin.
    #[serde(default)]
    pub tls_cert: Option<String>,

    /// PEM private key for `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<String>,
}

/// A peer entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    /// HTTPS endpoint (e.g., "https://10.0.1.5:8790"). An `http://` endpoint
    /// is refused: it has no certificate to check.
    pub endpoint: String,
    /// Ed25519 public key hex (64 chars): the only node id whose signals
    /// this node accepts for this peer. Empty: learned from the peer's ping,
    /// over the connection its certificate was checked on.
    pub public_key: String,
    /// Human-friendly label (optional)
    #[serde(default)]
    pub label: Option<String>,
    /// SHA-256 of the certificate the peer answers with (64 hex digits,
    /// colons allowed: `openssl x509 -noout -fingerprint -sha256`).
    #[serde(default)]
    pub tls_cert_sha256: Option<String>,
    /// PEM file of the CA the peer's certificate must chain to, for the
    /// endpoint's name. A peer with neither this nor `tls_cert_sha256` is
    /// refused (`tls::peer_client`).
    #[serde(default)]
    pub tls_ca: Option<String>,
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
            initial_trust: default_initial_trust(),
            tls_cert: None,
            tls_key: None,
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
fn default_initial_trust() -> f32 {
    0.5
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

            tls_cert_sha256 = "AB:CD"

            [[peers]]
            endpoint = "https://10.0.2.5:8790"
            public_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            tls_ca = "/etc/innerwarden/mesh-ca.pem"
        "#;
        let cfg: MeshConfig = toml::from_str(toml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bind, "0.0.0.0:9999");
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].label.as_deref(), Some("prod-eu"));
        assert!(cfg.peers[1].label.is_none());
        assert_eq!(cfg.peers[0].tls_cert_sha256.as_deref(), Some("AB:CD"));
        assert!(cfg.peers[0].tls_ca.is_none());
        assert_eq!(
            cfg.peers[1].tls_ca.as_deref(),
            Some("/etc/innerwarden/mesh-ca.pem")
        );
        assert!(cfg.tls_cert.is_none() && cfg.tls_key.is_none());
        assert!(!cfg.auto_broadcast);
        assert_eq!(cfg.max_signals_per_hour, 100);
    }
}
