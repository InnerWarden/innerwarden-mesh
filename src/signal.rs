use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::{sha256_hex, NodeIdentity};

/// A threat signal shared between mesh nodes.
///
/// When a node blocks an IP, it broadcasts a ThreatSignal to all peers.
/// Peers validate the signature, score it against the sender's reputation,
/// and stage it for potential blocking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignal {
    /// Ed25519 public key (hex) of the sending node
    pub node_id: String,
    /// IP address being reported as malicious
    pub ip: String,
    /// Which detector triggered the block (e.g., "ssh_bruteforce")
    pub detector: String,
    /// AI confidence from the sending node (0.0-1.0)
    pub confidence: f32,
    /// SHA-256 hash of the incident evidence (privacy-preserving)
    pub evidence_hash: String,
    /// Suggested block duration in seconds
    pub ttl_secs: u64,
    /// When the signal was created
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature (base64) over the canonical JSON of all fields above
    pub signature: String,
}

impl ThreatSignal {
    /// Create and sign a new threat signal.
    pub fn new(
        identity: &NodeIdentity,
        ip: String,
        detector: String,
        confidence: f32,
        evidence: &[u8],
        ttl_secs: u64,
    ) -> Self {
        let mut signal = Self {
            node_id: identity.node_id.clone(),
            ip,
            detector,
            confidence,
            evidence_hash: sha256_hex(evidence),
            ttl_secs,
            timestamp: Utc::now(),
            signature: String::new(), // placeholder, filled below
        };
        let canonical = signal.canonical_bytes();
        signal.signature = identity.sign(&canonical);
        signal
    }

    /// Canonical byte representation for signing/verification.
    /// Excludes the `signature` field itself.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{:.4}|{}|{}|{}",
            self.node_id,
            self.ip,
            self.detector,
            self.confidence,
            self.evidence_hash,
            self.ttl_secs,
            self.timestamp.to_rfc3339(),
        )
        .into_bytes()
    }

    /// Verify the signal's Ed25519 signature.
    pub fn verify_signature(&self) -> bool {
        let canonical = self.canonical_bytes();
        NodeIdentity::verify(&self.node_id, &canonical, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify() {
        let id = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &id,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.92,
            b"incident evidence json",
            3600,
        );

        assert!(signal.verify_signature());
        assert_eq!(signal.node_id, id.node_id);
        assert_eq!(signal.ip, "1.2.3.4");
        assert_eq!(signal.confidence, 0.92);
    }

    #[test]
    fn tampered_ip_fails_verification() {
        let id = NodeIdentity::generate();
        let mut signal = ThreatSignal::new(
            &id,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.92,
            b"evidence",
            3600,
        );
        signal.ip = "5.6.7.8".to_string(); // tamper
        assert!(!signal.verify_signature());
    }

    #[test]
    fn tampered_confidence_fails_verification() {
        let id = NodeIdentity::generate();
        let mut signal = ThreatSignal::new(
            &id,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.92,
            b"evidence",
            3600,
        );
        signal.confidence = 1.0; // tamper
        assert!(!signal.verify_signature());
    }

    #[test]
    fn wrong_node_id_fails() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let mut signal = ThreatSignal::new(
            &alice,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.85,
            b"evidence",
            3600,
        );
        signal.node_id = bob.node_id.clone(); // impersonate
        assert!(!signal.verify_signature());
    }

    #[test]
    fn serialization_roundtrip() {
        let id = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &id,
            "10.0.0.1".to_string(),
            "port_scan".to_string(),
            0.75,
            b"evidence",
            7200,
        );
        let json = serde_json::to_string(&signal).unwrap();
        let deserialized: ThreatSignal = serde_json::from_str(&json).unwrap();
        assert!(deserialized.verify_signature());
    }
}
