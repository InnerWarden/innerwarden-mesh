use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Information about a known mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Ed25519 public key hex (node identity)
    pub node_id: String,
    /// HTTPS endpoint for sending signals (e.g., "https://10.0.1.5:8790")
    pub endpoint: String,
    /// Human-friendly label (optional)
    pub label: Option<String>,
    /// When this peer was added
    pub added_at: DateTime<Utc>,
}

/// Reputation tracker for a peer — tit-for-tat trust evolution.
///
/// Trust starts at 0.1 (skeptical of new peers).
/// Confirmed signals increase trust by +0.05 (capped at 1.0).
/// Contradicted signals decrease trust by -0.15 (asymmetric penalty).
///
/// This means: 3 confirmed signals to offset 1 contradiction.
/// A malicious peer cannot build trust cheaply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub node_id: String,
    pub signals_sent: u64,
    pub signals_confirmed: u64,
    pub signals_contradicted: u64,
    pub trust_score: f32,
    pub last_signal_at: Option<DateTime<Utc>>,
    /// If set, all signals from this peer are ignored until this time.
    pub quarantined_until: Option<DateTime<Utc>>,
}

const INITIAL_TRUST: f32 = 0.1;
const CONFIRM_BOOST: f32 = 0.05;
const CONTRADICT_PENALTY: f32 = 0.15;

impl PeerReputation {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            signals_sent: 0,
            signals_confirmed: 0,
            signals_contradicted: 0,
            trust_score: INITIAL_TRUST,
            last_signal_at: None,
            quarantined_until: None,
        }
    }

    /// Record a received signal (before confirmation).
    pub fn record_signal(&mut self) {
        self.signals_sent += 1;
        self.last_signal_at = Some(Utc::now());
    }

    /// Local incident confirmed this peer's signal — trust increases.
    pub fn confirm_signal(&mut self) {
        self.signals_confirmed += 1;
        self.trust_score = (self.trust_score + CONFIRM_BOOST).min(1.0);
    }

    /// Signal expired without local confirmation — trust decreases.
    pub fn contradict_signal(&mut self) {
        self.signals_contradicted += 1;
        self.trust_score = (self.trust_score - CONTRADICT_PENALTY).max(0.0);
    }

    /// Whether this peer is currently quarantined.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined_until
            .map(|until| Utc::now() < until)
            .unwrap_or(false)
    }

    /// Quarantine this peer for the given duration.
    pub fn quarantine(&mut self, duration: Duration) {
        self.quarantined_until = Some(Utc::now() + duration);
        self.trust_score = 0.0;
    }

    /// Effective weight of a signal from this peer.
    /// weight = trust_score × signal_confidence
    pub fn effective_weight(&self, signal_confidence: f32) -> f32 {
        if self.is_quarantined() {
            return 0.0;
        }
        self.trust_score * signal_confidence
    }

    /// Confirmation ratio (for diagnostics).
    pub fn confirmation_ratio(&self) -> f32 {
        if self.signals_sent == 0 {
            return 0.0;
        }
        self.signals_confirmed as f32 / self.signals_sent as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_starts_skeptical() {
        let rep = PeerReputation::new("abc123".to_string());
        assert_eq!(rep.trust_score, INITIAL_TRUST);
        assert_eq!(rep.signals_sent, 0);
        assert!(!rep.is_quarantined());
    }

    #[test]
    fn trust_increases_on_confirm() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.confirm_signal();
        assert_eq!(rep.trust_score, INITIAL_TRUST + CONFIRM_BOOST);
        assert_eq!(rep.signals_confirmed, 1);
    }

    #[test]
    fn trust_decreases_on_contradict() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.5;
        rep.contradict_signal();
        assert_eq!(rep.trust_score, 0.5 - CONTRADICT_PENALTY);
        assert_eq!(rep.signals_contradicted, 1);
    }

    #[test]
    fn trust_capped_at_1() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.98;
        rep.confirm_signal();
        assert_eq!(rep.trust_score, 1.0);
    }

    #[test]
    fn trust_floored_at_0() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.05;
        rep.contradict_signal();
        assert_eq!(rep.trust_score, 0.0);
    }

    #[test]
    fn three_confirms_to_offset_one_contradict() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.5;
        rep.contradict_signal(); // 0.5 - 0.15 = 0.35
        rep.confirm_signal(); // 0.35 + 0.05 = 0.40
        rep.confirm_signal(); // 0.40 + 0.05 = 0.45
        rep.confirm_signal(); // 0.45 + 0.05 = 0.50
        assert!((rep.trust_score - 0.5).abs() < 0.001);
    }

    #[test]
    fn quarantine_zeroes_weight() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.9;
        rep.quarantine(Duration::hours(1));
        assert!(rep.is_quarantined());
        assert_eq!(rep.effective_weight(0.95), 0.0);
    }

    #[test]
    fn effective_weight_calculation() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.trust_score = 0.8;
        assert!((rep.effective_weight(0.9) - 0.72).abs() < 0.001);
    }

    #[test]
    fn confirmation_ratio() {
        let mut rep = PeerReputation::new("abc".to_string());
        rep.signals_sent = 10;
        rep.signals_confirmed = 7;
        assert!((rep.confirmation_ratio() - 0.7).abs() < 0.001);
    }
}
