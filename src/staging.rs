use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::peer::PeerReputation;
use crate::signal::ThreatSignal;

/// What action the staging pool took for a signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StagedAction {
    /// Score < 0.3 — discarded, no action
    Discarded,
    /// Score 0.3-0.6 — logged, monitored, no block
    Watchlisted,
    /// Score 0.6-0.8 — blocked with short TTL (1 hour)
    BlockedShortTtl,
    /// Score > 0.8 — blocked for full duration (24 hours)
    BlockedFull,
}

/// A signal that has been received and staged for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedSignal {
    pub signal: ThreatSignal,
    pub weighted_score: f32,
    pub received_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub action: StagedAction,
    /// Node IDs that sent corroborating signals for the same IP
    pub contributing_peers: Vec<String>,
    /// Whether a local incident confirmed this signal
    pub locally_confirmed: bool,
}

/// The staging pool — core safety mechanism of the mesh.
///
/// Signals never cause immediate blocks. They enter the pool,
/// get scored, and only trigger blocks when the weighted score
/// exceeds thresholds. All blocks have TTL and auto-revert.
pub struct StagingPool {
    staged: HashMap<String, StagedSignal>, // keyed by IP
    max_entries: usize,
}

/// Score thresholds for action selection.
const THRESHOLD_DISCARD: f32 = 0.3;
const THRESHOLD_WATCHLIST: f32 = 0.6;
const THRESHOLD_BLOCK_SHORT: f32 = 0.8;

/// TTL values.
const TTL_SHORT_SECS: i64 = 3600; // 1 hour
const TTL_FULL_SECS: i64 = 86400; // 24 hours

impl StagingPool {
    pub fn new(max_entries: usize) -> Self {
        Self {
            staged: HashMap::new(),
            max_entries,
        }
    }

    /// Ingest a new signal. Returns the action taken.
    pub fn ingest(&mut self, signal: ThreatSignal, reputation: &PeerReputation) -> StagedAction {
        let weighted_score = reputation.effective_weight(signal.confidence);
        let ip = signal.ip.clone();
        let now = Utc::now();

        // Check if we already have a staged entry for this IP
        if let Some(existing) = self.staged.get_mut(&ip) {
            // Aggregate: take max score, add contributing peer
            if weighted_score > existing.weighted_score {
                existing.weighted_score = weighted_score;
            }
            if !existing
                .contributing_peers
                .contains(&signal.node_id)
            {
                existing.contributing_peers.push(signal.node_id.clone());
            }
            // Re-evaluate action with new score
            let action = score_to_action(existing.weighted_score);
            existing.action = action.clone();
            existing.expires_at = now + ttl_for_action(&action);
            return action;
        }

        let action = score_to_action(weighted_score);
        let expires_at = now + ttl_for_action(&action);

        if action == StagedAction::Discarded {
            return action;
        }

        // Enforce max entries
        if self.staged.len() >= self.max_entries {
            // Remove oldest expired entry, or oldest entry
            let oldest_key = self
                .staged
                .iter()
                .min_by_key(|(_, v)| v.received_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                self.staged.remove(&key);
            }
        }

        self.staged.insert(
            ip,
            StagedSignal {
                contributing_peers: vec![signal.node_id.clone()],
                signal,
                weighted_score,
                received_at: now,
                expires_at,
                action: action.clone(),
                locally_confirmed: false,
            },
        );

        action
    }

    /// Tick: remove expired entries. Returns IPs that should be unblocked.
    pub fn tick_expirations(&mut self) -> Vec<String> {
        let now = Utc::now();
        let mut to_unblock = Vec::new();

        self.staged.retain(|ip, staged| {
            if staged.expires_at < now {
                // Expired — should unblock if it was a block action
                if matches!(
                    staged.action,
                    StagedAction::BlockedShortTtl | StagedAction::BlockedFull
                ) {
                    to_unblock.push(ip.clone());
                }
                false // remove
            } else {
                true // keep
            }
        });

        to_unblock
    }

    /// Mark a signal as confirmed by a local incident.
    /// This prevents the signal from being counted as a contradiction.
    pub fn confirm_local(&mut self, ip: &str) {
        if let Some(staged) = self.staged.get_mut(ip) {
            staged.locally_confirmed = true;
        }
    }

    /// Get a staged signal by IP.
    pub fn get(&self, ip: &str) -> Option<&StagedSignal> {
        self.staged.get(ip)
    }

    /// All IPs currently blocked by the mesh.
    pub fn active_blocks(&self) -> Vec<(&str, &StagedSignal)> {
        self.staged
            .iter()
            .filter(|(_, v)| {
                matches!(
                    v.action,
                    StagedAction::BlockedShortTtl | StagedAction::BlockedFull
                )
            })
            .map(|(k, v)| (k.as_str(), v))
            .collect()
    }

    /// Check if an IP is currently blocked by the mesh.
    pub fn is_blocked(&self, ip: &str) -> bool {
        self.staged.get(ip).map_or(false, |s| {
            matches!(
                s.action,
                StagedAction::BlockedShortTtl | StagedAction::BlockedFull
            )
        })
    }

    /// All staged signals (for diagnostics/dashboard).
    pub fn all(&self) -> Vec<(&str, &StagedSignal)> {
        self.staged.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }

    /// Number of staged entries.
    pub fn len(&self) -> usize {
        self.staged.len()
    }

    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Collect expired but unconfirmed signals (for contradiction tracking).
    /// Returns (ip, node_ids) pairs.
    pub fn collect_contradictions(&self) -> Vec<(String, Vec<String>)> {
        let now = Utc::now();
        self.staged
            .iter()
            .filter(|(_, v)| v.expires_at < now && !v.locally_confirmed)
            .map(|(ip, v)| (ip.clone(), v.contributing_peers.clone()))
            .collect()
    }
}

fn score_to_action(score: f32) -> StagedAction {
    if score >= THRESHOLD_BLOCK_SHORT {
        StagedAction::BlockedFull
    } else if score >= THRESHOLD_WATCHLIST {
        StagedAction::BlockedShortTtl
    } else if score >= THRESHOLD_DISCARD {
        StagedAction::Watchlisted
    } else {
        StagedAction::Discarded
    }
}

fn ttl_for_action(action: &StagedAction) -> Duration {
    match action {
        StagedAction::BlockedFull => Duration::seconds(TTL_FULL_SECS),
        StagedAction::BlockedShortTtl => Duration::seconds(TTL_SHORT_SECS),
        StagedAction::Watchlisted => Duration::hours(2),
        StagedAction::Discarded => Duration::zero(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reputation(trust: f32) -> PeerReputation {
        let mut rep = PeerReputation::new("peer1".to_string());
        rep.trust_score = trust;
        rep
    }

    fn make_signal(ip: &str, confidence: f32) -> ThreatSignal {
        use crate::crypto::NodeIdentity;
        let id = NodeIdentity::generate();
        ThreatSignal::new(
            &id,
            ip.to_string(),
            "ssh_bruteforce".to_string(),
            confidence,
            b"evidence",
            3600,
        )
    }

    #[test]
    fn low_score_discarded() {
        let mut pool = StagingPool::new(100);
        let rep = make_reputation(0.1); // trust 0.1 * confidence 0.5 = 0.05
        let action = pool.ingest(make_signal("1.2.3.4", 0.5), &rep);
        assert_eq!(action, StagedAction::Discarded);
        assert!(pool.is_empty());
    }

    #[test]
    fn medium_score_watchlisted() {
        let mut pool = StagingPool::new(100);
        let rep = make_reputation(0.5); // 0.5 * 0.8 = 0.4
        let action = pool.ingest(make_signal("1.2.3.4", 0.8), &rep);
        assert_eq!(action, StagedAction::Watchlisted);
        assert!(!pool.is_blocked("1.2.3.4"));
    }

    #[test]
    fn high_score_blocked_short() {
        let mut pool = StagingPool::new(100);
        let rep = make_reputation(0.8); // 0.8 * 0.85 = 0.68
        let action = pool.ingest(make_signal("1.2.3.4", 0.85), &rep);
        assert_eq!(action, StagedAction::BlockedShortTtl);
        assert!(pool.is_blocked("1.2.3.4"));
    }

    #[test]
    fn very_high_score_blocked_full() {
        let mut pool = StagingPool::new(100);
        let rep = make_reputation(0.9); // 0.9 * 0.95 = 0.855
        let action = pool.ingest(make_signal("1.2.3.4", 0.95), &rep);
        assert_eq!(action, StagedAction::BlockedFull);
        assert!(pool.is_blocked("1.2.3.4"));
    }

    #[test]
    fn multiple_peers_aggregate() {
        let mut pool = StagingPool::new(100);
        let rep1 = make_reputation(0.4); // 0.4 * 0.8 = 0.32 → watchlisted
        pool.ingest(make_signal("1.2.3.4", 0.8), &rep1);
        assert_eq!(pool.get("1.2.3.4").unwrap().action, StagedAction::Watchlisted);

        // Second peer with higher trust: 0.85 * 0.9 = 0.765 → blocked short TTL
        let rep2 = make_reputation(0.85);
        pool.ingest(make_signal("1.2.3.4", 0.9), &rep2);
        assert_eq!(
            pool.get("1.2.3.4").unwrap().action,
            StagedAction::BlockedShortTtl
        );
    }

    #[test]
    fn local_confirmation() {
        let mut pool = StagingPool::new(100);
        let rep = make_reputation(0.8);
        pool.ingest(make_signal("1.2.3.4", 0.85), &rep);
        pool.confirm_local("1.2.3.4");
        assert!(pool.get("1.2.3.4").unwrap().locally_confirmed);
    }

    #[test]
    fn max_entries_eviction() {
        let mut pool = StagingPool::new(2);
        let rep = make_reputation(0.5);
        pool.ingest(make_signal("1.1.1.1", 0.8), &rep);
        pool.ingest(make_signal("2.2.2.2", 0.8), &rep);
        pool.ingest(make_signal("3.3.3.3", 0.8), &rep);
        assert_eq!(pool.len(), 2); // oldest evicted
    }

    #[test]
    fn quarantined_peer_zero_weight() {
        let mut pool = StagingPool::new(100);
        let mut rep = make_reputation(0.9);
        rep.quarantine(chrono::Duration::hours(1));
        let action = pool.ingest(make_signal("1.2.3.4", 0.95), &rep);
        assert_eq!(action, StagedAction::Discarded);
    }
}
