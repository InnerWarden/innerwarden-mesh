use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};

use crate::signal::ThreatSignal;

/// Validation errors for inbound signals.
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    PrivateIp,
    InvalidConfidence,
    TimestampTooFarFuture,
    TimestampTooOld,
    InvalidSignature,
    RateLimited,
    Quarantined,
}

/// Validate a signal before processing.
pub fn validate_signal(signal: &ThreatSignal) -> Result<(), ValidationError> {
    // Reject private/reserved IPs
    if is_private_ip(&signal.ip) {
        return Err(ValidationError::PrivateIp);
    }

    // Confidence must be in [0.0, 1.0]
    if signal.confidence < 0.0 || signal.confidence > 1.0 {
        return Err(ValidationError::InvalidConfidence);
    }

    // Timestamp: not more than 5 minutes in the future
    let now = Utc::now();
    if signal.timestamp > now + Duration::minutes(5) {
        return Err(ValidationError::TimestampTooFarFuture);
    }

    // Timestamp: not more than 1 hour in the past
    if signal.timestamp < now - Duration::hours(1) {
        return Err(ValidationError::TimestampTooOld);
    }

    // Verify Ed25519 signature
    if !signal.verify_signature() {
        return Err(ValidationError::InvalidSignature);
    }

    Ok(())
}

/// Returns true if the IP is private, loopback, link-local, or reserved.
pub fn is_private_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return true; // unparseable = reject
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Per-peer rate limiter. Tracks signal timestamps in a sliding window.
pub struct RateLimiter {
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    max_per_hour: usize,
}

impl RateLimiter {
    pub fn new(max_per_hour: usize) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_hour,
        }
    }

    /// Check if a peer is within rate limits. Returns true if allowed.
    pub fn check(&mut self, peer_id: &str) -> bool {
        let now = Utc::now();
        let cutoff = now - Duration::hours(1);
        let window = self.windows.entry(peer_id.to_string()).or_default();
        window.retain(|ts| *ts > cutoff);
        if window.len() >= self.max_per_hour {
            return false;
        }
        window.push_back(now);
        true
    }

    /// Check if a peer should be quarantined (consistently exceeding limits).
    pub fn should_quarantine(&self, peer_id: &str) -> bool {
        let Some(window) = self.windows.get(peer_id) else {
            return false;
        };
        window.len() >= self.max_per_hour
    }

    /// Number of signals from a peer in the last hour.
    pub fn count(&self, peer_id: &str) -> usize {
        self.windows.get(peer_id).map(|w| w.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeIdentity;

    fn valid_signal() -> ThreatSignal {
        let id = NodeIdentity::generate();
        ThreatSignal::new(
            &id,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.85,
            b"evidence",
            3600,
        )
    }

    #[test]
    fn accepts_valid_signal() {
        assert!(validate_signal(&valid_signal()).is_ok());
    }

    #[test]
    fn rejects_private_ip() {
        let id = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &id,
            "192.168.1.1".to_string(),
            "test".to_string(),
            0.9,
            b"e",
            3600,
        );
        assert_eq!(
            validate_signal(&signal),
            Err(ValidationError::PrivateIp)
        );
    }

    #[test]
    fn rejects_loopback() {
        let id = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &id,
            "127.0.0.1".to_string(),
            "test".to_string(),
            0.9,
            b"e",
            3600,
        );
        assert_eq!(
            validate_signal(&signal),
            Err(ValidationError::PrivateIp)
        );
    }

    #[test]
    fn rejects_invalid_confidence() {
        let id = NodeIdentity::generate();
        let mut signal = ThreatSignal::new(
            &id,
            "1.2.3.4".to_string(),
            "test".to_string(),
            1.5, // invalid
            b"e",
            3600,
        );
        // Re-sign won't help — confidence is out of range
        assert_eq!(
            validate_signal(&signal),
            Err(ValidationError::InvalidConfidence)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut signal = valid_signal();
        signal.ip = "5.6.7.8".to_string(); // tamper after signing
        assert_eq!(
            validate_signal(&signal),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.check("peer1"));
        assert!(rl.check("peer1"));
        assert!(rl.check("peer1"));
        assert!(!rl.check("peer1")); // 4th should fail
    }

    #[test]
    fn rate_limiter_independent_per_peer() {
        let mut rl = RateLimiter::new(2);
        assert!(rl.check("peer1"));
        assert!(rl.check("peer1"));
        assert!(!rl.check("peer1"));
        assert!(rl.check("peer2")); // different peer, fresh window
    }

    #[test]
    fn rate_limiter_quarantine_detection() {
        let mut rl = RateLimiter::new(2);
        rl.check("peer1");
        rl.check("peer1");
        assert!(rl.should_quarantine("peer1"));
        assert!(!rl.should_quarantine("peer2"));
    }

    #[test]
    fn private_ip_detection() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("0.0.0.0"));
        assert!(!is_private_ip("1.2.3.4"));
        assert!(!is_private_ip("8.8.8.8"));
    }
}
