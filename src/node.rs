use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn};

use crate::config::MeshConfig;
use crate::crypto::NodeIdentity;
use crate::peer::{PeerInfo, PeerReputation};
use crate::persistence;
use crate::signal::ThreatSignal;
use crate::staging::{StagedAction, StagingPool};
use crate::transport::{self, MeshClient, MeshServerState};
use crate::validation::RateLimiter;

/// Result of a mesh tick — tells the agent what to do.
pub struct MeshTickResult {
    /// IPs to block locally (ip, ttl_secs)
    pub block_ips: Vec<(String, u64)>,
    /// IPs to unblock (TTL expired, no local confirmation)
    pub unblock_ips: Vec<String>,
    /// Peers that were quarantined this tick
    pub quarantined_peers: Vec<String>,
    /// Peers whose signals were contradicted (for trust decay)
    pub contradicted_peers: Vec<(String, Vec<String>)>,
}

/// A live suppression advisory handed to the agent (spec 062 Phase 6b). The
/// agent applies it ONLY as corroboration for a shape it already dismisses
/// locally — never as an independent trigger.
#[derive(Debug, Clone)]
pub struct AdvisorySuppression {
    pub node_id: String,
    pub detector: String,
    pub ip: String,
    pub dismissals: u64,
    pub peer_trust: f32,
}

impl AdvisorySuppression {
    /// The shape key: `detector|ip`.
    pub fn shape(&self) -> String {
        format!("{}|{}", self.detector, self.ip)
    }
}

/// The main mesh node — assembles all components.
/// Created by the agent, stored in AgentState.
pub struct MeshNode {
    pub identity: Arc<NodeIdentity>,
    peers: Vec<PeerInfo>,
    server_state: Arc<MeshServerState>,
    client: MeshClient,
    config: MeshConfig,
    data_dir: std::path::PathBuf,
    /// Tracks which IPs we've already told the agent to block
    /// (prevents re-emitting on every tick).
    notified_blocks: std::collections::HashSet<String>,
    /// Last time we ran peer discovery (for periodic re-discovery).
    last_discovery: chrono::DateTime<Utc>,
    /// The listener's certificate and key (`tls::listener_cert_paths`).
    listener_cert: (std::path::PathBuf, std::path::PathBuf),
}

impl MeshNode {
    /// Create a new mesh node. Loads identity and state from disk.
    pub fn new(config: MeshConfig, data_dir: &Path) -> Result<Self> {
        let identity_path = data_dir.join("mesh-identity.key");
        let identity = Arc::new(NodeIdentity::load_or_create(&identity_path)?);
        info!(node_id = %identity.node_id, "mesh: node identity loaded");

        // Load persisted state
        let state = persistence::load_state(data_dir)?;

        // Restore reputations
        let mut reputations: HashMap<String, PeerReputation> = HashMap::new();
        for rep in state.reputations {
            reputations.insert(rep.node_id.clone(), rep);
        }

        // The peers are the configured ones the client accepted, nothing
        // else. A peer persisted from an earlier run, or learned over a
        // connection nobody checked, is not one: its node id is read again,
        // over its checked certificate, or taken from its `public_key`.
        let (client, refused) = MeshClient::for_peers(&config.peers);
        for r in &refused {
            warn!(endpoint = %r.endpoint, reason = %r.reason, "mesh: peer refused, never contacted");
        }
        let mut peers: Vec<PeerInfo> = Vec::new();
        let mut known_peers: HashSet<String> = HashSet::new();
        for pe in &config.peers {
            if !client.contacts(&pe.endpoint) || peers.iter().any(|p| p.endpoint == pe.endpoint) {
                continue;
            }
            let key = pe.public_key.trim();
            if !key.is_empty() {
                if !NodeIdentity::is_node_id(key) {
                    warn!(endpoint = %pe.endpoint, "mesh: peer refused, public_key is not an Ed25519 key in hex");
                    continue;
                }
                known_peers.insert(key.to_string());
            }
            peers.push(PeerInfo {
                node_id: key.to_string(),
                endpoint: pe.endpoint.clone(),
                label: pe.label.clone(),
                added_at: Utc::now(),
            });
        }
        drop(state.peers);

        let listener_cert = crate::tls::listener_cert_paths(
            data_dir,
            config.tls_cert.as_deref(),
            config.tls_key.as_deref(),
        )?;
        match crate::tls::cert_file_sha256(&listener_cert.0) {
            Ok(sha) => info!(
                cert = %listener_cert.0.display(),
                sha256 = %crate::tls::format_sha256(&sha),
                "mesh: listener certificate (peers pin this as tls_cert_sha256)"
            ),
            Err(e) => warn!(error = %format!("{e:#}"), "mesh: listener certificate unreadable"),
        }

        // Restore staging pool
        let mut staging = StagingPool::new(config.max_staged);
        // TODO: restore staged entries from persistence

        let server_state = Arc::new(MeshServerState {
            identity: identity.clone(),
            staging: Arc::new(Mutex::new(staging)),
            reputations: Arc::new(Mutex::new(reputations)),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.max_signals_per_hour))),
            suppressions: Arc::new(Mutex::new(Vec::new())),
            known_peers: Arc::new(Mutex::new(known_peers)),
            config: config.clone(),
        });

        Ok(Self {
            identity,
            peers,
            server_state,
            client,
            config,
            data_dir: data_dir.to_path_buf(),
            notified_blocks: std::collections::HashSet::new(),
            last_discovery: chrono::DateTime::<Utc>::MIN_UTC,
            listener_cert,
        })
    }

    /// Start the inbound HTTPS listener, answering with the listener
    /// certificate (`tls_cert`/`tls_key`, or the node's own pair).
    pub async fn start_listener(&self) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let tls = crate::tls::server_config(&self.listener_cert.0, &self.listener_cert.1)?;
        transport::start_server(self.server_state.clone(), &self.config.bind, Some(tls)).await
    }

    /// The SHA-256 of the listener's certificate, in openssl's form: what a
    /// peer sets as `tls_cert_sha256` for this node.
    pub fn listener_cert_sha256(&self) -> Result<String> {
        Ok(crate::tls::format_sha256(&crate::tls::cert_file_sha256(
            &self.listener_cert.0,
        )?))
    }

    /// Discover peer identities by pinging their endpoints.
    /// Resolves node_ids and sets initial trust for config-defined peers.
    pub async fn discover_peers(&mut self) {
        let initial_trust = self.config.initial_trust;
        let mut resolved = Vec::new();

        for peer in &self.peers {
            info!(endpoint = %peer.endpoint, "mesh: pinging peer...");
            match self.client.ping(peer).await {
                // A peer configured with a key that answers as another node
                // is misconfigured or not the peer: its answer is not taken.
                Some(resp) if !peer.node_id.is_empty() && resp.node_id != peer.node_id => {
                    warn!(
                        endpoint = %peer.endpoint,
                        answered = &resp.node_id[..16.min(resp.node_id.len())],
                        "mesh: peer answered with a node id other than its configured public_key; \
                         only the configured key is accepted"
                    );
                    resolved.push(peer.clone());
                }
                Some(resp) if !NodeIdentity::is_node_id(&resp.node_id) => {
                    warn!(endpoint = %peer.endpoint, "mesh: peer answered with no valid node id");
                    resolved.push(peer.clone());
                }
                Some(resp) => {
                    info!(
                        endpoint = %peer.endpoint,
                        peer_node_id = &resp.node_id[..16.min(resp.node_id.len())],
                        "mesh: peer discovered"
                    );
                    // Read over the peer's checked certificate: this id is
                    // the peer's, and its signals are accepted from now on.
                    self.server_state
                        .known_peers
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(resp.node_id.clone());
                    // Update peer with real node_id
                    resolved.push(PeerInfo {
                        node_id: resp.node_id.clone(),
                        endpoint: peer.endpoint.clone(),
                        label: peer.label.clone(),
                        added_at: peer.added_at,
                    });
                    // Set initial trust for config-defined peers
                    let mut reps = self.server_state.reputations.lock().unwrap();
                    let rep = reps
                        .entry(resp.node_id.clone())
                        .or_insert_with(|| PeerReputation::new(resp.node_id));
                    if rep.signals_sent == 0 {
                        // Only set initial trust if no history yet
                        rep.trust_score = initial_trust;
                    }
                }
                None => {
                    warn!(endpoint = %peer.endpoint, "mesh: peer unreachable");
                    resolved.push(peer.clone()); // keep for retry later
                }
            }
        }

        self.peers = resolved;
        self.last_discovery = Utc::now();
        info!(peers = self.peers.len(), "mesh: peer discovery complete");
    }

    /// Re-run discovery if enough time has passed or there are undiscovered peers.
    /// Call this periodically (e.g., from the agent's slow loop).
    pub async fn rediscover_if_needed(&mut self) {
        let interval = chrono::Duration::seconds(self.config.poll_secs as i64 * 2);
        if Utc::now() - self.last_discovery < interval {
            return;
        }

        // Peers whose node id is not known yet (configured without a
        // `public_key` and not reached since). A refused peer is not in
        // `self.peers` and is never retried: its configuration has to change.
        let undiscovered = self.peers.iter().any(|p| p.node_id.is_empty());
        if undiscovered {
            info!(undiscovered, "mesh: re-running peer discovery");
            self.discover_peers().await;
        }
    }

    /// Broadcast a local block decision to all peers.
    pub async fn broadcast_local_block(
        &self,
        ip: &str,
        detector: &str,
        confidence: f32,
        evidence: &[u8],
        ttl_secs: u64,
    ) {
        if !self.config.auto_broadcast {
            return;
        }

        let signal = ThreatSignal::new(
            &self.identity,
            ip.to_string(),
            detector.to_string(),
            confidence,
            evidence,
            ttl_secs,
        );

        // Log the outbound signal
        if let Err(e) = persistence::append_signal_log(&self.data_dir, &signal) {
            warn!(error = %e, "mesh: failed to log outbound signal");
        }

        let mut sent = 0;
        for peer in &self.peers {
            if self.client.send_signal(peer, &signal).await {
                sent += 1;
            }
        }
        info!(
            ip,
            detector,
            confidence,
            peers_notified = sent,
            peers_total = self.peers.len(),
            "mesh: broadcast local block"
        );
    }

    /// Broadcast a local learned-suppression to all peers (spec 062 Phase 6b).
    ///
    /// Advisory only: peers record it but never auto-suppress on it — see
    /// [`crate::signal::SuppressionSignal`]. Reuses `auto_broadcast` so an
    /// operator who disabled outbound block signals also stays silent here.
    pub async fn broadcast_local_suppression(
        &self,
        detector: &str,
        ip: &str,
        dismissals: u64,
        ttl_secs: u64,
    ) {
        if !self.config.auto_broadcast {
            return;
        }
        let signal = crate::signal::SuppressionSignal::new(
            &self.identity,
            detector.to_string(),
            ip.to_string(),
            dismissals,
            ttl_secs,
        );
        let mut sent = 0;
        for peer in &self.peers {
            if self.client.send_suppression(peer, &signal).await {
                sent += 1;
            }
        }
        info!(
            detector,
            ip,
            dismissals,
            peers_notified = sent,
            peers_total = self.peers.len(),
            "mesh: broadcast local suppression (advisory)"
        );
    }

    /// Drain the suppression-advisory inbox, dropping any that have expired.
    /// Returns the live advisories for the agent to apply under its OWN gate
    /// (the shape must already be locally dismissed). The mesh layer never
    /// suppresses anything itself.
    pub fn drain_advisory_suppressions(&mut self) -> Vec<AdvisorySuppression> {
        let now = Utc::now();
        let mut inbox = self.server_state.suppressions.lock().unwrap();
        let drained: Vec<AdvisorySuppression> = inbox
            .iter()
            .filter(|s| s.expires_at > now)
            .map(|s| AdvisorySuppression {
                node_id: s.node_id.clone(),
                detector: s.detector.clone(),
                ip: s.ip.clone(),
                dismissals: s.dismissals,
                peer_trust: s.peer_trust,
            })
            .collect();
        inbox.clear();
        drained
    }

    /// Called by agent on each slow-loop tick.
    /// Returns actions for the agent to execute.
    pub fn tick(&mut self) -> MeshTickResult {
        let mut result = MeshTickResult {
            block_ips: vec![],
            unblock_ips: vec![],
            quarantined_peers: vec![],
            contradicted_peers: vec![],
        };

        let mut staging = self.server_state.staging.lock().unwrap();

        // Expire old entries
        result.unblock_ips = staging.tick_expirations();

        // Collect new blocks that we haven't notified the agent about yet
        for (ip, staged) in staging.active_blocks() {
            if !self.notified_blocks.contains(ip) {
                let ttl = (staged.expires_at - Utc::now()).num_seconds().max(0) as u64;
                result.block_ips.push((ip.to_string(), ttl));
                self.notified_blocks.insert(ip.to_string());
            }
        }

        // Clean notified_blocks for unblocked IPs
        for ip in &result.unblock_ips {
            self.notified_blocks.remove(ip);
        }

        // Collect contradictions (expired + unconfirmed) for trust decay
        let contradictions = staging.collect_contradictions();
        drop(staging); // release lock before modifying reputations

        if !contradictions.is_empty() {
            let mut reps = self.server_state.reputations.lock().unwrap();
            for (ip, peer_ids) in &contradictions {
                for peer_id in peer_ids {
                    if let Some(rep) = reps.get_mut(peer_id) {
                        rep.contradict_signal();
                        info!(
                            peer = %peer_id,
                            ip,
                            trust = rep.trust_score,
                            "mesh: signal contradicted — trust decreased"
                        );
                    }
                }
            }
            result.contradicted_peers = contradictions;
        }

        result
    }

    /// Check if an IP is blocked by the mesh.
    pub fn is_mesh_blocked(&self, ip: &str) -> bool {
        self.server_state.staging.lock().unwrap().is_blocked(ip)
    }

    /// Notify mesh that a local incident confirmed a staged signal.
    /// Increases trust for the peer that sent it.
    pub fn confirm_local_incident(&self, ip: &str) {
        let mut staging = self.server_state.staging.lock().unwrap();
        if let Some(staged) = staging.get(ip) {
            let peer_ids = staged.contributing_peers.clone();
            staging.confirm_local(ip);
            drop(staging);

            let mut reps = self.server_state.reputations.lock().unwrap();
            for peer_id in &peer_ids {
                if let Some(rep) = reps.get_mut(peer_id) {
                    rep.confirm_signal();
                    info!(
                        peer = %peer_id,
                        ip,
                        trust = rep.trust_score,
                        "mesh: signal confirmed locally — trust increased"
                    );
                }
            }
        }
    }

    /// Save state to disk.
    pub fn persist(&self) -> Result<()> {
        let peers = self.peers.clone();
        let reputations: Vec<PeerReputation> = self
            .server_state
            .reputations
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();

        let state = persistence::MeshState {
            peers,
            reputations,
            staged: vec![], // TODO: serialize staging pool
        };
        persistence::save_state(&self.data_dir, &state)
    }

    /// Number of configured peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Node identity string (for logging/display).
    pub fn node_id(&self) -> &str {
        &self.identity.node_id
    }

    /// Get peer summaries for dashboard.
    pub fn peer_summaries(&self) -> Vec<PeerSummary> {
        let reps = self.server_state.reputations.lock().unwrap();
        self.peers
            .iter()
            .map(|p| {
                let rep = reps.get(&p.node_id);
                PeerSummary {
                    node_id: p.node_id.clone(),
                    endpoint: p.endpoint.clone(),
                    label: p.label.clone(),
                    trust_score: rep.map(|r| r.trust_score).unwrap_or(0.1),
                    signals_sent: rep.map(|r| r.signals_sent).unwrap_or(0),
                    signals_confirmed: rep.map(|r| r.signals_confirmed).unwrap_or(0),
                    quarantined: rep.map(|r| r.is_quarantined()).unwrap_or(false),
                }
            })
            .collect()
    }

    /// Get staged signal count for dashboard.
    pub fn staged_count(&self) -> usize {
        self.server_state.staging.lock().unwrap().len()
    }

    /// Get active block count for dashboard.
    pub fn active_block_count(&self) -> usize {
        self.server_state
            .staging
            .lock()
            .unwrap()
            .active_blocks()
            .len()
    }
}

/// Summary of a peer for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerSummary {
    pub node_id: String,
    pub endpoint: String,
    pub label: Option<String>,
    pub trust_score: f32,
    pub signals_sent: u64,
    pub signals_confirmed: u64,
    pub quarantined: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn create_node_and_start() {
        let dir = tempfile::tempdir().unwrap();
        let config = MeshConfig::default();
        let node = MeshNode::new(config, dir.path()).unwrap();
        assert!(!node.node_id().is_empty());
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.staged_count(), 0);
    }

    #[tokio::test]
    async fn drain_advisory_suppressions_drops_expired_and_clears_inbox() {
        use crate::transport::ReceivedSuppression;
        let dir = tempfile::tempdir().unwrap();
        let mut node = MeshNode::new(MeshConfig::default(), dir.path()).unwrap();
        let now = Utc::now();
        {
            let mut inbox = node.server_state.suppressions.lock().unwrap();
            // live
            inbox.push(ReceivedSuppression {
                node_id: "peer-a".into(),
                detector: "web_scan".into(),
                ip: "8.8.8.8".into(),
                dismissals: 9,
                peer_trust: 0.9,
                received_at: now,
                expires_at: now + chrono::Duration::hours(1),
            });
            // expired
            inbox.push(ReceivedSuppression {
                node_id: "peer-b".into(),
                detector: "nmap_scan".into(),
                ip: "9.9.9.9".into(),
                dismissals: 3,
                peer_trust: 0.85,
                received_at: now - chrono::Duration::hours(2),
                expires_at: now - chrono::Duration::hours(1),
            });
        }
        let live = node.drain_advisory_suppressions();
        assert_eq!(live.len(), 1, "expired advisory must be dropped");
        assert_eq!(live[0].shape(), "web_scan|8.8.8.8");
        // Inbox is drained either way.
        assert_eq!(node.server_state.suppressions.lock().unwrap().len(), 0);
        // Second drain is empty.
        assert!(node.drain_advisory_suppressions().is_empty());
    }

    fn loopback_config(peers: Vec<crate::config::PeerEntry>) -> MeshConfig {
        MeshConfig {
            bind: "127.0.0.1:0".to_string(),
            peers,
            initial_trust: 0.9,
            ..MeshConfig::default()
        }
    }

    /// A node listening on loopback with no peers: its endpoint, its
    /// certificate's digest and its node id, as another node configures it.
    async fn listening(dir: &Path) -> (SocketAddr, String, String, tokio::task::JoinHandle<()>) {
        let node = MeshNode::new(loopback_config(vec![]), dir).unwrap();
        let (addr, h) = node.start_listener().await.unwrap();
        (
            addr,
            node.listener_cert_sha256().unwrap(),
            node.node_id().to_string(),
            h,
        )
    }

    fn pinned(addr: SocketAddr, sha: &str, key: &str) -> crate::config::PeerEntry {
        crate::config::PeerEntry {
            endpoint: format!("https://{addr}"),
            public_key: key.to_string(),
            label: None,
            tls_cert_sha256: Some(sha.to_string()),
            tls_ca: None,
        }
    }

    /// Both sides as an operator configures them: A pins B's certificate, B
    /// names A's key and pins A's certificate. A's block reaches B and B
    /// stages it.
    #[tokio::test]
    async fn two_nodes_full_flow() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let (addr_a, sha_a, id_a, _ha) = listening(dir_a.path()).await;

        let mut node_b = MeshNode::new(
            loopback_config(vec![pinned(addr_a, &sha_a, &id_a)]),
            dir_b.path(),
        )
        .unwrap();
        let (addr_b, _hb) = node_b.start_listener().await.unwrap();
        let sha_b = node_b.listener_cert_sha256().unwrap();
        // B reads A over A's pinned certificate: A's configured trust.
        node_b.discover_peers().await;

        // A again (same data dir: same identity and certificate), now with B.
        let node_a = MeshNode::new(
            loopback_config(vec![pinned(addr_b, &sha_b, "")]),
            dir_a.path(),
        )
        .unwrap();
        assert_eq!(node_a.node_id(), id_a);
        assert_eq!(node_a.peer_count(), 1);
        node_a
            .broadcast_local_block("9.8.7.6", "c2_callback", 0.92, b"evidence", 3600)
            .await;

        // Node B ticks — should have a block
        let result = node_b.tick();
        assert!(result.block_ips.iter().any(|(ip, _)| ip == "9.8.7.6"));
        assert!(node_b.is_mesh_blocked("9.8.7.6"));

        // Node B confirms locally — trust should increase
        node_b.confirm_local_incident("9.8.7.6");
        let reps = node_b.server_state.reputations.lock().unwrap();
        let rep = reps.get(&id_a).unwrap();
        assert!(rep.trust_score > 0.9); // was 0.9, confirm adds 0.05
        assert_eq!(rep.signals_confirmed, 1);
    }

    fn accepts(node: &MeshNode, sender: &str) -> bool {
        node.server_state
            .known_peers
            .lock()
            .unwrap()
            .contains(sender)
    }

    /// A peer configured without a key: its id is learned from its ping over
    /// its pinned certificate, and only then are its signals taken.
    #[tokio::test]
    async fn a_peer_without_a_key_is_heard_only_after_its_checked_ping() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let (addr_a, sha_a, id_a, _ha) = listening(dir_a.path()).await;
        let mut node_b = MeshNode::new(
            loopback_config(vec![pinned(addr_a, &sha_a, "")]),
            dir_b.path(),
        )
        .unwrap();
        assert!(!accepts(&node_b, &id_a));
        node_b.discover_peers().await;
        assert!(accepts(&node_b, &id_a));
    }

    /// FAILS ON REVERT (the configured-key check in `discover_peers`): a peer
    /// configured with one key that answers as another node gets the other
    /// node's signals accepted.
    #[tokio::test]
    async fn a_peer_answering_as_another_node_than_its_key_is_not_taken() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let (addr_a, sha_a, id_a, _ha) = listening(dir_a.path()).await;
        let configured = NodeIdentity::generate().node_id;
        let mut node_b = MeshNode::new(
            loopback_config(vec![pinned(addr_a, &sha_a, &configured)]),
            dir_b.path(),
        )
        .unwrap();
        node_b.discover_peers().await;
        assert!(accepts(&node_b, &configured));
        assert!(
            !accepts(&node_b, &id_a),
            "took the id the endpoint answered with"
        );
        assert!(node_b.server_state.reputations.lock().unwrap().is_empty());
    }

    /// A configured peer with no way to check its certificate, over plain
    /// HTTP, or with a key that is not one, is not a peer at all; and a peer
    /// persisted from an earlier run is never contacted again.
    #[tokio::test]
    async fn refused_and_persisted_peers_are_not_peers() {
        let dir = tempfile::tempdir().unwrap();
        let state = persistence::MeshState {
            peers: vec![PeerInfo {
                node_id: NodeIdentity::generate().node_id,
                endpoint: "https://203.0.113.9:8790".into(),
                label: None,
                added_at: Utc::now(),
            }],
            ..Default::default()
        };
        persistence::save_state(dir.path(), &state).unwrap();
        let pin = "ab".repeat(32);
        let mut no_check = pinned("127.0.0.1:9".parse().unwrap(), &pin, "");
        no_check.tls_cert_sha256 = None;
        let mut plain = pinned("127.0.0.1:10".parse().unwrap(), &pin, "");
        plain.endpoint = "http://127.0.0.1:10".into();
        let bad_key = pinned("127.0.0.1:11".parse().unwrap(), &pin, "not-a-key");
        let good = pinned("127.0.0.1:12".parse().unwrap(), &pin, "");
        let node = MeshNode::new(
            loopback_config(vec![no_check, plain, bad_key, good]),
            dir.path(),
        )
        .unwrap();
        let endpoints: Vec<String> = node.peers.iter().map(|p| p.endpoint.clone()).collect();
        assert_eq!(endpoints, vec!["https://127.0.0.1:12".to_string()]);
        assert!(node.server_state.known_peers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();

        let node1 = MeshNode::new(MeshConfig::default(), dir.path()).unwrap();
        let node_id = node1.node_id().to_string();
        node1.persist().unwrap();

        let node2 = MeshNode::new(MeshConfig::default(), dir.path()).unwrap();
        assert_eq!(node2.node_id(), node_id); // same identity
    }
}
