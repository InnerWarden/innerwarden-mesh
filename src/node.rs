use std::collections::HashMap;
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

        // Merge config peers with persisted peers.
        // Dedup by endpoint (not node_id) because config peers may have empty
        // public_key — those get resolved later via discover_peers().
        let mut peers: Vec<PeerInfo> = state.peers;
        for pe in &config.peers {
            if !peers.iter().any(|p| p.endpoint == pe.endpoint) {
                peers.push(PeerInfo {
                    node_id: pe.public_key.clone(),
                    endpoint: pe.endpoint.clone(),
                    label: pe.label.clone(),
                    added_at: Utc::now(),
                });
            }
        }

        // Restore staging pool
        let mut staging = StagingPool::new(config.max_staged);
        // TODO: restore staged entries from persistence

        let server_state = Arc::new(MeshServerState {
            identity: identity.clone(),
            staging: Arc::new(Mutex::new(staging)),
            reputations: Arc::new(Mutex::new(reputations)),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.max_signals_per_hour))),
            config: config.clone(),
        });

        Ok(Self {
            identity,
            peers,
            server_state,
            client: MeshClient::new(),
            config,
            data_dir: data_dir.to_path_buf(),
            notified_blocks: std::collections::HashSet::new(),
            last_discovery: chrono::DateTime::<Utc>::MIN_UTC,
        })
    }

    /// Start the inbound HTTPS listener.
    pub async fn start_listener(&self) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        transport::start_server(self.server_state.clone(), &self.config.bind).await
    }

    /// Discover peer identities by pinging their endpoints.
    /// Resolves node_ids and sets initial trust for config-defined peers.
    pub async fn discover_peers(&mut self) {
        let initial_trust = self.config.initial_trust;
        let mut resolved = Vec::new();

        for peer in &self.peers {
            info!(endpoint = %peer.endpoint, "mesh: pinging peer...");
            match self.client.ping(peer).await {
                Some(resp) => {
                    info!(
                        endpoint = %peer.endpoint,
                        peer_node_id = &resp.node_id[..16.min(resp.node_id.len())],
                        "mesh: peer discovered"
                    );
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

        // Check if any peers still have empty node_ids (not yet discovered)
        let undiscovered = self.peers.iter().any(|p| p.node_id.is_empty());
        // Also re-discover if we have fewer active peers than configured
        let fewer_than_config = self.peers.len() < self.config.peers.len();

        if undiscovered || fewer_than_config {
            info!(
                undiscovered,
                fewer_than_config,
                "mesh: re-running peer discovery"
            );
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
            ip, detector, confidence,
            peers_notified = sent,
            peers_total = self.peers.len(),
            "mesh: broadcast local block"
        );
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
        self.server_state.staging.lock().unwrap().active_blocks().len()
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
    async fn two_nodes_full_flow() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        // Create Node A
        let mut cfg_a = MeshConfig::default();
        cfg_a.bind = "127.0.0.1:0".to_string();
        let node_a = MeshNode::new(cfg_a, dir_a.path()).unwrap();
        let (addr_a, _h1) = node_a.start_listener().await.unwrap();

        // Create Node B
        let mut cfg_b = MeshConfig::default();
        cfg_b.bind = "127.0.0.1:0".to_string();
        let mut node_b = MeshNode::new(cfg_b, dir_b.path()).unwrap();
        let (addr_b, _h2) = node_b.start_listener().await.unwrap();

        // Give Node B high trust for Node A
        {
            let mut reps = node_b.server_state.reputations.lock().unwrap();
            let mut rep = PeerReputation::new(node_a.identity.node_id.clone());
            rep.trust_score = 0.9;
            reps.insert(node_a.identity.node_id.clone(), rep);
        }

        // Node A broadcasts to Node B
        let peer_b = PeerInfo {
            node_id: node_b.identity.node_id.clone(),
            endpoint: format!("http://{addr_b}"),
            label: None,
            added_at: Utc::now(),
        };

        // Manually send signal (broadcast_local_block uses self.peers which is empty in test)
        let signal = ThreatSignal::new(
            &node_a.identity,
            "9.8.7.6".to_string(),
            "c2_callback".to_string(),
            0.92,
            b"evidence",
            3600,
        );
        assert!(node_a.client.send_signal(&peer_b, &signal).await);

        // Node B ticks — should have a block
        let result = node_b.tick();
        assert!(result.block_ips.iter().any(|(ip, _)| ip == "9.8.7.6"));
        assert!(node_b.is_mesh_blocked("9.8.7.6"));

        // Node B confirms locally — trust should increase
        node_b.confirm_local_incident("9.8.7.6");
        let reps = node_b.server_state.reputations.lock().unwrap();
        let rep = reps.get(&node_a.identity.node_id).unwrap();
        assert!(rep.trust_score > 0.9); // was 0.9, confirm adds 0.05
        assert_eq!(rep.signals_confirmed, 1);
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
