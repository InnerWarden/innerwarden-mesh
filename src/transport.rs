use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Duration;
use tracing::{info, warn};

use crate::config::MeshConfig;
use crate::crypto::NodeIdentity;
use crate::peer::{PeerInfo, PeerReputation};
use crate::signal::ThreatSignal;
use crate::staging::{StagedAction, StagingPool};
use crate::validation::{self, RateLimiter};

/// Shared state for the mesh HTTP server.
pub struct MeshServerState {
    pub identity: Arc<NodeIdentity>,
    pub staging: Arc<Mutex<StagingPool>>,
    pub reputations: Arc<Mutex<HashMap<String, PeerReputation>>>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub config: MeshConfig,
}

/// Response for POST /mesh/signal
#[derive(serde::Serialize)]
struct SignalResponse {
    accepted: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Response for GET /mesh/ping
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PingResponse {
    node_id: String,
    version: String,
    uptime_secs: u64,
    staged_count: usize,
}

/// Start the mesh peer-to-peer listener.
/// Returns the actual bound address (useful when binding to port 0 in tests).
pub async fn start_server(
    state: Arc<MeshServerState>,
    bind: &str,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let app = Router::new()
        .route("/mesh/signal", post(handle_signal))
        .route("/mesh/ping", get(handle_ping))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    info!(addr = %addr, "mesh listener started");

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!(error = %e, "mesh listener error");
        }
    });

    Ok((addr, handle))
}

/// POST /mesh/signal — receive a threat signal from a peer.
async fn handle_signal(
    State(state): State<Arc<MeshServerState>>,
    Json(signal): Json<ThreatSignal>,
) -> (StatusCode, Json<SignalResponse>) {
    // Validate signal
    if let Err(e) = validation::validate_signal(&signal) {
        return (
            StatusCode::BAD_REQUEST,
            Json(SignalResponse {
                accepted: false,
                action: "rejected".to_string(),
                error: Some(format!("{e:?}")),
            }),
        );
    }

    // Rate limit check
    {
        let mut rl = state.rate_limiter.lock().unwrap();
        if !rl.check(&signal.node_id) {
            // Quarantine peer
            let mut reps = state.reputations.lock().unwrap();
            let rep = reps
                .entry(signal.node_id.clone())
                .or_insert_with(|| PeerReputation::new(signal.node_id.clone()));
            rep.quarantine(Duration::hours(1));
            warn!(
                peer = %signal.node_id,
                "mesh: rate limit exceeded — peer quarantined for 1 hour"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(SignalResponse {
                    accepted: false,
                    action: "quarantined".to_string(),
                    error: Some("rate limit exceeded".to_string()),
                }),
            );
        }
    }

    // Get or create reputation for this peer
    let reputation = {
        let mut reps = state.reputations.lock().unwrap();
        let rep = reps
            .entry(signal.node_id.clone())
            .or_insert_with(|| PeerReputation::new(signal.node_id.clone()));
        rep.record_signal();
        rep.clone()
    };

    if reputation.is_quarantined() {
        return (
            StatusCode::FORBIDDEN,
            Json(SignalResponse {
                accepted: false,
                action: "quarantined".to_string(),
                error: Some("peer is quarantined".to_string()),
            }),
        );
    }

    // Ingest into staging pool
    let action = {
        let mut staging = state.staging.lock().unwrap();
        staging.ingest(signal.clone(), &reputation)
    };

    let action_str = match &action {
        StagedAction::Discarded => "discarded",
        StagedAction::Watchlisted => "watchlisted",
        StagedAction::BlockedShortTtl => "blocked_short_ttl",
        StagedAction::BlockedFull => "blocked_full",
    };

    info!(
        peer = %signal.node_id,
        ip = %signal.ip,
        detector = %signal.detector,
        confidence = signal.confidence,
        weighted_score = reputation.effective_weight(signal.confidence),
        action = action_str,
        "mesh: signal received"
    );

    (
        StatusCode::OK,
        Json(SignalResponse {
            accepted: action != StagedAction::Discarded,
            action: action_str.to_string(),
            error: None,
        }),
    )
}

/// GET /mesh/ping — health check and identity exchange.
async fn handle_ping(State(state): State<Arc<MeshServerState>>) -> Json<PingResponse> {
    let staged_count = state.staging.lock().unwrap().len();
    Json(PingResponse {
        node_id: state.identity.node_id.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: 0, // TODO: track actual uptime
        staged_count,
    })
}

/// Client for sending signals to peers.
pub struct MeshClient {
    http: reqwest::Client,
}

impl MeshClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true) // peers may use self-signed certs
            .build()
            .unwrap_or_default();
        Self { http }
    }

    /// Send a threat signal to a peer. Returns true if accepted.
    pub async fn send_signal(&self, peer: &PeerInfo, signal: &ThreatSignal) -> bool {
        let url = format!("{}/mesh/signal", peer.endpoint);
        match self.http.post(&url).json(signal).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!(peer = %peer.node_id, ip = %signal.ip, "mesh: signal sent");
                    true
                } else {
                    warn!(
                        peer = %peer.node_id,
                        status = %resp.status(),
                        "mesh: signal rejected by peer"
                    );
                    false
                }
            }
            Err(e) => {
                warn!(peer = %peer.node_id, error = %e, "mesh: failed to send signal");
                false
            }
        }
    }

    /// Ping a peer to check if it's alive.
    pub async fn ping(&self, peer: &PeerInfo) -> Option<PingResponse> {
        let url = format!("{}/mesh/ping", peer.endpoint);
        match self.http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server_state() -> Arc<MeshServerState> {
        Arc::new(MeshServerState {
            identity: Arc::new(NodeIdentity::generate()),
            staging: Arc::new(Mutex::new(StagingPool::new(1000))),
            reputations: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(50))),
            config: MeshConfig::default(),
        })
    }

    #[tokio::test]
    async fn ping_returns_node_id() {
        let state = test_server_state();
        let node_id = state.identity.node_id.clone();
        let (addr, _handle) = start_server(state, "127.0.0.1:0").await.unwrap();

        let client = MeshClient::new();
        let peer = PeerInfo {
            node_id: "test".to_string(),
            endpoint: format!("http://{addr}"),
            label: None,
            added_at: chrono::Utc::now(),
        };
        let resp = client.ping(&peer).await.unwrap();
        assert_eq!(resp.node_id, node_id);
    }

    #[tokio::test]
    async fn signal_accepted_from_new_peer() {
        let state = test_server_state();
        let (addr, _handle) = start_server(state, "127.0.0.1:0").await.unwrap();

        let sender = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &sender,
            "1.2.3.4".to_string(),
            "ssh_bruteforce".to_string(),
            0.9,
            b"evidence",
            3600,
        );

        let client = MeshClient::new();
        let peer = PeerInfo {
            node_id: "server".to_string(),
            endpoint: format!("http://{addr}"),
            label: None,
            added_at: chrono::Utc::now(),
        };

        // New peer trust = 0.1, confidence 0.9 → weight 0.09 < 0.3 → discarded
        // But signal is still "accepted" (valid, just low weight)
        let sent = client.send_signal(&peer, &signal).await;
        assert!(sent);
    }

    #[tokio::test]
    async fn signal_rejected_for_private_ip() {
        let state = test_server_state();
        let (addr, _handle) = start_server(state, "127.0.0.1:0").await.unwrap();

        let sender = NodeIdentity::generate();
        let signal = ThreatSignal::new(
            &sender,
            "192.168.1.1".to_string(), // private IP
            "test".to_string(),
            0.9,
            b"e",
            3600,
        );

        let url = format!("http://{addr}/mesh/signal");
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&signal)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn two_nodes_exchange_signals() {
        // Node A
        let state_a = test_server_state();
        let id_a = state_a.identity.clone();
        let (addr_a, _h1) = start_server(state_a.clone(), "127.0.0.1:0").await.unwrap();

        // Node B
        let state_b = test_server_state();
        let (addr_b, _h2) = start_server(state_b.clone(), "127.0.0.1:0").await.unwrap();

        // Give Node B high trust for Node A's identity
        {
            let mut reps = state_b.reputations.lock().unwrap();
            let mut rep = PeerReputation::new(id_a.node_id.clone());
            rep.trust_score = 0.9;
            reps.insert(id_a.node_id.clone(), rep);
        }

        // Node A creates and sends signal to Node B
        let signal = ThreatSignal::new(
            &id_a,
            "5.6.7.8".to_string(),
            "c2_callback".to_string(),
            0.95,
            b"evidence hash",
            3600,
        );

        let client = MeshClient::new();
        let peer_b = PeerInfo {
            node_id: state_b.identity.node_id.clone(),
            endpoint: format!("http://{addr_b}"),
            label: None,
            added_at: chrono::Utc::now(),
        };

        let sent = client.send_signal(&peer_b, &signal).await;
        assert!(sent);

        // Verify Node B staged the signal (trust 0.9 * confidence 0.95 = 0.855 → blocked full)
        let staging = state_b.staging.lock().unwrap();
        assert!(staging.is_blocked("5.6.7.8"));
    }
}
