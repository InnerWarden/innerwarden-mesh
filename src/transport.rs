use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Duration;
use tracing::{info, warn};

use chrono::{DateTime, Utc};

use crate::config::{MeshConfig, PeerEntry};
use crate::crypto::NodeIdentity;
use crate::peer::{PeerInfo, PeerReputation};
use crate::signal::{SuppressionSignal, ThreatSignal};
use crate::staging::{StagedAction, StagingPool};
use crate::validation::{self, RateLimiter};

/// Minimum sender trust before a suppression advisory is even recorded (spec
/// 062 Phase 6b). Suppression fails dangerous, so the bar is the mesh's
/// "blocked full" trust tier — a peer below this is ignored outright. The
/// receiving agent then applies a SECOND gate (the shape must already be
/// locally dismissed) before anything is suppressed.
pub const MIN_ADVISORY_TRUST: f32 = 0.8;

/// A suppression advisory accepted from a high-trust peer, awaiting the
/// agent's advisory-only application. The mesh layer never acts on these
/// itself — it only verifies, trust-scores, and hands them to the agent.
#[derive(Debug, Clone)]
pub struct ReceivedSuppression {
    pub node_id: String,
    pub detector: String,
    pub ip: String,
    pub dismissals: u64,
    pub peer_trust: f32,
    pub received_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ReceivedSuppression {
    /// The shape key: `detector|ip`.
    pub fn shape(&self) -> String {
        format!("{}|{}", self.detector, self.ip)
    }
}

/// Shared state for the mesh HTTP server.
pub struct MeshServerState {
    pub identity: Arc<NodeIdentity>,
    pub staging: Arc<Mutex<StagingPool>>,
    pub reputations: Arc<Mutex<HashMap<String, PeerReputation>>>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Inbox of accepted suppression advisories, drained by the agent each tick.
    pub suppressions: Arc<Mutex<Vec<ReceivedSuppression>>>,
    /// The node ids this node takes signals from: each configured peer's
    /// `public_key`, and the id a peer configured without one answered its
    /// ping with over a checked certificate. A signal or advisory signed by
    /// any other id is refused before anything is recorded about it, so a
    /// stranger never gets a reputation, a rate-limit slot or a staged block.
    pub known_peers: Arc<Mutex<HashSet<String>>>,
    pub config: MeshConfig,
}

impl MeshServerState {
    fn knows(&self, node_id: &str) -> bool {
        self.known_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(node_id)
    }
}

/// The answer to a signal or advisory from a node id no peer was configured
/// with.
fn refuse_unknown_peer(node_id: &str) -> (StatusCode, Json<SignalResponse>) {
    warn!(
        peer = %NodeIdentity::short_id(node_id),
        "mesh: refused a message from a node id no configured peer has"
    );
    (
        StatusCode::FORBIDDEN,
        Json(SignalResponse {
            accepted: false,
            action: "unknown_peer".to_string(),
            error: Some("node id not configured as a peer".to_string()),
        }),
    )
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
    pub node_id: String,
    pub version: String,
    pub uptime_secs: u64,
    pub staged_count: usize,
}

/// Start the mesh peer-to-peer listener over TLS (`tls`), the way
/// `MeshNode::start_listener` always does. Without `tls` it serves plain HTTP,
/// and only on a loopback address (behind a TLS terminator on the same host):
/// a plain listener on any other address is refused.
/// Returns the actual bound address (useful when binding to port 0 in tests).
pub async fn start_server(
    state: Arc<MeshServerState>,
    bind: &str,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let app = Router::new()
        .route("/mesh/signal", post(handle_signal))
        .route("/mesh/suppression", post(handle_suppression))
        .route("/mesh/ping", get(handle_ping))
        .with_state(state);
    serve(app, bind, tls).await
}

/// How long a connection the TLS listener took may stay open for, and how many
/// it serves at once. Whoever reaches the port can open a connection, finish
/// the handshake and then send nothing, or headers a byte at a time, or a body
/// that never ends: each of these holds a task and a socket. So a peer has
/// [`ConnLimits::handshake`] to finish TLS, [`ConnLimits::header_read`] to send
/// each request's headers (also the longest an idle keep-alive connection
/// waits for the next one), and the whole connection ends after
/// [`ConnLimits::lifetime`] (the request in flight gets [`ConnLimits::grace`]
/// to finish). At most [`ConnLimits::max_connections`] are served at once; the
/// next one waits in the kernel's accept queue until one of those ends. A mesh
/// request is a small JSON body, answered in milliseconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnLimits {
    pub max_connections: usize,
    pub handshake: std::time::Duration,
    pub header_read: std::time::Duration,
    pub lifetime: std::time::Duration,
    pub grace: std::time::Duration,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            handshake: std::time::Duration::from_secs(10),
            header_read: std::time::Duration::from_secs(10),
            lifetime: std::time::Duration::from_secs(60),
            grace: std::time::Duration::from_secs(5),
        }
    }
}

/// Serve `app` on `bind`: over TLS, or plain HTTP on a loopback address only.
async fn serve(
    app: Router,
    bind: &str,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    serve_with(app, bind, tls, ConnLimits::default()).await
}

async fn serve_with(
    app: Router,
    bind: &str,
    tls: Option<Arc<rustls::ServerConfig>>,
    limits: ConnLimits,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let Some(tls) = tls else {
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "mesh: refusing plain HTTP on {addr}; serve TLS (tls_cert/tls_key or the \
                 generated pair) or bind a loopback address behind a TLS terminator"
            );
        }
        info!(addr = %addr, "mesh listener started (plain HTTP, loopback only)");
        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error = %e, "mesh listener error");
            }
        });
        return Ok((addr, handle));
    };
    info!(
        addr = %addr,
        max_connections = limits.max_connections,
        "mesh listener started (TLS)"
    );

    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let handle = tokio::spawn(async move {
        loop {
            // A free slot first: at the cap nothing more is accepted.
            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            let (tcp, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "mesh listener accept error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let handshake = tokio::time::timeout(limits.handshake, acceptor.accept(tcp));
                let Ok(Ok(stream)) = handshake.await else {
                    return;
                };
                let service = hyper_util::service::TowerToHyperService::new(app);
                let conn = hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(limits.header_read)
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                tokio::pin!(conn);
                tokio::select! {
                    _ = conn.as_mut() => {}
                    _ = tokio::time::sleep(limits.lifetime) => {
                        conn.as_mut().graceful_shutdown();
                        let _ = tokio::time::timeout(limits.grace, conn).await;
                    }
                }
            });
        }
    });

    Ok((addr, handle))
}

/// POST /mesh/signal — receive a threat signal from a peer.
async fn handle_signal(
    State(state): State<Arc<MeshServerState>>,
    Json(signal): Json<ThreatSignal>,
) -> (StatusCode, Json<SignalResponse>) {
    if !state.knows(&signal.node_id) {
        return refuse_unknown_peer(&signal.node_id);
    }

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

/// POST /mesh/suppression — receive a suppression advisory from a peer.
///
/// Spec 062 Phase 6b. Verifies the signature, rate-limits, and trust-gates the
/// sender at [`MIN_ADVISORY_TRUST`]. An accepted advisory is parked in the
/// `suppressions` inbox for the agent to apply under its OWN second gate (the
/// shape must already be locally dismissed). This handler NEVER suppresses
/// anything — it cannot, it has no view of local dismissal history.
async fn handle_suppression(
    State(state): State<Arc<MeshServerState>>,
    Json(signal): Json<SuppressionSignal>,
) -> (StatusCode, Json<SignalResponse>) {
    if !state.knows(&signal.node_id) {
        return refuse_unknown_peer(&signal.node_id);
    }
    if let Err(e) = validation::validate_suppression(&signal) {
        return (
            StatusCode::BAD_REQUEST,
            Json(SignalResponse {
                accepted: false,
                action: "rejected".to_string(),
                error: Some(format!("{e:?}")),
            }),
        );
    }

    // Rate limit (shares the per-peer window with threat signals).
    {
        let mut rl = state.rate_limiter.lock().unwrap();
        if !rl.check(&signal.node_id) {
            let mut reps = state.reputations.lock().unwrap();
            let rep = reps
                .entry(signal.node_id.clone())
                .or_insert_with(|| PeerReputation::new(signal.node_id.clone()));
            rep.quarantine(Duration::hours(1));
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

    // Trust gate: suppression fails dangerous, so only high-trust peers are
    // even recorded. A low-trust peer's advisory is dropped, NOT staged.
    if reputation.trust_score < MIN_ADVISORY_TRUST {
        info!(
            peer = %signal.node_id,
            shape = %signal.shape(),
            trust = reputation.trust_score,
            "mesh: suppression advisory ignored — sender below advisory trust floor"
        );
        return (
            StatusCode::OK,
            Json(SignalResponse {
                accepted: false,
                action: "low_trust_ignored".to_string(),
                error: None,
            }),
        );
    }

    let now = Utc::now();
    let ttl = signal.ttl_secs.min(7 * 24 * 3600); // cap advisory life at 7 days
    {
        let mut inbox = state.suppressions.lock().unwrap();
        inbox.push(ReceivedSuppression {
            node_id: signal.node_id.clone(),
            detector: signal.detector.clone(),
            ip: signal.ip.clone(),
            dismissals: signal.dismissals,
            peer_trust: reputation.trust_score,
            received_at: now,
            expires_at: now + Duration::seconds(ttl as i64),
        });
    }

    info!(
        peer = %signal.node_id,
        shape = %signal.shape(),
        dismissals = signal.dismissals,
        trust = reputation.trust_score,
        "mesh: suppression advisory accepted (advisory-only; agent applies local gate)"
    );

    (
        StatusCode::OK,
        Json(SignalResponse {
            accepted: true,
            action: "advisory_recorded".to_string(),
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

/// Client for sending signals to peers: one HTTPS client per configured peer,
/// each checking that peer's certificate (`tls::peer_client`). A peer without
/// one is never contacted.
pub struct MeshClient {
    by_endpoint: HashMap<String, reqwest::Client>,
}

/// A configured peer the client refused, and why.
#[derive(Debug, Clone)]
pub struct RefusedPeer {
    pub endpoint: String,
    pub reason: String,
}

impl MeshClient {
    /// A client for `peers`, and the ones it refused (no `https://`, no
    /// certificate pin or CA, an unreadable CA). Never contacted.
    ///
    /// Only the first `[[peers]]` entry for an endpoint counts, here and in
    /// `MeshNode::new`, which takes its `public_key`: a later entry for the
    /// same endpoint is refused, so the certificate checked and the node id
    /// taken always come from the same entry. Even when the first is refused,
    /// a later one never stands in for it.
    pub fn for_peers(peers: &[PeerEntry]) -> (Self, Vec<RefusedPeer>) {
        let mut by_endpoint = HashMap::new();
        let mut refused = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for peer in peers {
            if !seen.insert(peer.endpoint.as_str()) {
                refused.push(RefusedPeer {
                    endpoint: peer.endpoint.clone(),
                    reason: "another [[peers]] entry names this endpoint first; only the first \
                             one is used"
                        .to_string(),
                });
                continue;
            }
            match crate::tls::peer_client(peer, std::time::Duration::from_secs(10)) {
                Ok(client) => {
                    by_endpoint.insert(peer.endpoint.clone(), client);
                }
                Err(e) => refused.push(RefusedPeer {
                    endpoint: peer.endpoint.clone(),
                    reason: format!("{e:#}"),
                }),
            }
        }
        (Self { by_endpoint }, refused)
    }

    /// Whether `endpoint` is a peer this client will contact.
    pub fn contacts(&self, endpoint: &str) -> bool {
        self.by_endpoint.contains_key(endpoint)
    }

    fn http(&self, peer: &PeerInfo) -> Option<&reqwest::Client> {
        let client = self.by_endpoint.get(&peer.endpoint);
        if client.is_none() {
            warn!(endpoint = %peer.endpoint, "mesh: not contacting a peer with no checked certificate");
        }
        client
    }

    /// Send a threat signal to a peer. Returns true if accepted.
    pub async fn send_signal(&self, peer: &PeerInfo, signal: &ThreatSignal) -> bool {
        let Some(http) = self.http(peer) else {
            return false;
        };
        let url = format!("{}/mesh/signal", peer.endpoint);
        match http.post(&url).json(signal).send().await {
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

    /// Send a suppression advisory to a peer. Returns true if accepted.
    pub async fn send_suppression(&self, peer: &PeerInfo, signal: &SuppressionSignal) -> bool {
        let Some(http) = self.http(peer) else {
            return false;
        };
        let url = format!("{}/mesh/suppression", peer.endpoint);
        match http.post(&url).json(signal).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                warn!(peer = %peer.node_id, error = %e, "mesh: failed to send suppression");
                false
            }
        }
    }

    /// Ping a peer to check if it's alive.
    pub async fn ping(&self, peer: &PeerInfo) -> Option<PingResponse> {
        let http = self.http(peer)?;
        let url = format!("{}/mesh/ping", peer.endpoint);
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::testing;

    fn test_server_state(known: &[&str]) -> Arc<MeshServerState> {
        Arc::new(MeshServerState {
            identity: Arc::new(NodeIdentity::generate()),
            staging: Arc::new(Mutex::new(StagingPool::new(1000))),
            reputations: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(50))),
            suppressions: Arc::new(Mutex::new(Vec::new())),
            known_peers: Arc::new(Mutex::new(known.iter().map(|id| id.to_string()).collect())),
            config: MeshConfig::default(),
        })
    }

    /// A TLS listener with a fresh self-signed certificate for 127.0.0.1,
    /// and that certificate's SHA-256.
    async fn tls_server(state: Arc<MeshServerState>) -> (SocketAddr, [u8; 32]) {
        let (config, sha) = testing::leaf(&["127.0.0.1"], None);
        let (addr, _h) = start_server(state, "127.0.0.1:0", Some(config))
            .await
            .unwrap();
        (addr, sha)
    }

    fn peer_entry(addr: SocketAddr, pin: Option<[u8; 32]>, ca: Option<&str>) -> PeerEntry {
        PeerEntry {
            endpoint: format!("https://{addr}"),
            public_key: String::new(),
            label: None,
            tls_cert_sha256: pin.map(|p| crate::tls::format_sha256(&p)),
            tls_ca: ca.map(str::to_string),
        }
    }

    /// A client that contacts exactly the peer at `addr`, as configured.
    fn client_for(entry: PeerEntry) -> (MeshClient, PeerInfo) {
        let (client, refused) = MeshClient::for_peers(std::slice::from_ref(&entry));
        assert!(refused.is_empty(), "{refused:?}");
        let peer = PeerInfo {
            node_id: entry.public_key.clone(),
            endpoint: entry.endpoint,
            label: None,
            added_at: chrono::Utc::now(),
        };
        (client, peer)
    }

    fn signal_from(sender: &NodeIdentity, ip: &str) -> ThreatSignal {
        ThreatSignal::new(
            sender,
            ip.to_string(),
            "ssh_bruteforce".to_string(),
            0.9,
            b"evidence",
            3600,
        )
    }

    #[tokio::test]
    async fn ping_returns_node_id_over_the_pinned_certificate() {
        let state = test_server_state(&[]);
        let node_id = state.identity.node_id.clone();
        let (addr, sha) = tls_server(state).await;

        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        let resp = client.ping(&peer).await.unwrap();
        assert_eq!(resp.node_id, node_id);
    }

    /// FAILS ON REVERT (any certificate accepted): the peer behind another
    /// certificate is pinged and sent the signal.
    #[tokio::test]
    async fn a_peer_answering_with_another_certificate_is_never_read_nor_sent_to() {
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        let (addr, _real) = tls_server(state.clone()).await;
        let (_other_config, other_sha) = testing::leaf(&["127.0.0.1"], None);

        let (client, peer) = client_for(peer_entry(addr, Some(other_sha), None));
        assert!(
            client.ping(&peer).await.is_none(),
            "read a swapped certificate"
        );
        assert!(
            !client
                .send_signal(&peer, &signal_from(&sender, "1.2.3.4"))
                .await
        );
        assert!(state.staging.lock().unwrap().is_empty());
        assert!(state.reputations.lock().unwrap().is_empty());
    }

    /// A peer checked against a CA: its certificate must chain to that CA for
    /// the endpoint's name; one from another CA is refused.
    #[tokio::test]
    async fn a_peer_checked_against_its_ca_and_one_from_another_ca() {
        let ca = testing::ca();
        let other_ca = testing::ca();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca.pem).unwrap();
        let other_path = dir.path().join("other.pem");
        std::fs::write(&other_path, &other_ca.pem).unwrap();

        let state = test_server_state(&[]);
        let node_id = state.identity.node_id.clone();
        let (config, _) = testing::leaf(&["127.0.0.1"], Some(&ca));
        let (addr, _h) = start_server(state, "127.0.0.1:0", Some(config))
            .await
            .unwrap();

        let (client, peer) = client_for(peer_entry(addr, None, ca_path.to_str()));
        assert_eq!(client.ping(&peer).await.unwrap().node_id, node_id);
        let (client, peer) = client_for(peer_entry(addr, None, other_path.to_str()));
        assert!(
            client.ping(&peer).await.is_none(),
            "another CA's peer was read"
        );
    }

    /// A certificate signed by the configured CA but for another name is
    /// refused, with or without a pin beside the CA. A pin alone does not
    /// read the name: the pin is the identity.
    #[tokio::test]
    async fn a_certificate_from_the_right_ca_for_another_name_is_refused() {
        let ca = testing::ca();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca.pem).unwrap();
        let state = test_server_state(&[]);
        let node_id = state.identity.node_id.clone();
        let (config, sha) = testing::leaf(&["other.name"], Some(&ca));
        let (addr, _h) = start_server(state, "127.0.0.1:0", Some(config))
            .await
            .unwrap();

        let (client, peer) = client_for(peer_entry(addr, None, ca_path.to_str()));
        assert!(
            client.ping(&peer).await.is_none(),
            "read a certificate made out to another name"
        );
        let (client, peer) = client_for(peer_entry(addr, Some(sha), ca_path.to_str()));
        assert!(
            client.ping(&peer).await.is_none(),
            "the pin let a certificate for another name past the CA"
        );
        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        assert_eq!(client.ping(&peer).await.unwrap().node_id, node_id);
    }

    /// FAILS ON REVERT (the CA check skipped when a pin matches): with both a
    /// pin and a CA, each must hold.
    #[tokio::test]
    async fn with_a_pin_and_a_ca_both_must_hold() {
        let ca = testing::ca();
        let other_ca = testing::ca();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca.pem).unwrap();
        let other_path = dir.path().join("other.pem");
        std::fs::write(&other_path, &other_ca.pem).unwrap();
        let state = test_server_state(&[]);
        let node_id = state.identity.node_id.clone();
        let (config, sha) = testing::leaf(&["127.0.0.1"], Some(&ca));
        let (_unused, other_sha) = testing::leaf(&["127.0.0.1"], Some(&ca));
        let (addr, _h) = start_server(state, "127.0.0.1:0", Some(config))
            .await
            .unwrap();

        let (client, peer) = client_for(peer_entry(addr, Some(sha), ca_path.to_str()));
        assert_eq!(client.ping(&peer).await.unwrap().node_id, node_id);
        let (client, peer) = client_for(peer_entry(addr, Some(other_sha), ca_path.to_str()));
        assert!(
            client.ping(&peer).await.is_none(),
            "the CA let a certificate past a pin it does not match"
        );
        let (client, peer) = client_for(peer_entry(addr, Some(sha), other_path.to_str()));
        assert!(
            client.ping(&peer).await.is_none(),
            "the pin let a certificate past a CA it does not chain to"
        );
    }

    /// FAILS ON REVERT (each entry overwriting the one before in the client,
    /// while the node takes the first entry's key): two `[[peers]]` entries
    /// for one endpoint, the client checked the last one's pin.
    #[tokio::test]
    async fn only_the_first_entry_for_an_endpoint_counts() {
        let state = test_server_state(&[]);
        let (addr, real) = tls_server(state).await;
        let (_other_config, other) = testing::leaf(&["127.0.0.1"], None);
        let peer = PeerInfo {
            node_id: String::new(),
            endpoint: format!("https://{addr}"),
            label: None,
            added_at: chrono::Utc::now(),
        };

        let entries = [
            peer_entry(addr, Some(real), None),
            peer_entry(addr, Some(other), None),
        ];
        let (client, refused) = MeshClient::for_peers(&entries);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].reason.contains("first"), "{refused:?}");
        assert!(client.ping(&peer).await.is_some(), "checked the second pin");

        let entries = [
            peer_entry(addr, Some(other), None),
            peer_entry(addr, Some(real), None),
        ];
        let (client, refused) = MeshClient::for_peers(&entries);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(client.ping(&peer).await.is_none(), "checked the second pin");

        // The first refused (no pin, no CA): a later entry never stands in.
        let entries = [
            peer_entry(addr, None, None),
            peer_entry(addr, Some(real), None),
        ];
        let (client, refused) = MeshClient::for_peers(&entries);
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(!client.contacts(&peer.endpoint));
    }

    /// A TLS connection to `addr` that accepts the certificate `sha`.
    async fn raw_tls(
        addr: SocketAddr,
        sha: [u8; 32],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        tokio_rustls::TlsConnector::from(testing::pinned_client(sha))
            .connect(name, tcp)
            .await
    }

    /// Whether the listener closes `stream` within `within`.
    async fn closed_within<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
        within: std::time::Duration,
    ) -> bool {
        use tokio::io::AsyncReadExt;
        let mut sink = Vec::new();
        tokio::time::timeout(within, stream.read_to_end(&mut sink))
            .await
            .is_ok()
    }

    fn short_limits() -> ConnLimits {
        ConnLimits {
            max_connections: 8,
            handshake: std::time::Duration::from_secs(10),
            header_read: std::time::Duration::from_secs(30),
            lifetime: std::time::Duration::from_secs(60),
            grace: std::time::Duration::from_secs(5),
        }
    }

    async fn limited_server(limits: ConnLimits) -> (SocketAddr, [u8; 32], String) {
        let state = test_server_state(&[]);
        let node_id = state.identity.node_id.clone();
        let app = Router::new()
            .route("/mesh/signal", post(handle_signal))
            .route("/mesh/ping", get(handle_ping))
            .with_state(state);
        let (config, sha) = testing::leaf(&["127.0.0.1"], None);
        let (addr, _h) = serve_with(app, "127.0.0.1:0", Some(config), limits)
            .await
            .unwrap();
        (addr, sha, node_id)
    }

    /// FAILS ON REVERT (no timer on the HTTP/1 builder, so no header read
    /// timeout): a connection that finishes TLS and sends nothing is held
    /// open for as long as its sender likes.
    #[tokio::test]
    async fn a_connection_that_sends_no_request_is_closed() {
        let limits = ConnLimits {
            header_read: std::time::Duration::from_millis(300),
            ..short_limits()
        };
        let (addr, sha, _) = limited_server(limits).await;
        let mut silent = raw_tls(addr, sha).await.unwrap();
        assert!(
            closed_within(&mut silent, std::time::Duration::from_secs(5)).await,
            "a silent connection was held open"
        );
    }

    /// FAILS ON REVERT (no lifetime on a connection): headers on time and
    /// then a body that never ends hold the connection, and its slot, forever.
    #[tokio::test]
    async fn a_body_that_never_ends_holds_the_connection_no_longer_than_its_lifetime() {
        use tokio::io::AsyncWriteExt;
        let limits = ConnLimits {
            header_read: std::time::Duration::from_millis(300),
            lifetime: std::time::Duration::from_millis(600),
            grace: std::time::Duration::from_millis(200),
            ..short_limits()
        };
        let (addr, sha, _) = limited_server(limits).await;
        let mut slow = raw_tls(addr, sha).await.unwrap();
        slow.write_all(
            b"POST /mesh/signal HTTP/1.1\r\nHost: peer\r\nContent-Type: application/json\r\n\
              Content-Length: 1000\r\n\r\n{",
        )
        .await
        .unwrap();
        slow.flush().await.unwrap();
        assert!(
            closed_within(&mut slow, std::time::Duration::from_secs(5)).await,
            "a body that never ends held the connection"
        );
    }

    /// FAILS ON REVERT (no cap on connections): at the cap, the next
    /// connection is not even accepted until one being served ends; then it is
    /// served.
    #[tokio::test]
    async fn at_the_cap_the_next_connection_waits_for_a_free_slot() {
        use tokio::io::AsyncWriteExt;
        let limits = ConnLimits {
            max_connections: 1,
            ..short_limits()
        };
        let (addr, sha, node_id) = limited_server(limits).await;
        let holder = raw_tls(addr, sha).await.unwrap();

        let mut next = Box::pin(raw_tls(addr, sha));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut next)
                .await
                .is_err(),
            "a connection past the cap was served"
        );
        drop(holder);
        let mut next = tokio::time::timeout(std::time::Duration::from_secs(5), next)
            .await
            .expect("the freed slot went to the waiting connection")
            .unwrap();
        next.write_all(b"GET /mesh/ping HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut next, &mut answer)
            .await
            .unwrap();
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains(&node_id), "{answer}");
    }

    /// A peer the client refused (no pin, no CA, plain HTTP) is never
    /// contacted, even when something answers there.
    #[tokio::test]
    async fn a_refused_peer_is_never_contacted() {
        let state = test_server_state(&[]);
        let (addr, _h) = start_server(state, "127.0.0.1:0", None).await.unwrap();
        let entries = [
            PeerEntry {
                endpoint: format!("http://{addr}"),
                public_key: String::new(),
                label: None,
                tls_cert_sha256: Some("ab".repeat(32)),
                tls_ca: None,
            },
            peer_entry(addr, None, None),
        ];
        let (client, refused) = MeshClient::for_peers(&entries);
        assert_eq!(refused.len(), 2, "{refused:?}");
        for entry in &entries {
            assert!(!client.contacts(&entry.endpoint));
            let peer = PeerInfo {
                node_id: String::new(),
                endpoint: entry.endpoint.clone(),
                label: None,
                added_at: chrono::Utc::now(),
            };
            assert!(client.ping(&peer).await.is_none());
        }
    }

    #[tokio::test]
    async fn plain_http_is_served_only_on_loopback() {
        let err = start_server(test_server_state(&[]), "0.0.0.0:0", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refusing plain HTTP"), "{err}");
    }

    #[tokio::test]
    async fn signal_accepted_from_a_configured_peer() {
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        let (addr, sha) = tls_server(state).await;

        // New peer trust = 0.1, confidence 0.9 → weight 0.09 < 0.3 → discarded
        // But signal is still "accepted" (valid, just low weight)
        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        assert!(
            client
                .send_signal(&peer, &signal_from(&sender, "1.2.3.4"))
                .await
        );
    }

    /// FAILS ON REVERT (a byte slice of the id for the log line): the
    /// handler panics and the peer gets no answer.
    #[tokio::test]
    async fn an_unknown_node_id_with_a_multibyte_character_is_refused_not_a_panic() {
        // The log line's fields are read only when a subscriber listens, as
        // on every agent. One for this thread (the test runtime's only one).
        let _log =
            tracing::subscriber::set_default(tracing_subscriber::fmt().with_test_writer().finish());
        let state = test_server_state(&[]);
        let (addr, _h) = start_server(state, "127.0.0.1:0", None).await.unwrap();
        // A character straddling byte 16: a byte slice there panics the handler.
        let mut signal = signal_from(&NodeIdentity::generate(), "5.6.7.8");
        signal.node_id = format!("{}\u{e9}{}", "a".repeat(15), "b".repeat(47));
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/mesh/signal"))
            .json(&signal)
            .send()
            .await
            .expect("the handler answered");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// FAILS ON REVERT (reqwest's default policy follows up to 10 redirects
    /// with no scheme check): a pinned peer that answers with a redirect to
    /// `http://` has the request sent there in clear.
    #[tokio::test]
    async fn a_peer_s_redirect_is_never_followed() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let plain_hits = hits.clone();
        let plain = Router::new().route(
            "/mesh/ping",
            get(move || {
                plain_hits.fetch_add(1, Ordering::SeqCst);
                async {
                    Json(serde_json::json!({
                        "node_id": "a".repeat(64),
                        "version": "x",
                        "uptime_secs": 0,
                        "staged_count": 0
                    }))
                }
            }),
        );
        let (plain_addr, _p) = serve(plain, "127.0.0.1:0", None).await.unwrap();
        let to = format!("http://{plain_addr}/mesh/ping");
        let redirecting = Router::new().route(
            "/mesh/ping",
            get(move || async move {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(axum::http::header::LOCATION, to)],
                )
            }),
        );
        let (config, sha) = testing::leaf(&["127.0.0.1"], None);
        let (addr, _h) = serve(redirecting, "127.0.0.1:0", Some(config))
            .await
            .unwrap();

        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        assert!(client.ping(&peer).await.is_none(), "followed the redirect");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the plain listener was contacted"
        );
    }

    /// FAILS ON REVERT (the node-id check in the handlers): a validly signed
    /// signal from a node id no peer was configured with gets a reputation
    /// and a staged entry.
    #[tokio::test]
    async fn a_signal_or_advisory_from_an_unknown_node_id_is_refused() {
        let configured = NodeIdentity::generate();
        let stranger = NodeIdentity::generate();
        let state = test_server_state(&[&configured.node_id]);
        // Even a stranger that somehow had high trust is refused.
        high_trust_peer(&state, &stranger.node_id);
        let (addr, _h) = start_server(state.clone(), "127.0.0.1:0", None)
            .await
            .unwrap();

        let http = reqwest::Client::new();
        let resp = http
            .post(format!("http://{addr}/mesh/signal"))
            .json(&ThreatSignal::new(
                &stranger,
                "5.6.7.8".to_string(),
                "c2_callback".to_string(),
                0.99,
                b"e",
                3600,
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["action"], "unknown_peer");

        let resp = http
            .post(format!("http://{addr}/mesh/suppression"))
            .json(&SuppressionSignal::new(
                &stranger,
                "web_scan".to_string(),
                "8.8.8.8".to_string(),
                12,
                3600,
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(state.staging.lock().unwrap().is_empty());
        assert!(state.suppressions.lock().unwrap().is_empty());
        {
            let reps = state.reputations.lock().unwrap();
            assert_eq!(reps.get(&stranger.node_id).unwrap().signals_sent, 0);
            assert_eq!(reps.len(), 1, "the stranger got a reputation entry");
        }

        // The configured peer is still heard.
        let resp = http
            .post(format!("http://{addr}/mesh/signal"))
            .json(&signal_from(&configured, "5.6.7.8"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn signal_rejected_for_private_ip() {
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        let (addr, _handle) = start_server(state, "127.0.0.1:0", None).await.unwrap();

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

    // --- Suppression advisories (spec 062 Phase 6b) ---

    fn high_trust_peer(state: &Arc<MeshServerState>, node_id: &str) {
        let mut reps = state.reputations.lock().unwrap();
        let mut rep = PeerReputation::new(node_id.to_string());
        rep.trust_score = 0.9;
        reps.insert(node_id.to_string(), rep);
    }

    #[tokio::test]
    async fn suppression_accepted_from_high_trust_peer() {
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        high_trust_peer(&state, &sender.node_id);
        let (addr, sha) = tls_server(state.clone()).await;

        let sig = SuppressionSignal::new(
            &sender,
            "web_scan".to_string(),
            "8.8.8.8".to_string(),
            12,
            3600,
        );
        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        assert!(client.send_suppression(&peer, &sig).await);
        let inbox = state.suppressions.lock().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].shape(), "web_scan|8.8.8.8");
    }

    #[tokio::test]
    async fn suppression_ignored_from_low_trust_peer() {
        // No reputation seeded → fresh peer is below MIN_ADVISORY_TRUST.
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        let (addr, _h) = start_server(state.clone(), "127.0.0.1:0", None)
            .await
            .unwrap();

        let sig = SuppressionSignal::new(
            &sender,
            "web_scan".to_string(),
            "8.8.8.8".to_string(),
            12,
            3600,
        );
        let url = format!("http://{addr}/mesh/suppression");
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&sig)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["action"], "low_trust_ignored");
        assert_eq!(body["accepted"], false);
        // Nothing recorded — a low-trust peer cannot teach this node to ignore.
        assert_eq!(state.suppressions.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn suppression_allows_link_local_metadata_ip() {
        // The canonical case: imds_ssrf | 169.254.169.254. validate_signal
        // would reject link-local; validate_suppression must NOT.
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        high_trust_peer(&state, &sender.node_id);
        let (addr, sha) = tls_server(state.clone()).await;

        let sig = SuppressionSignal::new(
            &sender,
            "imds_ssrf".to_string(),
            "169.254.169.254".to_string(),
            1105,
            86_400,
        );
        let (client, peer) = client_for(peer_entry(addr, Some(sha), None));
        assert!(client.send_suppression(&peer, &sig).await);
        assert_eq!(state.suppressions.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn suppression_rejects_tampered_signature() {
        let sender = NodeIdentity::generate();
        let state = test_server_state(&[&sender.node_id]);
        let (addr, _h) = start_server(state, "127.0.0.1:0", None).await.unwrap();

        let mut sig = SuppressionSignal::new(
            &sender,
            "web_scan".to_string(),
            "8.8.8.8".to_string(),
            12,
            3600,
        );
        sig.dismissals = 999_999; // tamper after signing
        let url = format!("http://{addr}/mesh/suppression");
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&sig)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn two_nodes_exchange_signals() {
        // Node A
        let state_a = test_server_state(&[]);
        let id_a = state_a.identity.clone();
        let (_addr_a, _sha_a) = tls_server(state_a.clone()).await;

        // Node B knows Node A
        let state_b = test_server_state(&[&id_a.node_id]);
        let (addr_b, sha_b) = tls_server(state_b.clone()).await;

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

        let (client, peer_b) = client_for(peer_entry(addr_b, Some(sha_b), None));
        assert!(client.send_signal(&peer_b, &signal).await);

        // Verify Node B staged the signal (trust 0.9 * confidence 0.95 = 0.855 → blocked full)
        let staging = state_b.staging.lock().unwrap();
        assert!(staging.is_blocked("5.6.7.8"));
    }
}
