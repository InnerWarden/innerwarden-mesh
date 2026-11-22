//! Standalone mesh node for Docker testing.
//!
//! Env vars:
//!   MESH_BIND=0.0.0.0:8790
//!   MESH_DATA_DIR=/data
//!   MESH_NODE_NAME=node-a
//!   MESH_PEERS=https://peer1:8790@<sha256>,https://peer2:8790
//!     each peer is contacted only when its certificate can be checked: the
//!     SHA-256 after `@` (openssl's fingerprint), or MESH_TLS_CA for all;
//!     a peer with neither is refused
//!   MESH_TLS_CA=/certs/ca.pem    (CA every peer's certificate chains to)
//!   MESH_TLS_CERT=/certs/node.pem MESH_TLS_KEY=/certs/node.key
//!     (this node's listener; unset: a self-signed pair in MESH_DATA_DIR)
//!   MESH_SIMULATE=1  (only node-a simulates attacks)

use innerwarden_mesh::config::{MeshConfig, PeerEntry};
use innerwarden_mesh::node::MeshNode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let bind = std::env::var("MESH_BIND").unwrap_or_else(|_| "0.0.0.0:8790".to_string());
    let data_dir = std::env::var("MESH_DATA_DIR").unwrap_or_else(|_| "/tmp/mesh-data".to_string());
    let peers_str = std::env::var("MESH_PEERS").unwrap_or_default();
    let node_name = std::env::var("MESH_NODE_NAME").unwrap_or_else(|_| "node".to_string());
    let simulate = std::env::var("MESH_SIMULATE").unwrap_or_default() == "1";
    let tls_ca = std::env::var("MESH_TLS_CA").ok().filter(|v| !v.is_empty());
    let tls_cert = std::env::var("MESH_TLS_CERT")
        .ok()
        .filter(|v| !v.is_empty());
    let tls_key = std::env::var("MESH_TLS_KEY").ok().filter(|v| !v.is_empty());

    std::fs::create_dir_all(&data_dir)?;

    // Build config with peers
    let peers: Vec<PeerEntry> = if peers_str.is_empty() {
        vec![]
    } else {
        peers_str
            .split(',')
            .map(|item| {
                let (endpoint, pin) = match item.trim().rsplit_once('@') {
                    Some((ep, sha)) => (ep.to_string(), Some(sha.to_string())),
                    None => (item.trim().to_string(), None),
                };
                PeerEntry {
                    endpoint,
                    public_key: String::new(), // will discover via ping
                    label: None,
                    tls_cert_sha256: pin,
                    tls_ca: tls_ca.clone(),
                }
            })
            .collect()
    };

    let config = MeshConfig {
        enabled: true,
        bind: bind.clone(),
        peers,
        poll_secs: 10,
        auto_broadcast: true,
        max_signals_per_hour: 50,
        max_staged: 10_000,
        initial_trust: 0.7, // test mode: trust config peers enough to stage signals
        tls_cert,
        tls_key,
    };

    let mut node = MeshNode::new(config, std::path::Path::new(&data_dir))?;
    tracing::info!(
        node = %node_name,
        node_id = &node.node_id()[..16],
        "mesh node created"
    );

    let (addr, _handle) = node.start_listener().await?;
    tracing::info!(node = %node_name, addr = %addr, "listener active");

    // Wait for peers to come up, then discover their identities
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    node.discover_peers().await;

    // Main loop
    let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut attack_interval = tokio::time::interval(std::time::Duration::from_secs(20));
    let mut counter = 0u32;

    loop {
        tokio::select! {
            _ = tick_interval.tick() => {
                node.rediscover_if_needed().await;
                let result = node.tick();
                tracing::info!(
                    node = %node_name,
                    staged = node.staged_count(),
                    active_blocks = node.active_block_count(),
                    new_blocks = result.block_ips.len(),
                    expired = result.unblock_ips.len(),
                    "tick"
                );
                for (ip, ttl) in &result.block_ips {
                    tracing::warn!(
                        node = %node_name,
                        ip,
                        ttl,
                        "NEW MESH BLOCK"
                    );
                }
            }
            _ = attack_interval.tick(), if simulate => {
                counter += 1;
                let ip = format!("185.220.{}.{}", counter % 255, (counter * 7) % 255);
                let detectors = ["ssh_bruteforce", "credential_stuffing", "port_scan", "c2_callback"];
                let detector = detectors[(counter as usize) % detectors.len()];

                tracing::warn!(
                    node = %node_name,
                    ip = %ip,
                    detector,
                    "ATTACK DETECTED — broadcasting"
                );

                node.broadcast_local_block(
                    &ip,
                    detector,
                    0.92,
                    format!("evidence-{counter}").as_bytes(),
                    3600,
                ).await;
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!(node = %node_name, "shutting down");
                node.persist()?;
                break;
            }
        }
    }

    Ok(())
}
