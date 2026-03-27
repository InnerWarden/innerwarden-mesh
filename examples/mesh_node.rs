//! Standalone mesh node for Docker testing.
//!
//! Env vars:
//!   MESH_BIND=0.0.0.0:8790
//!   MESH_DATA_DIR=/data
//!   MESH_NODE_NAME=node-a
//!   MESH_PEERS=http://peer1:8790,http://peer2:8790
//!   MESH_SIMULATE=1  (only node-a simulates attacks)

use innerwarden_mesh::config::{MeshConfig, PeerEntry};
use innerwarden_mesh::node::MeshNode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let bind = std::env::var("MESH_BIND").unwrap_or_else(|_| "0.0.0.0:8790".to_string());
    let data_dir = std::env::var("MESH_DATA_DIR").unwrap_or_else(|_| "/tmp/mesh-data".to_string());
    let peers_str = std::env::var("MESH_PEERS").unwrap_or_default();
    let node_name = std::env::var("MESH_NODE_NAME").unwrap_or_else(|_| "node".to_string());
    let simulate = std::env::var("MESH_SIMULATE").unwrap_or_default() == "1";

    std::fs::create_dir_all(&data_dir)?;

    // Build config with peers
    let peers: Vec<PeerEntry> = if peers_str.is_empty() {
        vec![]
    } else {
        peers_str
            .split(',')
            .map(|ep| PeerEntry {
                endpoint: ep.trim().to_string(),
                public_key: String::new(), // will discover via ping
                label: None,
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
