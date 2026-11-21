# innerwarden-mesh — Collaborative Defense Network

Game-theory trust model for sharing threat signals between nodes. Attack one node, protect all others. BUSL-1.1 licensed (Business Source License 1.1).

## Library crate

Used as a dependency by the agent (`crates/agent/Cargo.toml`). Also has a standalone example (`examples/mesh_node.rs`) for Docker testing.

## How it works

1. Node A detects attack from IP X (via sensor/detector)
2. Agent broadcasts `ThreatSignal` (Ed25519 signed) to all peers
3. Peers validate signature, check trust score, stage the signal
4. If trust × confidence >= threshold → block IP with TTL
5. If local sensor confirms the IP is bad → trust increases (+0.05)
6. If signal expires unconfirmed → trust decreases (-0.15, 3:1 asymmetry)

## Source (10 modules)

| File | Purpose |
|------|---------|
| node.rs | MeshNode public API (start, discover, broadcast, tick) |
| transport.rs | Axum HTTP server (POST /mesh/signal, GET /mesh/ping) + reqwest client |
| staging.rs | StagingPool: score thresholds, TTL, auto-reversal |
| validation.rs | RFC1918 rejection, rate limiter, quarantine |
| peer.rs | PeerReputation: tit-for-tat trust evolution |
| crypto.rs | Ed25519 keypair (NodeIdentity), sign/verify |
| signal.rs | ThreatSignal struct + canonical serialization |
| config.rs | MeshConfig TOML deserialization |
| persistence.rs | mesh-state.json + mesh-signals-YYYY-MM-DD.jsonl |
| lib.rs | Re-exports |

## Trust scoring

| Score | Action | TTL |
|-------|--------|-----|
| < 0.3 | Discarded | — |
| 0.3-0.6 | Watchlisted (logged) | 2h |
| 0.6-0.8 | Blocked short | 1h |
| >= 0.8 | Blocked full | 24h |

New peers: initial_trust = 0.5 (config) or 0.7 (test mode).

## Testing

```bash
cargo test                    # 59 unit + integration tests
cd docker-test && docker compose up --build   # 3-node simulation
```

Docker test (`docker-test/docker-compose-4node.yml`): 3 Docker nodes + server agent on ports 8794-8796 + 8790.

## Agent integration

```toml
# agent.toml
[mesh]
enabled = true
bind = "0.0.0.0:8790"
poll_secs = 30
auto_broadcast = true

[[mesh.peers]]
endpoint = "https://peer1:8790"
public_key = ""            # empty: learned from the peer's ping over its checked certificate
tls_cert_sha256 = "AB:CD:..." # or tls_ca = "/path/ca.pem"; neither = peer refused
label = "prod-eu"
```

TLS (`src/tls.rs`): the client never accepts an unchecked certificate; the
listener serves TLS (`tls_cert`/`tls_key` in `[mesh]`, or the generated
`mesh-tls-cert.pem`/`mesh-tls-key.pem`); plain HTTP only on loopback. The
server takes signals only from configured node ids (`known_peers`).

Agent wrapper: `crates/agent/src/mesh.rs` (delegates to MeshNode).

## Known issues (2026-03-27)

- Peer re-discovery added (`rediscover_if_needed`) but not yet tested in multi-node production setup
- `docker-test/` still lists `http://` peers: those are refused now; it needs a CA (`MESH_TLS_CA`) or per-peer digests (`endpoint@sha256` in `MESH_PEERS`, see `examples/mesh_node.rs`)
