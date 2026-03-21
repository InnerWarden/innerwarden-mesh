# Inner Warden Mesh

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Attack one node, protect all others.**

Collaborative defense network for [Inner Warden](https://github.com/InnerWarden/innerwarden). Nodes share threat signals in real time using a game-theory-based trust model. No central authority. No blind trust.

## How it works

```
Node A detects SSH brute-force from 185.220.1.7
  → signs threat signal with Ed25519
  → broadcasts to all peers

Node B receives signal
  → verifies signature
  → checks sender's trust score (tit-for-tat)
  → scores: trust 0.85 × confidence 0.92 = 0.78
  → stages block with 1h TTL (auto-reverts if unconfirmed)

Node B later sees 185.220.1.7 attacking its own SSH
  → confirms signal → sender's trust increases
  → block upgraded to 24h
```

## Trust model

No signal causes immediate permanent action. Everything goes through a **staging pool**.

| Score | Action | TTL |
|-------|--------|-----|
| < 0.3 | Discarded | — |
| 0.3 - 0.6 | Watchlisted (logged, no block) | 2h |
| 0.6 - 0.8 | Blocked with short TTL | 1h |
| > 0.8 | Blocked full | 24h |

**Trust evolution (tit-for-tat):**
- New peers start at trust **0.1** (skeptical)
- Confirmed signal: **+0.05** trust
- Contradicted signal: **-0.15** trust (3:1 asymmetry)
- Rate limit: max 50 signals/hour per peer → quarantine on excess

A malicious peer cannot build trust cheaply. Three confirmed signals to offset one contradiction.

## Security

- **Ed25519 signatures** on every signal — tamper-proof, peer-authenticated
- **RFC1918 rejection** — private IPs never accepted as threats
- **Rate limiter + circuit breaker** — flood protection per peer
- **Staging pool** — no blind execution, all blocks have TTL
- **Auto-reversal** — unconfirmed blocks expire automatically

## Quick start

```bash
# On each server running Inner Warden:
innerwarden mesh enable
innerwarden mesh add-peer https://other-server:8790
sudo systemctl restart innerwarden-agent
```

## Architecture

```
innerwarden-mesh/
  src/
    crypto.rs      — Ed25519 keypair, sign, verify
    signal.rs      — ThreatSignal struct + canonical signing
    peer.rs        — PeerReputation with tit-for-tat trust
    validation.rs  — RFC1918 filter, rate limiter, circuit breaker
    staging.rs     — StagingPool with thresholds + TTL
    transport.rs   — axum HTTP server + reqwest client
    node.rs        — MeshNode public API
    config.rs      — TOML configuration
    persistence.rs — State save/load + signal audit log
```

## Testing

```bash
cargo test              # 49 unit + integration tests

# Docker 3-node simulation:
cd docker-test
docker compose up --build
```

## License

MIT. See [LICENSE](LICENSE).
