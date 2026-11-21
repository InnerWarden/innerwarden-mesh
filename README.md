# Inner Warden Mesh

[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

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

- **Checked TLS to every peer**: each configured peer names the SHA-256 of
  its certificate (`tls_cert_sha256`) or a CA file (`tls_ca`); a peer with
  neither, or a plain `http://` endpoint, is refused and never contacted. The
  listener serves TLS with `tls_cert`/`tls_key`, or with a self-signed pair the
  node makes once in its data directory (its digest is logged at start).
- **Configured node ids only**: a signal or advisory signed by a node id that
  is not a configured peer's `public_key` (or the id that peer answered its
  ping with, over its checked certificate) is refused before anything is
  recorded about it
- **Ed25519 signatures** on every signal — tamper-proof, peer-authenticated
- **RFC1918 rejection** — private IPs never accepted as threats
- **Rate limiter + circuit breaker** — flood protection per peer
- **Staging pool** — no blind execution, all blocks have TTL
- **Auto-reversal** — unconfirmed blocks expire automatically

## Quick start

```bash
# On each server running Inner Warden:
innerwarden mesh enable
innerwarden-ctl mesh add-peer https://other-server:8790 --cert-sha256 <the other server's digest>
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
cargo test              # 59 unit + integration tests

# Docker 3-node simulation:
cd docker-test
docker compose up --build
```

## License

BUSL-1.1 (Business Source License 1.1). See [LICENSE](LICENSE).
