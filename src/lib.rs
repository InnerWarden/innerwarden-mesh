//! innerwarden-mesh — Collaborative defense network for Inner Warden.
//!
//! Nodes share threat signals using a game-theory-based trust model.
//! Attacking one node protects all others. No signal causes immediate
//! action — everything goes through a staging pool with reputation-weighted
//! scoring and TTL-based auto-reversal.

pub mod crypto;
pub mod peer;
pub mod signal;
pub mod staging;
pub mod validation;
