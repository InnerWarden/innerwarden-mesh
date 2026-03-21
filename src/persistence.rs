use std::path::Path;

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

use crate::peer::{PeerInfo, PeerReputation};
use crate::staging::StagedSignal;

/// Mesh state that gets persisted to disk between restarts.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MeshState {
    pub peers: Vec<PeerInfo>,
    pub reputations: Vec<PeerReputation>,
    pub staged: Vec<StagedSignalEntry>,
}

/// Flattened staged signal for persistence (includes the IP key).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StagedSignalEntry {
    pub ip: String,
    pub signal: crate::signal::ThreatSignal,
    pub weighted_score: f32,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub action: crate::staging::StagedAction,
    pub contributing_peers: Vec<String>,
    pub locally_confirmed: bool,
}

const STATE_FILE: &str = "mesh-state.json";

/// Save mesh state to disk as pretty-printed JSON.
pub fn save_state(data_dir: &Path, state: &MeshState) -> Result<()> {
    let path = data_dir.join(STATE_FILE);
    let json = serde_json::to_string_pretty(state).context("serializing mesh state")?;
    std::fs::write(&path, json).context("writing mesh state")?;
    Ok(())
}

/// Load mesh state from disk. Returns default if file doesn't exist.
pub fn load_state(data_dir: &Path) -> Result<MeshState> {
    let path = data_dir.join(STATE_FILE);
    if !path.exists() {
        return Ok(MeshState::default());
    }
    let content = std::fs::read_to_string(&path).context("reading mesh state")?;
    let state: MeshState = serde_json::from_str(&content).context("parsing mesh state")?;
    Ok(state)
}

/// Append a signal to the mesh signal log (JSONL, one signal per line).
/// Used for audit trail — not loaded on restart, just for forensics.
pub fn append_signal_log(data_dir: &Path, entry: &impl Serialize) -> Result<()> {
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let path = data_dir.join(format!("mesh-signals-{today}.jsonl"));
    let mut line = serde_json::to_string(entry).context("serializing signal log entry")?;
    line.push('\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .context("opening mesh signal log")?
        .write_all(line.as_bytes())
        .context("writing mesh signal log")?;
    Ok(())
}

use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let state = MeshState {
            peers: vec![PeerInfo {
                node_id: "abc123".to_string(),
                endpoint: "https://10.0.1.5:8790".to_string(),
                label: Some("prod-eu".to_string()),
                added_at: chrono::Utc::now(),
            }],
            reputations: vec![PeerReputation::new("abc123".to_string())],
            staged: vec![],
        };

        save_state(dir.path(), &state).unwrap();
        let loaded = load_state(dir.path()).unwrap();

        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].node_id, "abc123");
        assert_eq!(loaded.reputations.len(), 1);
        assert_eq!(loaded.reputations[0].trust_score, 0.1);
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let state = load_state(dir.path()).unwrap();
        assert!(state.peers.is_empty());
        assert!(state.reputations.is_empty());
    }

    #[test]
    fn signal_log_appends() {
        let dir = tempfile::tempdir().unwrap();
        let entry = serde_json::json!({"ip": "1.2.3.4", "action": "watchlisted"});
        append_signal_log(dir.path(), &entry).unwrap();
        append_signal_log(dir.path(), &entry).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d");
        let path = dir.path().join(format!("mesh-signals-{today}.jsonl"));
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }
}
