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
    // Atomic: write to a temp file then rename over the target, so a crash or
    // kill mid-write can never leave a half-written or zero-byte state file.
    // A truncated mesh-state.json used to take the whole mesh offline on the
    // next boot (load failed hard), so the durable fix is to never create one.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).context("writing mesh state tmp")?;
    std::fs::rename(&tmp, &path).context("renaming mesh state into place")?;
    Ok(())
}

/// Load mesh state from disk. Returns default if the file is missing, empty, or
/// corrupt.
///
/// Fail-soft by design: a bad persistence file must NEVER disable collaborative
/// defense. Previously an empty or corrupt `mesh-state.json` (e.g. a zero-byte
/// file left by a non-atomic write before a crash) made this return `Err`,
/// which aborted `MeshNode::new` and silently took the entire mesh offline — no
/// listener, no peering — until the file was deleted by hand. Now it warns and
/// starts from a fresh default.
pub fn load_state(data_dir: &Path) -> Result<MeshState> {
    let path = data_dir.join(STATE_FILE);
    if !path.exists() {
        return Ok(MeshState::default());
    }
    let content = std::fs::read_to_string(&path).context("reading mesh state")?;
    if content.trim().is_empty() {
        tracing::warn!(
            path = %path.display(),
            "mesh state file is empty; starting with fresh state"
        );
        return Ok(MeshState::default());
    }
    match serde_json::from_str(&content) {
        Ok(state) => Ok(state),
        Err(e) => {
            tracing::warn!(
                error = %e, path = %path.display(),
                "mesh state file is corrupt; starting with fresh state (a bad persistence file must never disable the mesh)"
            );
            Ok(MeshState::default())
        }
    }
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
    fn load_empty_file_returns_default_not_error() {
        // Regression: a zero-byte mesh-state.json (left by a non-atomic write
        // before a crash) used to hard-fail load_state -> aborted MeshNode::new
        // -> the whole mesh went offline silently. Must fail soft now.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), "").unwrap();
        let state = load_state(dir.path()).expect("empty state must not error");
        assert!(state.peers.is_empty());
    }

    #[test]
    fn load_corrupt_file_returns_default_not_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), "{not valid json").unwrap();
        let state = load_state(dir.path()).expect("corrupt state must not error");
        assert!(state.peers.is_empty());
    }

    #[test]
    fn save_is_atomic_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        save_state(dir.path(), &MeshState::default()).unwrap();
        // No leftover temp file, and the result reloads cleanly.
        assert!(!dir.path().join("mesh-state.json.tmp").exists());
        assert!(dir.path().join(STATE_FILE).exists());
        load_state(dir.path()).expect("saved state reloads");
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
