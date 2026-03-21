use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// Node identity — Ed25519 keypair for signing threat signals.
/// Generated on first run, persisted to `mesh-identity.key`.
pub struct NodeIdentity {
    keypair: SigningKey,
    pub public_key: VerifyingKey,
    pub node_id: String, // hex-encoded public key (64 chars)
}

impl NodeIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let keypair = SigningKey::generate(&mut OsRng);
        let public_key = keypair.verifying_key();
        let node_id = hex::encode(public_key.as_bytes());
        Self {
            keypair,
            public_key,
            node_id,
        }
    }

    /// Load from seed file, or generate and save if absent.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path).context("reading mesh identity")?;
            if bytes.len() != 32 {
                anyhow::bail!("mesh identity file must be 32 bytes (Ed25519 seed)");
            }
            let seed: [u8; 32] = bytes.try_into().unwrap();
            let keypair = SigningKey::from_bytes(&seed);
            let public_key = keypair.verifying_key();
            let node_id = hex::encode(public_key.as_bytes());
            Ok(Self {
                keypair,
                public_key,
                node_id,
            })
        } else {
            let identity = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, identity.keypair.as_bytes())
                .context("writing mesh identity")?;
            Ok(identity)
        }
    }

    /// Sign a canonical message. Returns base64-encoded signature.
    pub fn sign(&self, message: &[u8]) -> String {
        let sig = self.keypair.sign(message);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    /// Verify a signature from a peer. `public_key_hex` is the peer's node_id.
    pub fn verify(public_key_hex: &str, message: &[u8], signature_b64: &str) -> bool {
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let pk_array: [u8; 32] = match pk_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature_b64) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        verifying_key.verify(message, &signature).is_ok()
    }
}

/// SHA-256 hash of arbitrary data, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(&hasher.finalize())
}

/// Minimal hex encode/decode (avoids adding `hex` crate dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let identity = NodeIdentity::generate();
        let msg = b"threat signal data";
        let sig = identity.sign(msg);
        assert!(NodeIdentity::verify(&identity.node_id, msg, &sig));
    }

    #[test]
    fn reject_tampered_message() {
        let identity = NodeIdentity::generate();
        let sig = identity.sign(b"original");
        assert!(!NodeIdentity::verify(&identity.node_id, b"tampered", &sig));
    }

    #[test]
    fn reject_wrong_key() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let sig = alice.sign(b"message");
        assert!(!NodeIdentity::verify(&bob.node_id, b"message", &sig));
    }

    #[test]
    fn reject_invalid_signature() {
        let identity = NodeIdentity::generate();
        assert!(!NodeIdentity::verify(&identity.node_id, b"msg", "not-valid-base64!!!"));
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh-identity.key");

        let id1 = NodeIdentity::load_or_create(&path).unwrap();
        let id2 = NodeIdentity::load_or_create(&path).unwrap();

        assert_eq!(id1.node_id, id2.node_id);

        let sig = id1.sign(b"test");
        assert!(NodeIdentity::verify(&id2.node_id, b"test", &sig));
    }

    #[test]
    fn sha256_hex_works() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
