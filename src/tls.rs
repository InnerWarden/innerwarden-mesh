//! TLS between peers: how each side knows the other.
//!
//! # A peer is contacted only when its configuration says how to know it
//!
//! Every configured peer names, besides its HTTPS endpoint, the certificate it
//! answers with: the SHA-256 of that certificate (`tls_cert_sha256`, the value
//! `openssl x509 -noout -fingerprint -sha256` prints, colons optional), or a
//! CA file (`tls_ca`) its certificate must chain to for the endpoint's name,
//! or both (then both must hold). A peer with neither, or with an `http://`
//! endpoint (no certificate to check), is refused: it is never contacted and
//! nothing it answers is read (fail closed). Until this, the client accepted
//! any certificate from anyone (`danger_accept_invalid_certs`), so whoever sat
//! between two peers read every signal and answered the identity ping with a
//! node id of its own choosing, which the node then trusted.
//!
//! With a pinned digest the certificate's name and dates are not checked: the
//! pin IS the identity, and the handshake still proves the peer holds that
//! certificate's private key (the handshake signature is verified against it).
//!
//! # The listener answers with its own certificate
//!
//! `tls_cert` and `tls_key` in `[mesh]` name a PEM certificate and key. Without
//! them, the node makes a self-signed pair in its data directory on first start
//! (`mesh-tls-cert.pem`, `mesh-tls-key.pem`, the key mode 0600) and keeps it:
//! its digest is what the other side pins ([`cert_file_sha256`]). Plain HTTP is
//! served only on a loopback address (behind a TLS terminator on the host).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::PeerEntry;

/// The self-signed certificate a node makes when `[mesh]` names none.
pub const GENERATED_CERT_FILE: &str = "mesh-tls-cert.pem";
/// Its private key (mode 0600).
pub const GENERATED_KEY_FILE: &str = "mesh-tls-key.pem";

/// The crypto every mesh TLS config is built with. Named, never the process
/// default: a host process may have none installed, or another one.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// PURE. A SHA-256 digest as written in a config: 64 hex digits, any case,
/// optionally separated by `:` (openssl's form). `None` for anything else.
pub fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    let hex: String = text.trim().chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// PURE. A digest in openssl's form (`AB:CD:...`), the form an operator pastes.
pub fn format_sha256(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The SHA-256 of a certificate's DER bytes.
pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// The SHA-256 of the first certificate of a PEM file: the value a peer pins.
pub fn cert_file_sha256(path: &Path) -> Result<[u8; 32]> {
    let cert = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading {}", path.display()))?
        .next()
        .with_context(|| format!("{} holds no certificate", path.display()))?
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(cert_sha256(cert.as_ref()))
}

/// Accepts exactly one certificate (by its SHA-256), and, when a CA is also
/// configured, only if it also chains to that CA for the endpoint's name.
#[derive(Debug)]
struct PinnedCert {
    sha256: [u8; 32],
    chain: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_sha256(end_entity.as_ref()) != self.sha256 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        match &self.chain {
            Some(chain) => {
                chain.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            None => Ok(ServerCertVerified::assertion()),
        }
    }

    // The handshake signature is checked against the certificate presented,
    // which is the pinned one: the peer proves it holds its private key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The CA file's certificates as a verifier for the endpoint's name.
fn ca_verifier(path: &str, provider: &Arc<CryptoProvider>) -> Result<Arc<WebPkiServerVerifier>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).with_context(|| format!("reading {path}"))? {
        let cert = cert.with_context(|| format!("parsing {path}"))?;
        roots
            .add(cert)
            .with_context(|| format!("{path}: not a CA certificate"))?;
    }
    if roots.is_empty() {
        bail!("{path} holds no certificate");
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .with_context(|| format!("{path}: unusable as a CA"))
}

/// The HTTP client for one configured peer, or why the peer is refused.
///
/// Refused: an endpoint that is not `https://`; neither `tls_cert_sha256` nor
/// `tls_ca`; a digest that does not parse; a CA file that does not load.
pub fn peer_client(entry: &PeerEntry, timeout: std::time::Duration) -> Result<reqwest::Client> {
    if !entry.endpoint.trim().starts_with("https://") {
        bail!("the endpoint is not https://, so there is no certificate to check");
    }
    let pin = match entry.tls_cert_sha256.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(text) => Some(parse_sha256(text).with_context(|| {
            "tls_cert_sha256 is not a SHA-256 digest (64 hex digits, colons allowed)"
        })?),
    };
    let ca = entry
        .tls_ca
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty());
    let provider = provider();
    let chain = ca.map(|path| ca_verifier(path, &provider)).transpose()?;
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?;
    let config = match (pin, chain) {
        (Some(sha256), chain) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert {
                sha256,
                chain,
                provider,
            }))
            .with_no_client_auth(),
        (None, Some(chain)) => builder.with_webpki_verifier(chain).with_no_client_auth(),
        (None, None) => {
            bail!("neither tls_cert_sha256 nor tls_ca is set, so its certificate cannot be checked")
        }
    };
    reqwest::Client::builder()
        .timeout(timeout)
        // A redirect is never followed: the next hop could be http:// (the
        // signal in clear) or another host, past the certificate checked here.
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(config)
        .build()
        .context("building the peer's HTTPS client")
}

/// The listener's certificate and key: the ones `[mesh]` names, or the node's
/// own self-signed pair, made on first start and kept.
pub fn listener_cert_paths(
    data_dir: &Path,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> Result<(PathBuf, PathBuf)> {
    let named = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    match (named(tls_cert), named(tls_key)) {
        (Some(cert), Some(key)) => Ok((cert, key)),
        (None, None) => {
            let cert = data_dir.join(GENERATED_CERT_FILE);
            let key = data_dir.join(GENERATED_KEY_FILE);
            if !cert.exists() || !key.exists() {
                generate_self_signed(&cert, &key)?;
            }
            Ok((cert, key))
        }
        _ => bail!("[mesh] names only one of tls_cert and tls_key; set both or neither"),
    }
}

/// Write a new self-signed pair. The key is created 0600 (never widened by
/// the umask first) and neither file is ever overwritten.
fn generate_self_signed(cert_path: &Path, key_path: &Path) -> Result<()> {
    use std::io::Write;

    let key = rcgen::KeyPair::generate().context("generating the mesh TLS key")?;
    let mut params = rcgen::CertificateParams::new(vec!["innerwarden-mesh".to_string()])
        .context("mesh certificate parameters")?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("InnerWarden mesh peer".to_string()),
    );
    let cert = params
        .self_signed(&key)
        .context("signing the mesh certificate")?;

    // A pair half written by an earlier start is replaced whole.
    for path in [cert_path, key_path] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    let create = |path: &Path, mode: u32| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        options
            .open(path)
            .with_context(|| format!("creating {}", path.display()))
    };
    create(key_path, 0o600)?
        .write_all(key.serialize_pem().as_bytes())
        .with_context(|| format!("writing {}", key_path.display()))?;
    create(cert_path, 0o644)?
        .write_all(cert.pem().as_bytes())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(())
}

/// The listener's TLS configuration from a PEM certificate chain and key.
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    if certs.is_empty() {
        bail!("{} holds no certificate", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("reading the key {}", key_path.display()))?;
    server_config_from(certs, key)
}

fn server_config_from(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the mesh certificate and key do not match")?;
    Ok(Arc::new(config))
}

/// Test support: a certificate for `names` (DNS names or IP literals), signed
/// by `issuer` or self-signed, as (DER, server config, its SHA-256).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub struct TestCa {
        pub issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        pub pem: String,
    }

    pub fn ca() -> TestCa {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mesh test CA");
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    pub fn leaf(names: &[&str], issuer: Option<&TestCa>) -> (Arc<rustls::ServerConfig>, [u8; 32]) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = match issuer {
            Some(ca) => params.signed_by(&key, &ca.issuer).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        let der = cert.der().clone();
        let sha = cert_sha256(der.as_ref());
        let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        (server_config_from(vec![der], key).unwrap(), sha)
    }

    /// A raw TLS client config that accepts exactly the certificate `sha256`,
    /// for tests that speak to the listener byte by byte.
    pub fn pinned_client(sha256: [u8; 32]) -> Arc<rustls::ClientConfig> {
        let provider = provider();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCert {
                    sha256,
                    chain: None,
                    provider,
                }))
                .with_no_client_auth(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(endpoint: &str, pin: Option<&str>, ca: Option<&str>) -> PeerEntry {
        PeerEntry {
            endpoint: endpoint.to_string(),
            public_key: String::new(),
            label: None,
            tls_cert_sha256: pin.map(str::to_string),
            tls_ca: ca.map(str::to_string),
        }
    }

    #[test]
    fn a_digest_parses_in_openssl_form_or_bare_hex_and_nothing_else() {
        let bare = "ab".repeat(32);
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(parse_sha256(&bare), Some([0xab; 32]));
        assert_eq!(parse_sha256(&colons), Some([0xab; 32]));
        assert_eq!(format_sha256(&[0xab; 32]), colons);
        assert_eq!(parse_sha256(&"ab".repeat(31)), None);
        assert_eq!(parse_sha256(&"zz".repeat(32)), None);
        assert_eq!(parse_sha256(""), None);
    }

    /// FAILS ON REVERT (the client back to accepting any certificate): a peer
    /// that says nothing about its certificate, or speaks plain HTTP, would be
    /// contacted.
    #[test]
    fn a_peer_without_a_pin_or_a_ca_or_over_plain_http_is_refused() {
        let t = std::time::Duration::from_secs(1);
        let pin = "ab".repeat(32);
        let none = peer_client(&entry("https://10.0.0.5:8790", None, None), t).unwrap_err();
        assert!(none.to_string().contains("neither"), "{none}");
        let blank = peer_client(&entry("https://10.0.0.5:8790", Some(" "), Some("")), t);
        assert!(blank.is_err());
        let plain = peer_client(&entry("http://10.0.0.5:8790", Some(&pin), None), t).unwrap_err();
        assert!(plain.to_string().contains("https"), "{plain}");
        let bad = peer_client(&entry("https://10.0.0.5:8790", Some("abc"), None), t).unwrap_err();
        assert!(bad.to_string().contains("tls_cert_sha256"), "{bad}");
        let missing_ca = peer_client(
            &entry("https://10.0.0.5:8790", None, Some("/nonexistent/ca.pem")),
            t,
        );
        assert!(missing_ca.is_err());
        assert!(peer_client(&entry("https://10.0.0.5:8790", Some(&pin), None), t).is_ok());
    }

    #[test]
    fn the_listener_makes_its_pair_once_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = listener_cert_paths(dir.path(), None, None).unwrap();
        let first = cert_file_sha256(&cert).unwrap();
        server_config(&cert, &key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let (again, _) = listener_cert_paths(dir.path(), None, None).unwrap();
        assert_eq!(cert_file_sha256(&again).unwrap(), first, "regenerated");
        assert!(listener_cert_paths(dir.path(), Some("/x.pem"), None).is_err());
        assert_eq!(
            listener_cert_paths(dir.path(), Some("/c.pem"), Some("/k.pem")).unwrap(),
            (PathBuf::from("/c.pem"), PathBuf::from("/k.pem"))
        );
    }
}
