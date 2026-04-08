//! Self-signed TLS cert + key generation for v2ray-plugin TLS / QUIC tests.
//!
//! Both v2ray-plugin transports require a cert+key pair on the server side
//! and the same cert (as a trust anchor) on the client side. We generate a
//! single ECDSA-P256 cert in a process-scoped tempdir and reference it from
//! both ends.
//!
//! ## Cert constraints
//!
//! Three things must be true or v2ray-plugin's TLS handshake fails:
//!
//! 1. **SAN `DNS:cloudfront.com`** — Go's `crypto/tls` rejects CN-only certs
//!    since Go 1.15. `rcgen::CertificateParams::new(vec!["cloudfront.com"])`
//!    populates the Subject Alternative Name correctly by default.
//! 2. **`is_ca = Ca(Unconstrained)`** — v2ray-plugin's client mode uses
//!    `Usage: Certificate_AUTHORITY_VERIFY` on the provided cert
//!    ([external/v2ray-plugin/main.go:187](../../../external/v2ray-plugin/main.go)),
//!    treating it as a trust anchor. For a self-signed leaf to verify
//!    against itself as a trust anchor, it must be marked as a CA.
//! 3. **`host=cloudfront.com`** plugin_opt on both client and server. v2ray-plugin
//!    uses this as `tls.Config{ServerName: *host}`. Mismatch between client
//!    SNI and server cert SAN = handshake failure.

use std::path::PathBuf;

/// Self-signed cert + key pair on disk, valid for SNI "cloudfront.com".
///
/// The tempdir lives for as long as the struct does. Dropping it removes
/// both files.
pub(crate) struct TestCerts {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    _tempdir: tempfile::TempDir,
}

impl TestCerts {
    /// Plugin_opts fragment for the cert/key paths, in the form
    /// `cert=<path>;key=<path>`. Use as a building block when constructing
    /// `SS_PLUGIN_OPTIONS` strings.
    pub fn plugin_opts_fragment(&self) -> String {
        // Tempdir paths on Windows contain backslashes but no semicolons or
        // equals signs, so SIP003's k=v;k=v separator format is safe to use
        // raw — no escaping required as long as paths don't contain ; or =.
        format!("cert={};key={}", self.cert_path.display(), self.key_path.display())
    }
}

/// Generate a self-signed CA cert with SAN `DNS:cloudfront.com` and write it
/// to a fresh tempdir. Panics if rcgen or std::fs fails — tests want loud
/// errors here.
pub(crate) fn generate_test_certs() -> TestCerts {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let mut params = CertificateParams::new(vec!["cloudfront.com".to_string()])
        .expect("rcgen accepts cloudfront.com as a subject name");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key_pair = KeyPair::generate().expect("rcgen ECDSA key generation");
    let cert = params
        .self_signed(&key_pair)
        .expect("rcgen self-sign with the matching key pair");

    let tempdir = tempfile::tempdir().expect("create cert tempdir");
    let cert_path = tempdir.path().join("test-cert.pem");
    let key_path = tempdir.path().join("test-key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert.pem");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key.pem");

    TestCerts {
        cert_path,
        key_path,
        _tempdir: tempdir,
    }
}
