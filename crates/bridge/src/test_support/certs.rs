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
    /// `cert=<path>;key=<path>`.
    pub fn plugin_opts_fragment(&self) -> String {
        format!(
            "cert={};key={}",
            path_for_plugin_opts(&self.cert_path),
            path_for_plugin_opts(&self.key_path)
        )
    }
}

/// Render a path for embedding in a SIP003 `plugin_opts` string.
///
/// v2ray-plugin's args parser treats backslashes as escape characters
/// (`\X` is unescaped to `X`), which mangles Windows paths like
/// `C:\Users\foo\AppData\...` into `C:UsersfooAppData...`. Workarounds:
///
/// 1. Replace backslashes with forward slashes — Windows accepts forward
///    slashes in file paths and v2ray-plugin's underlying `os.Open` does
///    too.
/// 2. Or double the backslashes (`\\`) in the plugin_opts string.
///
/// Option 1 is simpler and is what we use here.
pub(crate) fn path_for_plugin_opts(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// Generate a self-signed CA cert with SAN `DNS:cloudfront.com` and write it
/// to a fresh tempdir. Panics if rcgen or std::fs fails — tests want loud
/// errors here.
pub(crate) fn generate_test_certs() -> TestCerts {
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let mut params = CertificateParams::new(vec!["cloudfront.com".to_string()])
        .expect("rcgen accepts cloudfront.com as a subject name");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Explicit key usages: CA needs KeyCertSign + DigitalSignature; the
    // same cert is also presented as the server's leaf, so it needs
    // ServerAuth EKU. Without these, Go's crypto/x509 (v2ray-plugin's
    // verifier) rejects the cert during chain validation.
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

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
