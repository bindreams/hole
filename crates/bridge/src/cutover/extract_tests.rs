use super::*;

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_admin_args_are_quiet_admin_install_to_targetdir() {
    let args = msiexec_admin_args(
        Path::new(r"C:\dl\hole.msi"),
        Path::new(r"C:\Program Files\hole\.update-staging"),
    );
    assert_eq!(args[0], "/a", "admin (extract-only) install");
    assert!(args.iter().any(|a| a == r"C:\dl\hole.msi"), "the MSI path");
    assert!(args.iter().any(|a| a == "/qn"), "admin install must be silent");
    assert!(
        args.iter().any(|a| a.starts_with("TARGETDIR=")),
        "must target the staging dir"
    );
}

// `reverify` is locked to the production minisign key, so a present-but-unsigned
// payload is correctly rejected (no production secret exists to forge a positive
// fixture here). The accept-on-valid path is proven against a test keypair in
// `hole_common::verify` (`verify_payload_offline_accepts_a_signed_matching_payload`).

const ASSET_NAME: &str = "hole-1.0.0-windows-amd64.msi";
const MANIFEST: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  hole-1.0.0-windows-amd64.msi\n";
const MANIFEST_MINISIG: &str = "\
untrusted comment: signature from minisign secret key\n\
RUTXSaGccqReXWz2fRVbwUF7EDKUDrEVVhy1+ZHagqxXbUjrPRchUckCCnXfohVgUmLG+4ChwVsuqT+B7mEDsQVzzjkvfIpMsQ0=\n\
trusted comment: timestamp:1781791616\tfile:SHA256SUMS\thashed\n\
CXe1/4JyD0CUvZioxyOwNnRGBOioaiOGly0ng0V8g4lSWWbVK5nXQgmm0Brc5gJzCGui13REBwng4FvJNpz8Bg==\n";

#[skuld::test]
fn reverify_rejects_a_missing_payload() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.msi");
    assert!(
        reverify(&missing, ASSET_NAME, MANIFEST, MANIFEST_MINISIG).is_err(),
        "missing payload must fail closed"
    );
}

#[skuld::test]
fn reverify_rejects_a_directory_payload() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        reverify(dir.path(), ASSET_NAME, MANIFEST, MANIFEST_MINISIG).is_err(),
        "a directory is not a payload file"
    );
}

#[skuld::test]
fn reverify_rejects_a_payload_not_signed_by_the_production_key() {
    // The test manifest is signed by a test keypair, not the production key, so
    // `reverify` (production-key-locked) must reject even a hash-matching payload.
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join(ASSET_NAME);
    std::fs::write(&payload, b"hello world").unwrap();
    assert!(
        reverify(&payload, ASSET_NAME, MANIFEST, MANIFEST_MINISIG).is_err(),
        "a payload not signed by the production key must fail closed"
    );
}
