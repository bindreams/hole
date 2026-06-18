// Offline integrity + authenticity verification of a release payload.
//
// The pure core lives here so both the GUI (verify-on-download) and the
// privileged bridge (re-verify-before-extract) share one implementation over
// the same embedded minisign key — no network, no GUI-crate dependency.

use std::path::Path;

use sha2::Digest;
use thiserror::Error;

/// Embedded minisign public key for release verification.
pub const MINISIGN_PUBLIC_KEY: &str = "RWR/A9sHYSwUIYkFXgNc9NcHSP+aoWCHusziW4Kwl3vsbApsqy4Wte1Z";

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("SHA-256 hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("asset {0} not found in SHA256SUMS")]
    AssetNotInManifest(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// Public API ==========================================================================================================

/// Verify a payload's authenticity and integrity entirely offline.
///
/// The caller supplies the already-fetched `SHA256SUMS` manifest and its
/// minisign signature; this verifies the signature over the manifest first
/// (authenticity), then the payload's hash against its manifest entry
/// (integrity). Both checks must pass.
///
/// Blocking (hashes the file) — call from `spawn_blocking`.
pub fn verify_payload_offline(
    payload: &Path,
    asset_name: &str,
    sha256sums: &str,
    sha256sums_minisig: &str,
) -> Result<(), VerifyError> {
    verify_minisig_data(sha256sums.as_bytes(), sha256sums_minisig, MINISIGN_PUBLIC_KEY)?;
    let expected = find_hash_in_sha256sums(sha256sums, asset_name)?;
    verify_sha256_hash(payload, expected)
}

// SHA-256 verification ================================================================================================

/// Verify a file's SHA-256 hash against an expected hex digest.
pub fn verify_sha256_hash(asset_path: &Path, expected_hex: &str) -> Result<(), VerifyError> {
    let actual_hex = sha256_file(asset_path)?;
    if actual_hex != expected_hex.to_ascii_lowercase() {
        return Err(VerifyError::HashMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }
    Ok(())
}

// Minisign verification ===============================================================================================

/// Verify a minisign signature against data and a public key.
pub fn verify_minisig_data(data: &[u8], signature_text: &str, public_key_str: &str) -> Result<(), VerifyError> {
    use minisign_verify::{PublicKey, Signature};

    let pk = PublicKey::from_base64(public_key_str)
        .map_err(|e| VerifyError::SignatureInvalid(format!("invalid public key: {e}")))?;
    let sig = Signature::decode(signature_text)
        .map_err(|e| VerifyError::SignatureInvalid(format!("invalid signature file: {e}")))?;

    pk.verify(data, &sig, false)
        .map_err(|e| VerifyError::SignatureInvalid(e.to_string()))
}

// SHA256SUMS parsing ==================================================================================================

/// Look up an asset's hash in a SHA256SUMS manifest.
///
/// Expects `sha256sum`-compatible format: `<64-hex-chars>  <filename>` per line.
/// Matches `asset_name` exactly against the filename field.
pub fn find_hash_in_sha256sums<'a>(content: &'a str, asset_name: &str) -> Result<&'a str, VerifyError> {
    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        // sha256sum format: "<hash>  <filename>" (two-space separator).
        // split_whitespace handles both single and double spaces.
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        let Some(name) = parts.next() else { continue };

        if name == asset_name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(hash);
        }
    }

    Err(VerifyError::AssetNotInManifest(asset_name.to_string()))
}

// Helpers =============================================================================================================

/// Compute the SHA-256 hex digest of a file by streaming through the hasher.
pub fn sha256_file(path: &Path) -> Result<String, VerifyError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Encode bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;
