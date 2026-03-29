// Asset integrity and authenticity verification.

use std::path::Path;

use sha2::Digest;

use super::error::UpdateError;

/// Embedded minisign public key for release verification.
pub(crate) const MINISIGN_PUBLIC_KEY: &str = "RWR/A9sHYSwUIYkFXgNc9NcHSP+aoWCHusziW4Kwl3vsbApsqy4Wte1Z";

/// Maximum size for sidecar file downloads (1 MiB).
const SIDECAR_SIZE_LIMIT: u64 = 1024 * 1024;

// Public API ==========================================================================================================

/// Verify a downloaded asset's integrity (SHA-256) and authenticity (minisign).
///
/// Both checks are mandatory. SHA-256 is verified first (short-circuits on failure).
/// This is a blocking function — call from `spawn_blocking`.
pub fn verify_asset(asset_path: &Path, sha256_url: &str, minisig_url: &str) -> Result<(), UpdateError> {
    verify_sha256(asset_path, sha256_url)?;
    verify_minisig(asset_path, minisig_url)?;
    Ok(())
}

// SHA-256 verification ================================================================================================

/// Download the `.sha256` file and verify the asset's hash.
fn verify_sha256(asset_path: &Path, sha256_url: &str) -> Result<(), UpdateError> {
    let content = download_text(sha256_url)?;
    let expected_hex = parse_sha256_file(&content);
    verify_sha256_hash(asset_path, expected_hex)
}

/// Verify a file's SHA-256 hash against an expected hex digest. Pure function (no network).
pub(crate) fn verify_sha256_hash(asset_path: &Path, expected_hex: &str) -> Result<(), UpdateError> {
    let actual_hex = sha256_file(asset_path)?;
    if actual_hex != expected_hex.to_ascii_lowercase() {
        return Err(UpdateError::HashMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }
    Ok(())
}

// Minisign verification ===============================================================================================

/// Download the `.minisig` file and verify the asset's signature.
fn verify_minisig(asset_path: &Path, minisig_url: &str) -> Result<(), UpdateError> {
    let sig_text = download_text(minisig_url)?;
    let data = std::fs::read(asset_path)?;
    verify_minisig_data(&data, &sig_text, MINISIGN_PUBLIC_KEY)
}

/// Verify a minisign signature against data and a public key. Pure function (no network).
pub(crate) fn verify_minisig_data(data: &[u8], signature_text: &str, public_key_str: &str) -> Result<(), UpdateError> {
    use minisign_verify::{PublicKey, Signature};

    let pk = PublicKey::from_base64(public_key_str)
        .map_err(|e| UpdateError::SignatureInvalid(format!("invalid public key: {e}")))?;
    let sig = Signature::decode(signature_text)
        .map_err(|e| UpdateError::SignatureInvalid(format!("invalid signature file: {e}")))?;

    pk.verify(data, &sig, false)
        .map_err(|e| UpdateError::SignatureInvalid(e.to_string()))
}

// Helpers =============================================================================================================

/// Compute the SHA-256 hex digest of a file.
pub(crate) fn sha256_file(path: &Path) -> Result<String, UpdateError> {
    let data = std::fs::read(path)?;
    let hash = sha2::Sha256::digest(&data);
    Ok(hex_encode(&hash))
}

/// Parse a `.sha256` file, extracting the hex hash.
///
/// Handles both formats:
/// - `<hash>  <filename>` (sha256sum output)
/// - `<hash>` (bare hex)
///
/// Trims `\n` and `\r\n` before parsing.
pub(crate) fn parse_sha256_file(content: &str) -> &str {
    content.split_whitespace().next().unwrap_or("")
}

/// Encode bytes as lowercase hex.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Download a small text file from a URL, with a size limit.
fn download_text(url: &str) -> Result<String, UpdateError> {
    let response = ureq::get(url).call()?;
    let text = response
        .into_body()
        .with_config()
        .limit(SIDECAR_SIZE_LIMIT)
        .read_to_string()?;
    Ok(text)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod verify_tests;
