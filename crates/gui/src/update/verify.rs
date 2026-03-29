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
/// Downloads the release-level `SHA256SUMS` manifest and its minisign signature,
/// verifies the signature first (authenticity), then looks up and verifies the
/// asset's hash (integrity). Both checks must pass.
///
/// This is a blocking function — call from `spawn_blocking`.
pub fn verify_asset(
    asset_path: &Path,
    asset_name: &str,
    sha256sums_url: &str,
    sha256sums_minisig_url: &str,
) -> Result<(), UpdateError> {
    let sha256sums = download_text(sha256sums_url)?;
    let minisig = download_text(sha256sums_minisig_url)?;

    // Verify signature on the manifest first — if tampered, no point checking hashes.
    verify_minisig_data(sha256sums.as_bytes(), &minisig, MINISIGN_PUBLIC_KEY)?;

    // Look up this asset's expected hash and verify.
    let expected_hex = find_hash_in_sha256sums(&sha256sums, asset_name)?;
    verify_sha256_hash(asset_path, expected_hex)?;

    Ok(())
}

// SHA-256 verification ================================================================================================

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

// SHA256SUMS parsing ==================================================================================================

/// Look up an asset's hash in a SHA256SUMS manifest.
///
/// Expects `sha256sum`-compatible format: `<64-hex-chars>  <filename>` per line.
/// Matches `asset_name` exactly against the filename field.
pub(crate) fn find_hash_in_sha256sums<'a>(content: &'a str, asset_name: &str) -> Result<&'a str, UpdateError> {
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

    Err(UpdateError::AssetNotInManifest(asset_name.to_string()))
}

// Helpers =============================================================================================================

/// Compute the SHA-256 hex digest of a file.
pub(crate) fn sha256_file(path: &Path) -> Result<String, UpdateError> {
    let data = std::fs::read(path)?;
    let hash = sha2::Sha256::digest(&data);
    Ok(hex_encode(&hash))
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
