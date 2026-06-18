// Asset integrity and authenticity verification.
//
// The pure offline core (minisign + SHA-256 + manifest parsing) lives in
// `hole_common::verify` so the privileged bridge can re-verify the same payload
// without depending on the GUI crate. This module adds the GUI's network layer:
// download the sidecars, then call the shared core.

use std::path::Path;

use hole_common::verify::{verify_payload_offline, VerifyError};

use super::error::UpdateError;

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
    verify_payload_offline(asset_path, asset_name, &sha256sums, &minisig)?;
    Ok(())
}

// Helpers =============================================================================================================

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

impl From<VerifyError> for UpdateError {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::SignatureInvalid(m) => UpdateError::SignatureInvalid(m),
            VerifyError::HashMismatch { expected, actual } => UpdateError::HashMismatch { expected, actual },
            VerifyError::AssetNotInManifest(name) => UpdateError::AssetNotInManifest(name),
            VerifyError::Io(e) => UpdateError::Io(e),
        }
    }
}
