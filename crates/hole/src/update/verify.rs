// Asset integrity and authenticity verification.
//
// The pure offline core (minisign + SHA-256 + manifest parsing) lives in
// `hole_common::verify` so the privileged bridge can re-verify the same payload
// without depending on the GUI crate. This module is the GUI's network layer:
// download the sidecars so both the GUI's local verify and the bridge's
// re-verify can run the shared offline core against the same manifest.

use hole_common::verify::VerifyError;

use super::error::UpdateError;

/// Maximum size for sidecar file downloads (1 MiB).
const SIDECAR_SIZE_LIMIT: u64 = 1024 * 1024;

// Public API ==========================================================================================================

/// Download the `SHA256SUMS` manifest and its minisign signature, returning their
/// texts. The caller passes them to BOTH the local verify and the bridge's
/// `ApplyUpdate` request, so the bridge can re-verify the same payload offline.
pub fn fetch_manifest(sha256sums_url: &str, sha256sums_minisig_url: &str) -> Result<(String, String), UpdateError> {
    let sha256sums = download_text(sha256sums_url)?;
    let minisig = download_text(sha256sums_minisig_url)?;
    Ok((sha256sums, minisig))
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
