// Update error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("HTTP request failed: {0}")]
    Http(Box<ureq::Error>),
    #[error("failed to parse response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("installer failed with exit code {0}")]
    InstallerFailed(i32),
    #[error("SHA-256 hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("asset {0} not found in SHA256SUMS")]
    AssetNotInManifest(String),
}

impl From<ureq::Error> for UpdateError {
    fn from(e: ureq::Error) -> Self {
        Self::Http(Box::new(e))
    }
}
