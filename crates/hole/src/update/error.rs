// Update error types.

use thiserror::Error;

use super::withdrawals::WithdrawalListError;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("{}", http_failure(.0))]
    Http(Box<ureq::Error>),
    #[error("failed to parse response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SHA-256 hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("asset {0} not found in SHA256SUMS")]
    AssetNotInManifest(String),
    #[error(transparent)]
    WithdrawalList(#[from] WithdrawalListError),
}

impl From<ureq::Error> for UpdateError {
    fn from(e: ureq::Error) -> Self {
        Self::Http(Box::new(e))
    }
}

/// What a person reads for a failed request: a timeout says the server did not respond.
fn http_failure(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => format!("the server did not respond in time ({e})"),
        _ => format!("HTTP request failed: {e}"),
    }
}
