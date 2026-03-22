use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WiX extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("WiX build failed (exit code {code}): {stderr}")]
    BuildFailed { code: i32, stderr: String },

    #[error("cargo build failed (exit code {0})")]
    CargoBuildFailed(i32),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("staging failed: {0}")]
    StagingFailed(String),

    #[error("WiX is only supported on Windows")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, Error>;
