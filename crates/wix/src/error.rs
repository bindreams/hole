use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WiX extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("WiX build failed (exit code {code})")]
    BuildFailed { code: i32 },

    #[error("hook failed: `{command}` exited with code {code}")]
    HookFailed { command: String, code: i32 },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("WiX is only supported on Windows")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, Error>;
