#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("plugin '{name}' exited with code {code}")]
    PluginExit { name: String, code: i32 },

    #[error("plugin '{name}' was killed by signal")]
    PluginKilled { name: String },

    #[error("{0}")]
    Chain(String),

    #[error("environment variable '{var}' missing or invalid: {reason}")]
    Env { var: String, reason: String },

    #[error("malformed SS_PLUGIN_OPTIONS: {0}")]
    MalformedOptions(#[from] crate::sip003::MalformedOptions),

    /// Subprocess management — spawning a plugin under containment, signalling it,
    /// tearing its tree down. Transparent rather than flattened into
    /// [`Error::Chain`]: a caller that needs the distinction should read the type,
    /// not parse a message back into one.
    #[error(transparent)]
    Cosca(#[from] cosca::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
