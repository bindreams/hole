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

    /// A chain's hop failed to start, so [`ChainRunner::run`](crate::ChainRunner::run) ended the chain. `cause` is the
    /// typed failure the hop reported (or the exit-before-ready one the chain synthesized): a caller with no
    /// `on_ready` still tells a bind conflict from any other failure by matching it.
    #[error("plugin '{plugin}' failed to start: {cause}")]
    StartFailed {
        plugin: String,
        cause: crate::sitrep::StartError,
    },

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
