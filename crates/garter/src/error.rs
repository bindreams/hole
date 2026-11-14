/// Why running a chain or one of its plugins failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// A plugin process ended with a nonzero exit code.
    #[error("plugin '{name}' exited with code {code}")]
    PluginExit { name: String, code: i32 },

    /// A plugin process ended without an exit code: a signal on Unix. Never produced on Windows, where
    /// `ExitStatus::code()` is always `Some`.
    #[error("plugin '{name}' was killed by signal")]
    PluginKilled { name: String },

    /// Any other failure, carried as a message.
    #[error("{0}")]
    Chain(String),

    /// A chain's hop failed to start, so [`ChainRunner::run`](crate::ChainRunner::run) ended the chain. `cause` is the
    /// typed failure the hop reported (or the exit-before-ready one the chain synthesized).
    #[error("plugin '{plugin}' failed to start: {cause}")]
    StartFailed {
        plugin: String,
        cause: crate::sitrep::StartError,
    },

    /// A SIP003 environment variable is missing or invalid.
    #[error("environment variable '{var}' missing or invalid: {reason}")]
    Env { var: String, reason: String },

    /// `SS_PLUGIN_OPTIONS` is an options string a SIP003 plugin rejects.
    #[error("malformed SS_PLUGIN_OPTIONS: {0}")]
    MalformedOptions(#[from] crate::sip003::MalformedOptions),

    /// Subprocess management — spawning a plugin under containment, signalling it,
    /// tearing its tree down. Typed rather than flattened into
    /// [`Error::Chain`]: a caller that needs the distinction should read the type,
    /// not parse a message back into one.
    #[error("{0}")]
    Cosca(#[from] cosca::error::Error),
}

/// [`std::result::Result`] with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
