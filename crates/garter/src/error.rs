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
}

pub type Result<T> = std::result::Result<T, Error>;
