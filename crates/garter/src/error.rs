/// What a chain, a plugin or a tap fails with.
///
/// `Display` is written for a person: it names the plugins and what failed, and never prints a `source()`, a filesystem
/// path, or another crate's error text. The one free text is a plugin's own [`StartError::Fatal`](crate::StartError)
/// detail, shown as the plugin wrote it. A failed resolve names the server, which a consumer's redaction covers. The
/// cause is in the source chain, for logs.
///
/// Every [`Error::Chain`] garter raises carries only garter's own words.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("an I/O operation of the plugin chain failed")]
    Io(#[from] std::io::Error),

    #[error("plugin '{name}' exited with code {code}")]
    PluginExit { name: String, code: i32 },

    #[error("plugin '{name}' was killed by signal")]
    PluginKilled { name: String },

    #[error("{0}")]
    Chain(String),

    /// A chain's hop failed to start, so [`ChainRunner::run`](crate::ChainRunner::run) ended the chain. `cause` is the
    /// typed failure the hop reported, or the exit-before-ready one the chain synthesized when the hop ended without
    /// reporting and every member returned `Ok(())` (a member's own error is returned as itself).
    #[error("plugin '{plugin}' failed to start: {cause}")]
    StartFailed {
        plugin: String,
        cause: crate::sitrep::StartError,
    },

    /// `reason` is garter's wording ("not set", "contains invalid Unicode", "could not be parsed"); a parse error is
    /// the `cause`.
    #[error("environment variable '{var}' missing or invalid: {reason}")]
    Env {
        var: String,
        reason: String,
        #[source]
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The tap of `plugin` failed at `step`. `cause` is the OS error.
    #[error("the tap of plugin '{plugin}' could not {step}")]
    Tap {
        plugin: String,
        step: TapStep,
        #[source]
        cause: std::io::Error,
    },

    /// The server the chain forwards to (`host:port`) did not resolve: the lookup failed (`cause`), or it returned no
    /// address.
    #[error("could not resolve the server {server}")]
    Resolve {
        server: String,
        #[source]
        cause: Option<std::io::Error>,
    },

    #[error("malformed SS_PLUGIN_OPTIONS: {0}")]
    MalformedOptions(#[from] crate::sip003::MalformedOptions),

    /// Subprocess management — spawning a plugin under containment, signalling it,
    /// tearing its tree down. Typed rather than flattened into
    /// [`Error::Chain`]: a caller that needs the distinction should read the type,
    /// not parse a message back into one.
    #[error("a plugin process could not be managed")]
    Cosca(#[from] cosca::error::Error),

    /// `plugin` could not be spawned, and no process of it is left running (a spawn failure that may have left one is
    /// [`Error::StopUnconfirmed`]). `cause` is the OS's or cosca's error, which can name the plugin's path.
    #[error("could not spawn plugin '{plugin}'")]
    Spawn {
        plugin: String,
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A plugin's stop could not be confirmed: its root's kill was refused and the root is not known to have exited,
    /// its reap failed, a plugin task panicked, or the chain gave up on its members at the drain bound and ended them
    /// by dropping them. Such a plugin may still be running.
    ///
    /// `plugins` names the ones unconfirmed, never none. `cause` is the stop's own failure (the refusal, the failed
    /// reap, the panic's `JoinError`, the drain bound) and is the error's source, not part of its text; whatever else
    /// went wrong was logged when it happened.
    #[error("{}", unconfirmed_stop_text(plugins))]
    StopUnconfirmed {
        plugins: Vec<String>,
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The [`PidSink`](crate::PidSink) refused `plugin`'s identity, so the plugin was taken down at once and its stop
    /// confirmed (an unconfirmed one is [`Error::StopUnconfirmed`]). `cause` is the sink's own error.
    #[error("the pid sink refused plugin '{plugin}'")]
    PidSink {
        plugin: String,
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// What a tap was doing when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapStep {
    AllocateInnerPort,
    BindListener,
    ReadListenerAddress,
    AcceptConnection,
}

impl std::fmt::Display for TapStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TapStep::AllocateInnerPort => "allocate an inner port",
            TapStep::BindListener => "bind its listener",
            TapStep::ReadListenerAddress => "read its listener's address",
            TapStep::AcceptConnection => "accept a connection",
        })
    }
}

fn unconfirmed_stop_text(plugins: &[String]) -> String {
    let names: Vec<_> = plugins.iter().map(|p| format!("'{p}'")).collect();
    format!("plugin {} could not be confirmed stopped", names.join(", "))
}

/// How loudly an error outranks the rest when a chain reports one of several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Ordinary,
    PidSink,
    StopUnconfirmed,
}

impl Error {
    /// Whether no plugin is left running behind this error. False only for [`Error::StopUnconfirmed`]; every other error
    /// is raised before a plugin runs, or says how one ended.
    pub fn stop_confirmed(&self) -> bool {
        self.rank() != Rank::StopUnconfirmed
    }

    /// The one per-variant decision: where an error stands when a chain reports one of several.
    fn rank(&self) -> Rank {
        match self {
            Error::StopUnconfirmed { .. } => Rank::StopUnconfirmed,
            Error::PidSink { .. } => Rank::PidSink,
            Error::Io(_)
            | Error::PluginExit { .. }
            | Error::PluginKilled { .. }
            | Error::Chain(_)
            | Error::StartFailed { .. }
            | Error::Env { .. }
            | Error::Tap { .. }
            | Error::Resolve { .. }
            | Error::MalformedOptions(_)
            | Error::Cosca(_)
            | Error::Spawn { .. } => Rank::Ordinary,
        }
    }

    /// Whether `self` stands above `other` when a chain reports one of several. Equal ranks do not: the first stands.
    pub(crate) fn ranks_above(&self, other: &Error) -> bool {
        self.rank() > other.rank()
    }

    /// Whether this error outranks an error of the caller's own that is not a garter error (a cancel, a readiness
    /// timeout): the caller reports this one instead. The ranking `Error::then` applies, asked of one error.
    pub fn outranks_a_callers_own_error(&self) -> bool {
        self.rank() > Rank::Ordinary
    }

    /// The error a plugin's task ends with when it ends without returning: it panicked, so unwinding skipped the
    /// plugin's own take-down, or the runtime cancelled it. Either way its child may still be running.
    pub(crate) fn task_lost(plugin: &str, lost: tokio::task::JoinError) -> Error {
        Error::StopUnconfirmed {
            plugins: vec![plugin.to_owned()],
            cause: Box::new(lost),
        }
    }

    /// The error a chain reports when `self` came first and `later` followed: the higher [`Rank`] wins, and the first
    /// error stands among equals. Two unconfirmed stops name all their plugins and keep the earlier cause.
    ///
    /// Logs nothing: an error is logged where it arises or is taken (a member's exit, the ready gate, a stopped
    /// inner), so the error dropped here, and the cause the merged stop drops, are already in the log.
    pub(crate) fn then(self, later: Error) -> Error {
        match (self, later) {
            (
                Error::StopUnconfirmed { mut plugins, cause },
                Error::StopUnconfirmed {
                    plugins: later_plugins, ..
                },
            ) => {
                plugins.extend(later_plugins);
                Error::StopUnconfirmed { plugins, cause }
            }
            (first, later) if later.ranks_above(&first) => later,
            (first, _) => first,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
