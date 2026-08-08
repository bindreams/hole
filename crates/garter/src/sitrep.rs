//! sitrep — a structured plugin→client control protocol.
//!
//! A plugin emits newline-delimited JSON events on its **stdout**; human
//! logs stay on **stderr**. The first stdout line MUST be the `hello`
//! handshake `{"event":"hello","protocol":"sitrep-<semver>"}` — its
//! presence (a `protocol` matching `^sitrep-`) is the tier-1 capability
//! signal. Subsequent JSON-object lines are events (dispatched by
//! `event`; unknown events are ignored for forward-compat); non-JSON
//! lines are log passthrough. The normative protocol spec is in
//! `crates/garter/SITREP.md`; this module is its reference implementation.
//!
//! `SITREP_PROTOCOL` is the protocol version this consumer SPEAKS. Bump
//! the MAJOR only for breaking envelope/semantics changes; MINOR is
//! additive (old consumers ignore new events/fields); PATCH is non-wire.
pub const SITREP_PROTOCOL: &str = "sitrep-1.0.0";

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// IP transports a plugin actually serves at its local listener.
    /// Reported on `ready` — the authoritative per-plugin transport set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Transports: u8 {
        const TCP = 0b01;
        const UDP = 0b10;
    }
}

/// Readiness payload reported by a single plugin when its listener is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginReady {
    /// The address the plugin is actually accepting on.
    pub listen: SocketAddr,
    /// Transports served at `listen`.
    pub transports: Transports,
}

/// Display text for [`StartError::ExitedBeforeReady`] and the fallback a
/// caller shows if it can't recover anything more specific.
pub const EXITED_BEFORE_READY_DETAIL: &str = "plugin exited before becoming ready";

/// A typed start failure reported by a plugin (or synthesized from a
/// bare process exit by the runner). The consumer maps this to a retry
/// decision — `BindConflict` is the only retryable class.
#[derive(Debug, Clone)]
pub enum StartError {
    /// The plugin could not bind its listener. `errno` is the raw OS
    /// error (locale-proof) where the plugin could type it; 0 if unknown.
    BindConflict { errno: i32, addr: SocketAddr },
    /// Any terminal start failure the reporter can already name (config
    /// error, upstream-dial failure, bare process exit). Never retried.
    Fatal { detail: String, errno: Option<i32> },
    /// A plugin's readiness sender dropped unsent before ever reporting
    /// `ready` or a specific `Fatal` — synthesized locally
    /// (`ChainRunner`'s readiness aggregator, `TapPlugin`'s inner-exit
    /// race) when the cause is not known at the point this is raised.
    ///
    /// Deliberately distinct from `Fatal`, not just a `Fatal` with
    /// [`EXITED_BEFORE_READY_DETAIL`] text: `SitrepEvent` has no wire
    /// counterpart for this variant, so a `StartError` reconstructed FROM
    /// a parsed sitrep event can only ever be `BindConflict`/`Fatal`, never
    /// this. A caller holding the plugin's own driving task (e.g. bridge's
    /// `spawn_plugin_runner_at`) can therefore match on the variant — not
    /// compare `detail` text — to tell "no reason was ever given, go look"
    /// from a genuine plugin-reported `Fatal` apart, even one forwarded
    /// verbatim by a nested garter whose own placeholder text happens to
    /// read the same.
    ExitedBeforeReady,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::BindConflict { errno, addr } => {
                write!(f, "bind conflict on {addr} (errno {errno})")
            }
            StartError::Fatal { detail, .. } => write!(f, "{detail}"),
            StartError::ExitedBeforeReady => write!(f, "{EXITED_BEFORE_READY_DETAIL}"),
        }
    }
}

/// Recover a specific exit reason from `joined` — the outcome of joining a
/// plugin-driving task (a `ChainRunner::run` future, or equivalent) — for
/// the case where the ready-gate signal itself carried no diagnosis (a bare
/// [`StartError::ExitedBeforeReady`], or the ready channel dropping unsent
/// before anything was reported).
///
/// `Ok(Err(e))` (the task's own `run()` call returned a specific error)
/// yields that error's `Display` text. `Ok(Ok(()))` (a clean exit — e.g.
/// shutdown raced the readiness report) and `Err(_)` (the task panicked or
/// was cancelled while being joined) both fall back to
/// [`EXITED_BEFORE_READY_DETAIL`]; the panic/cancel case is also logged at
/// `error!`, since it signals a bug rather than routine diagnostic noise.
///
/// Shared by every caller that joins a plugin-driving task for this exact
/// gap — bridge's `spawn_plugin_runner_at`, galoshes' `main`, and
/// plugin-e2e's `run_roundtrip` all reach the identical three-way match;
/// this is the single implementation.
pub fn recover_exit_detail_from_joined(joined: &Result<crate::Result<()>, tokio::task::JoinError>) -> String {
    match joined {
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(())) => EXITED_BEFORE_READY_DETAIL.into(),
        Err(join_err) => {
            tracing::error!(error = %join_err, "plugin-driving task ended abnormally while recovering exit detail");
            EXITED_BEFORE_READY_DETAIL.into()
        }
    }
}

/// A parsed sitrep control event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SitrepEvent {
    Hello {
        protocol: String,
    },
    Ready {
        listen: SocketAddr,
        #[serde(with = "transports_serde")]
        transports: Transports,
    },
    BindConflict {
        errno: i32,
        addr: SocketAddr,
    },
    Fatal {
        detail: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        errno: Option<i32>,
    },
}

/// Whether this consumer can speak a plugin's advertised protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    Supported,
    FallBackToTier2,
}

/// Parse one stdout line.
///
/// - `Ok(Some(event))` — a recognized sitrep event.
/// - `Ok(None)` — a log line (non-JSON), a JSON object without a known
///   `event` (unknown event = ignored, forward-compat), or a JSON object
///   that isn't a sitrep envelope. Callers treat this as log passthrough.
///   Note: a `{`-prefixed line whose `event` matches a known variant but
///   contains a malformed field (e.g. an unparseable `listen` address) is
///   also swallowed to `Ok(None)` — the reserved `Err` arm is where a
///   future strict mode would surface it.
/// - `Err(_)` — reserved; currently never returned (unknown events are
///   ignored, not errors). Kept in the signature so a future strict mode
///   can surface malformed envelopes without an API break.
pub fn parse_event(line: &str) -> Result<Option<SitrepEvent>, serde_json::Error> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return Ok(None); // not JSON → log line
    }
    // Untagged-tolerant: an unknown `event` (or no `event`) deserializes
    // to None rather than erroring, so newer plugins / non-sitrep JSON
    // never break an older consumer.
    match serde_json::from_str::<SitrepEvent>(trimmed) {
        Ok(ev) => Ok(Some(ev)),
        Err(_) => Ok(None),
    }
}

/// A tier-1 capability check: true iff `line` is a `hello` handshake whose
/// protocol is `sitrep-*`.
pub fn is_hello_handshake(line: &str) -> bool {
    matches!(parse_event(line), Ok(Some(SitrepEvent::Hello { protocol })) if protocol.starts_with("sitrep-"))
}

/// Gate a plugin's advertised `protocol` string against what we speak.
/// Compatibility is on MAJOR only; an unknown major (or malformed
/// string) degrades gracefully to the tier-2 probe path.
pub fn protocol_support(protocol: &str) -> ProtocolSupport {
    let ours = SITREP_PROTOCOL
        .strip_prefix("sitrep-")
        .and_then(|s| semver::Version::parse(s).ok());
    let theirs = protocol
        .strip_prefix("sitrep-")
        .and_then(|s| semver::Version::parse(s).ok());
    match (ours, theirs) {
        (Some(o), Some(t)) if o.major == t.major => ProtocolSupport::Supported,
        _ => ProtocolSupport::FallBackToTier2,
    }
}

mod transports_serde {
    use super::Transports;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Transports, s: S) -> Result<S::Ok, S::Error> {
        let mut v = Vec::new();
        if t.contains(Transports::TCP) {
            v.push("tcp");
        }
        if t.contains(Transports::UDP) {
            v.push("udp");
        }
        s.collect_seq(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Transports, D::Error> {
        let names: Vec<String> = Vec::deserialize(d)?;
        let mut t = Transports::empty();
        for n in names {
            match n.as_str() {
                "tcp" => t |= Transports::TCP,
                "udp" => t |= Transports::UDP,
                _ => {} // unknown transport name ignored (forward-compat)
            }
        }
        Ok(t)
    }
}
