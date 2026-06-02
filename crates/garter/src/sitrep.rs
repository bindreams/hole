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
    /// Reported on `ready`; retires the static `udp_supported` flag.
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

/// A typed start failure reported by a plugin (or synthesized from a
/// bare process exit by the runner). The consumer maps this to a retry
/// decision — `BindConflict` is the only retryable class.
#[derive(Debug, Clone)]
pub enum StartError {
    /// The plugin could not bind its listener. `errno` is the raw OS
    /// error (locale-proof) where the plugin could type it; 0 if unknown.
    BindConflict { errno: i32, addr: SocketAddr },
    /// Any terminal start failure (config error, upstream-dial failure,
    /// bare process exit). Never retried.
    Fatal { detail: String, errno: Option<i32> },
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::BindConflict { errno, addr } => {
                write!(f, "bind conflict on {addr} (errno {errno})")
            }
            StartError::Fatal { detail, .. } => write!(f, "{detail}"),
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
