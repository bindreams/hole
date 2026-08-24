//! Process-global redaction registry and the byte-level redactor that
//! consumes it.
//!
//! Callers [`arm`] a *token* (an opaque stand-in such as
//! `<server:8f2a1c04>`) against the literal strings that must never reach a
//! log file. Everything written through a [`RedactingWriter`] — or passed
//! through [`redact_bytes`] / [`redact_str`] — then has those literals
//! replaced by their token.
//!
//! The registry exists because the set of code that can write a sensitive
//! literal is not enumerable: a process logs at `info` by default, so any
//! dependency, any child process whose stderr is relayed, and any OS command
//! whose argv is logged can emit one. Per-site redaction covers only sites
//! someone thought of; this covers bytes.
//!
//! Reads are lock-free (`arc_swap::ArcSwap` over an immutable snapshot), so
//! no logging call can block or deadlock behind a concurrent [`arm`].

use std::borrow::Cow;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use arc_swap::ArcSwap;

/// Literal strings this process emits into its own logs for its own
/// reasons. Arming a literal that is a substring of one of these mangles
/// ordinary diagnostics — `server: "hole"` would rewrite `hole-tun`,
/// `hole_bridge::proxy_manager` and the log directory path throughout the
/// file, which reads as a broken logger rather than as redaction.
///
/// The corpus drives a *warning* only. A colliding literal is still armed:
/// privacy does not yield to legibility. That asymmetry is what makes an
/// enumerated list safe here — an incomplete corpus can weaken a diagnostic
/// message and can never weaken redaction.
const COLLISION_CORPUS: &[&str] = &[
    // `tracing` target prefixes.
    "hole",
    "hole_bridge",
    "hole_common",
    "tun_engine",
    "garter",
    "galoshes",
    // The TUN device name.
    "hole-tun",
    // Plugin binary names.
    "ex-ray",
    "v2ray-plugin",
    // Default installed-service log directories.
    r"C:\ProgramData\hole\logs",
    "/var/log/hole",
];

/// One armed literal and the token that replaces it.
struct Entry {
    /// ASCII-lowercased `literal`. Matching is ASCII-case-insensitive, so
    /// two case-variants of one literal match exactly the same text and are
    /// the same registry key — keeping them apart would let one endpoint
    /// wear two unlinked tokens, which is what last-wins exists to prevent.
    key: String,
    literal: String,
    token: String,
}

/// Immutable registry snapshot. `automaton`'s pattern ids index `entries`.
struct Snapshot {
    entries: Vec<Entry>,
    /// `None` for the empty registry, which is distinguished so
    /// [`redact_bytes`] can return its input untouched rather than
    /// re-encoding it.
    automaton: Option<AhoCorasick>,
}

impl Snapshot {
    fn empty() -> Self {
        Self {
            entries: Vec::new(),
            automaton: None,
        }
    }

    fn build(entries: Vec<Entry>) -> Self {
        if entries.is_empty() {
            return Self::empty();
        }
        // `LeftmostLongest`, not the default `Standard` (earliest-ending
        // match): with `10.0.0.1` and `10.0.0.12` both armed, the default
        // redacts `10.0.0.12` to `<token-for-10.0.0.1>2`, leaking the
        // trailing byte AND attributing the line to the wrong entry.
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(entries.iter().map(|e| e.literal.as_str()))
            .expect("aho-corasick build has no size limits configured");
        Self {
            entries,
            automaton: Some(automaton),
        }
    }
}

fn registry() -> &'static ArcSwap<Snapshot> {
    static REGISTRY: OnceLock<ArcSwap<Snapshot>> = OnceLock::new();
    REGISTRY.get_or_init(|| ArcSwap::from_pointee(Snapshot::empty()))
}

/// Arm `literals` so every later write replaces them with `token`.
///
/// Keyed by literal, **last wins**: re-arming a literal already present
/// re-points it at the new token in place and never adds a pattern, so the
/// automaton is bounded by the number of distinct literals however many
/// times a long-running service arms. Last-wins is load-bearing — the
/// crash-recovery path arms a server IP under `<server:recovered>` before
/// any config exists, and the following connect must be able to re-point
/// that literal at the real entry's token. A replacement emits one `info!`
/// naming both tokens, which is what joins the pre-connect lines to the
/// session lines for a reader of the collected bundle.
///
/// Empty and whitespace-only literals are skipped. An empty pattern is a
/// zero-width match that wins at every position: measured, arming
/// `["", "1.2.3.4"]` shreds every character of the output with tokens *and*
/// leaves `1.2.3.4` in the clear.
///
/// Minting a token is the caller's job; this crate knows nothing about
/// server entries.
pub fn arm(token: &str, literals: impl IntoIterator<Item = String>) {
    let accepted: Vec<String> = literals.into_iter().filter(|l| !l.trim().is_empty()).collect();
    if accepted.is_empty() {
        return;
    }

    // Recorded inside the CAS loop and logged after it: `rcu` re-runs its
    // closure on contention, and logging from inside would double-announce.
    let mut superseded: Vec<String> = Vec::new();
    registry().rcu(|current| {
        superseded.clear();
        let mut entries: Vec<Entry> = current
            .entries
            .iter()
            .map(|e| Entry {
                key: e.key.clone(),
                literal: e.literal.clone(),
                token: e.token.clone(),
            })
            .collect();
        for literal in &accepted {
            let key = literal.to_ascii_lowercase();
            match entries.iter_mut().find(|e| e.key == key) {
                Some(existing) => {
                    if existing.token != token {
                        superseded.push(std::mem::replace(&mut existing.token, token.to_string()));
                    }
                    existing.literal.clone_from(literal);
                }
                None => entries.push(Entry {
                    key,
                    literal: literal.clone(),
                    token: token.to_string(),
                }),
            }
        }
        Arc::new(Snapshot::build(entries))
    });

    // After arming, so the literal named inside a collision warning is itself
    // covered by the redactor on the way to the file.
    for literal in &accepted {
        if let Some(collision) = vocabulary_collision(literal) {
            tracing::warn!(
                target: "hole::redact",
                token = %token,
                collision = %collision,
                "a redacted literal is part of Hole's own log vocabulary; that vocabulary will read as the token from here on"
            );
        }
    }
    for old in superseded {
        tracing::info!(target: "hole::redact", "redaction: {old} and {token} are the same endpoint");
    }
}

/// The one token minted without a server entry in hand: the crash-recovery
/// sweep replays a prior run's routes before any config exists. Last-wins
/// arming re-points those literals at the real entry's token on the
/// following connect, and announces the join.
pub const RECOVERED_TOKEN: &str = "<server:recovered>";

/// Arm both textual forms a resolved address takes in a log — bare, and the
/// bracketed `[…]` form a `host:port` join uses for IPv6.
pub fn arm_ip(token: &str, ip: IpAddr) {
    if !ip_is_armable(ip) {
        return;
    }
    arm(token, [ip.to_string(), format!("[{ip}]")]);
}

/// Whether an address may be armed at all.
///
/// Loopback and the unspecified address are excluded: they are not the
/// server, they are Hole's own listeners, the DNS forwarder, the plugin
/// handoff and the `localaddr=` of a firewall dump. Arming either turns
/// every one of those mentions into a token and destroys the log.
pub fn ip_is_armable(ip: IpAddr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified()
}

/// The first [`COLLISION_CORPUS`] entry `literal` would mangle, if any.
///
/// The test is "`literal` is an ASCII-case-insensitive substring of a corpus
/// entry" — that is the direction in which arming damages Hole's own words.
/// The converse (a corpus entry inside a longer literal) is not a collision:
/// `myhole.example.invalid` redacts only itself and leaves `hole-tun` alone.
fn vocabulary_collision(literal: &str) -> Option<&'static str> {
    let needle = literal.to_ascii_lowercase();
    COLLISION_CORPUS
        .iter()
        .copied()
        .find(|entry| entry.to_ascii_lowercase().contains(&needle))
}

/// Number of distinct literals currently armed. Diagnostic; the registry is
/// otherwise opaque.
pub fn armed_literal_count() -> usize {
    registry().load().entries.len()
}

/// Replace every armed literal in `input` with its token.
///
/// Returns `Cow::Borrowed` — byte-identical, not re-encoded — when nothing
/// matched or the registry is empty.
pub fn redact_bytes(input: &[u8]) -> Cow<'_, [u8]> {
    let snapshot = registry().load();
    let Some(automaton) = snapshot.automaton.as_ref() else {
        return Cow::Borrowed(input);
    };
    let mut out: Option<Vec<u8>> = None;
    let mut cursor = 0usize;
    for m in automaton.find_iter(input) {
        let buf = out.get_or_insert_with(|| Vec::with_capacity(input.len()));
        buf.extend_from_slice(&input[cursor..m.start()]);
        buf.extend_from_slice(snapshot.entries[m.pattern().as_usize()].token.as_bytes());
        cursor = m.end();
    }
    match out {
        Some(mut buf) => {
            buf.extend_from_slice(&input[cursor..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(input),
    }
}

/// [`redact_bytes`] for text. Same guarantees.
pub fn redact_str(input: &str) -> Cow<'_, str> {
    match redact_bytes(input.as_bytes()) {
        Cow::Borrowed(_) => Cow::Borrowed(input),
        // Both haystack and tokens are valid UTF-8 and an armed literal can
        // only match on a character boundary, so this decodes. `lossy` is the
        // never-panic floor rather than a path with a known trigger.
        Cow::Owned(bytes) => {
            Cow::Owned(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
        }
    }
}

/// An `io::Write` that redacts on the way through.
///
/// Wrap the writer *under* a log sink so every formatted event passes
/// through, whoever authored it.
#[derive(Clone, Debug)]
pub struct RedactingWriter<W> {
    inner: W,
}

impl<W: io::Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Unwrap the wrapped writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    /// Returns the count of **input** bytes consumed, never of output bytes
    /// emitted. Redaction changes length, and reporting the output count
    /// would make [`io::Write::write_all`]'s default loop slice `&buf[n..]`
    /// out of range and panic — on `tracing_appender`'s worker thread,
    /// silently ending all file logging.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_all(&redact_bytes(buf))?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(&redact_bytes(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod redact_tests;
