//! Arming the redaction registry from a [`crate::config::ServerEntry`], and the
//! classification fields that replace the address in a log line.
//!
//! [`util::redact`] knows nothing about server entries; this is the layer
//! that mints a token, derives the textual forms an address can take, and
//! decides which of them are safe to arm.

use std::net::IpAddr;

use crate::config::ServerEntry;

// The classifiers live beside `arm_ip` in `util` because `tun-engine`'s
// crash-recovery path needs them and cannot reach `hole-common`.
pub use util::redact::{ip_family, ip_scope};

/// Token for the crash-recovery path, which replays a prior run's routes
/// before any config exists and so has no entry in hand. Last-wins arming
/// re-points the literal at the real entry token on the following connect,
/// and announces the join.
pub const RECOVERED_TOKEN: &str = "<server:recovered>";

/// The opaque stand-in for one entry's address: `<server:8f2a1c04>`.
///
/// Derived from the entry's random v4 UUID, never from the address. For a
/// non-UUID id (`ServerEntry::default_placeholder`, test fixtures) the hex
/// characters of the id are used in order and right-padded, so the token is
/// always the same shape and the function is total.
pub fn token_for(entry_id: &str) -> String {
    let mut hex: String = entry_id
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(TOKEN_HEX_LEN)
        .collect::<String>()
        .to_ascii_lowercase();
    while hex.len() < TOKEN_HEX_LEN {
        hex.push('0');
    }
    format!("<server:{hex}>")
}

/// Width of a token's hex body. `<server:recovered>` is the one fixed
/// exception to the shape.
const TOKEN_HEX_LEN: usize = 8;

/// Arm every textual form of `entry`'s configured address.
///
/// Never panics on user input: nothing upstream validates the host, so the
/// value is arbitrary text. A candidate that cannot be derived is dropped;
/// the others are still armed.
pub fn arm_server(entry: &ServerEntry) {
    let configured = entry.server.expose();
    let mut candidates = vec![configured.to_string()];
    if let Some(stripped) = configured.strip_suffix('.') {
        candidates.push(stripped.to_string());
    }
    // `Err` is reachable from an imported config and is discarded: that one
    // candidate is dropped, the rest are still armed, and nothing panics.
    if let Ok(a_label) = idna::domain_to_ascii(configured) {
        candidates.push(a_label);
    }
    if let Ok(ip) = unbracket(configured).parse::<IpAddr>() {
        candidates.push(ip.to_string());
    }
    arm_candidates(&token_for(&entry.id), candidates);
}

/// Arm **every** entry, not only the selected one: any of them can reach a
/// log (the auto-test loop walks the whole list), and the support-bundle
/// collector scrubs with this same registry.
pub fn arm_config(config: &crate::config::AppConfig) {
    for entry in &config.servers {
        arm_server(entry);
    }
}

/// Arm the DoH-resolved address for `entry_id`, in both the bare and the
/// bracketed form `handoff_host` hands to the plugin chain.
pub fn arm_resolved_ip(entry_id: &str, ip: IpAddr) {
    util::redact::arm_ip(&token_for(entry_id), ip);
}

fn arm_candidates(token: &str, candidates: impl IntoIterator<Item = String>) {
    util::redact::arm(token, candidates.into_iter().filter(|c| may_arm(c)));
}

/// Shape of a configured address: `"domain"`, `"ipv4"` or `"ipv6"`.
pub fn server_kind(configured: &str) -> &'static str {
    match unbracket(configured).parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => "ipv4",
        Ok(IpAddr::V6(_)) => "ipv6",
        Err(_) => "domain",
    }
}

/// Strip one surrounding `[`/`]` pair, as in `handoff_host`'s IPv6 form.
fn unbracket(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value)
}

/// Whether one derived candidate may be armed.
///
/// Applied **per candidate**, not once to the configured value — that is the
/// whole point. `server = "127.0.0.1."` does not parse as an `IpAddr`, so a
/// value-level carve-out lets it through, and the trailing-dot strip then
/// arms the bare `127.0.0.1`: every loopback mention in the process (both
/// listeners, the DNS forwarder, `netsh wfp show filters
/// localaddr=127.0.0.1`, the plugin handoff) becomes a token.
fn may_arm(candidate: &str) -> bool {
    if candidate.trim().is_empty() {
        return false;
    }
    if candidate.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match unbracket(candidate).parse::<IpAddr>() {
        Ok(ip) => util::redact::ip_is_armable(ip),
        // Case folding is the automaton's job, so no lowercased variant is
        // derived here.
        Err(_) => true,
    }
}

#[cfg(test)]
#[path = "redact_arm_tests.rs"]
mod redact_arm_tests;
