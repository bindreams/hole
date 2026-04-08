//! Filter decision loop. Reverse-iterates a `RuleSet` and returns the
//! action of the first matching rule (gitignore semantics: the rule that
//! appears later in the user's list wins). If no rule matches, the
//! terminal fallback is `Proxy` — this matches the bridge's
//! "everything is proxied by default" contract.

use std::net::IpAddr;

use hole_common::config::FilterAction;

use super::rules::RuleSet;

/// Layer-4 protocol of a connection. Filter rules apply to both
/// uniformly today, but downstream code (Plans 2/3) may branch on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// Snapshot of the connection-level info the filter engine sees. The
/// dispatcher fills this in immediately before calling `decide`.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// Set when the dispatcher recovered a domain via fake DNS reverse
    /// lookup or the TLS/HTTP sniffer. `None` for raw IP destinations.
    pub domain: Option<String>,
    pub proto: L4Proto,
}

/// Run the filter engine for one connection. O(n) in the rule count;
/// pure function.
pub fn decide(rules: &RuleSet, conn: &ConnInfo) -> FilterAction {
    for rule in rules.rules.iter().rev() {
        if rule.matcher.matches(conn) {
            return rule.action;
        }
    }
    // Terminal fallback: never reached when the UI's locked default
    // rules are present, but preserves "proxy everything" if a
    // hand-edited config strips them out.
    FilterAction::Proxy
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;
