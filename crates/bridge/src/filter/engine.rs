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
    ///
    /// The matcher canonicalizes this value internally on every match
    /// (case-fold + trailing dot strip + IDNA), so callers may pass
    /// the raw string from the sniffer or fake DNS without
    /// pre-normalizing. The dispatcher in Plans 2/3 may still want to
    /// canonicalize once via [`super::matcher::canonicalize_for_match`]
    /// to amortize the cost across rules.
    pub domain: Option<String>,
    pub proto: L4Proto,
}

/// Result of a filter engine decision: the action to take and the index
/// of the rule that matched (if any). The rule index is the position in
/// the original user-supplied rule list. `None` means the terminal
/// fallback fired (no rule matched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: FilterAction,
    pub rule_index: Option<usize>,
}

/// Run the filter engine for one connection. O(n) in the rule count;
/// pure function.
pub fn decide(rules: &RuleSet, conn: &ConnInfo) -> Decision {
    for (i, rule) in rules.rules.iter().enumerate().rev() {
        if rule.matcher.matches(conn) {
            return Decision {
                action: rule.action,
                rule_index: Some(i),
            };
        }
    }
    // Terminal fallback: never reached when the UI's locked default
    // rules are present, but preserves "proxy everything" if a
    // hand-edited config strips them out.
    Decision {
        action: FilterAction::Proxy,
        rule_index: None,
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;
