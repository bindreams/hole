//! Filter decision loop. Reverse-iterates a `RuleSet` and returns the
//! action of the first matching rule (gitignore semantics: the rule that
//! appears later in the user's list wins). If no rule matches, the
//! terminal fallback is `Proxy` — this matches the bridge's
//! "everything is proxied by default" contract.

use std::net::SocketAddr;

use hole_common::config::FilterAction;

use super::rules::{CompiledRule, RuleSet};

/// Layer-4 protocol of a connection. The dispatcher branches on this:
/// TCP flows are peeked for a domain, UDP flows are matched on IP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// Snapshot of the connection-level info the filter engine sees. The
/// dispatcher fills this in immediately before calling `decide`.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub dst: SocketAddr,
    /// Set when the dispatcher recovered a domain via the TLS/HTTP
    /// sniffer. `None` for raw IP destinations, non-peekable flows, and
    /// all UDP flows (no UDP peek path today).
    ///
    /// The matcher canonicalizes this value internally on every match
    /// (case-fold + trailing dot strip + IDNA), so callers may pass the
    /// raw string from the sniffer without pre-normalizing.
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

/// Reverse-scan the ruleset and return the action of the first rule for which
/// `pred` holds (gitignore last-match-wins), reporting that rule's *original*
/// user index. The terminal fallback is `Proxy` with no index. Both `decide`
/// and `decide_test` go through here so the two surfaces cannot drift.
fn first_match(rules: &RuleSet, pred: impl Fn(&CompiledRule) -> bool) -> Decision {
    for rule in rules.rules.iter().rev() {
        if pred(rule) {
            return Decision {
                action: rule.action,
                rule_index: Some(rule.original_index),
            };
        }
    }
    // Terminal fallback: preserves "proxy everything" if a hand-edited
    // config lacks the UI's default rules.
    Decision {
        action: FilterAction::Proxy,
        rule_index: None,
    }
}

/// Run the filter engine for one connection. O(n) in the rule count;
/// pure function.
pub fn decide(rules: &RuleSet, conn: &ConnInfo) -> Decision {
    first_match(rules, |rule| rule.matcher.matches(conn))
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;
