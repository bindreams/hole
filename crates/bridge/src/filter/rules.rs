//! `RuleSet` — the compiled form of a `Vec<FilterRule>`. Compilation is
//! infallible: invalid rules are dropped and recorded in `dropped`, the
//! rest are kept. The bridge surfaces the dropped list via the IPC
//! status response so the GUI can highlight problem rows.

use hole_common::config::{FilterAction, FilterRule};
use serde::{Deserialize, Serialize};

use super::matcher::Matcher;

/// A filter rule that failed to compile, recording its original index
/// and a human-readable reason. Moved to `hole_common::protocol` and
/// wired into the IPC status response in Plan 4 when the GUI needs it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvalidFilter {
    pub index: u32,
    pub error: String,
}

/// One compiled rule: matcher + action. Rules are stored in the same
/// order as the user's input so the reverse-scan in `engine::decide`
/// preserves gitignore semantics.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub matcher: Matcher,
    pub action: FilterAction,
}

/// A compiled ruleset, ready for the filter engine. Lifetime: created
/// once per `start`/`reload` and held by the dispatcher behind an
/// `ArcSwap` for lock-free reads.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Compiled rules in the user's original order.
    pub rules: Vec<CompiledRule>,
    /// Cached: true if any rule's matcher is a domain matcher. The
    /// dispatcher uses this to skip the sniffer/fake-DNS path entirely
    /// when only IP rules exist.
    pub has_domain_rules: bool,
    /// Rules that failed to compile, with their original index in the
    /// user's input and a human-readable reason.
    pub dropped: Vec<InvalidFilter>,
}

impl RuleSet {
    /// Compile a slice of `FilterRule`s into a `RuleSet`. Never fails:
    /// invalid rules go into `dropped`, the rest are kept.
    pub fn from_user_rules(rules: &[FilterRule]) -> Self {
        let mut compiled = Vec::with_capacity(rules.len());
        let mut dropped = Vec::new();

        for (i, rule) in rules.iter().enumerate() {
            // The wire schema uses u32 for the index. A user with
            // > 4 billion rules is implausible, but if they ever
            // existed we'd silently truncate — clamp explicitly.
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            match Matcher::compile(&rule.address, rule.matching) {
                Ok(matcher) => compiled.push(CompiledRule {
                    matcher,
                    action: rule.action,
                }),
                Err(err) => dropped.push(InvalidFilter {
                    index,
                    error: err.to_string(),
                }),
            }
        }

        let has_domain_rules = compiled.iter().any(|r| {
            matches!(
                r.matcher,
                Matcher::ExactDomain(_) | Matcher::SubdomainDomain(_) | Matcher::WildcardDomain(_)
            )
        });

        Self {
            rules: compiled,
            has_domain_rules,
            dropped,
        }
    }
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod rules_tests;
