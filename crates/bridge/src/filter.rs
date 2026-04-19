//! Filter engine — compiles user filter rules and decides per-connection
//! actions. The engine is pure (no I/O, no async), iterating rules in
//! reverse order with last-match-wins (gitignore) semantics.
//!
//! Module exposes the data types ([`ConnInfo`], [`Decision`], [`RuleSet`])
//! and the decision function [`decide`]. The runtime dispatcher lives in
//! [`crate::hole_router`]: for TCP it peeks the first ≤ 2 KiB of payload
//! via [`sniffer::peek`] to recover TLS SNI / HTTP Host before calling
//! `decide`; for UDP the dispatcher matches on IP only.

pub mod engine;
pub mod matcher;
pub mod rules;
pub mod sniffer;

pub use engine::{decide, ConnInfo, Decision, L4Proto};
pub use matcher::Matcher;
pub use rules::{CompiledRule, RuleSet};
pub use sniffer::peek;

#[cfg(test)]
#[path = "filter_tests.rs"]
mod filter_tests;
