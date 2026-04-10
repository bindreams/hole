//! Filter engine — compiles user filter rules and decides per-connection
//! actions. The engine is pure (no I/O, no async), iterating rules in
//! reverse order with last-match-wins (gitignore) semantics.
//!
//! This crate exposes the data types and decision function. The dispatcher
//! that drives them at runtime is added in Plan 2 (TCP) and Plan 3 (UDP).

pub mod engine;
pub mod fake_dns;
pub mod matcher;
pub mod rules;
pub mod sniffer;

pub use engine::{decide, ConnInfo, L4Proto};
pub use fake_dns::{AllocateError, FakeDns, DEFAULT_POOL_V4, DEFAULT_POOL_V6, FAKE_DNS_TTL};
pub use matcher::Matcher;
pub use rules::{CompiledRule, RuleSet};
pub use sniffer::peek;

#[cfg(test)]
#[path = "filter_tests.rs"]
mod filter_tests;
