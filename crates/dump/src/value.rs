//! The [`DumpValue`] data model.

use std::borrow::Cow;

/// A YAML-shaped value produced by [`crate::Dump::dump`] and consumed
/// by the formatter.
#[derive(Debug, Clone, PartialEq)]
pub enum DumpValue {
    /// YAML `null` / `~`.
    Null,
    Bool(bool),
    /// Signed integer up to `i128`. `UInt` exists separately so that
    /// the `i64::MAX..=u128::MAX` range round-trips losslessly.
    Int(i128),
    UInt(u128),
    /// NaN and ±infinity are emitted as `.nan` / `.inf` / `-.inf` per
    /// YAML 1.2.
    Float(f64),
    String(String),
    /// Arbitrary byte sequence, emitted as `!!binary` (base64).
    Bytes(Vec<u8>),
    Seq(Vec<DumpValue>),
    /// Keys may be any `DumpValue`, not just strings. Built-in impls
    /// for unordered collections sort their entries so output is
    /// byte-deterministic.
    Map(Vec<(DumpValue, DumpValue)>),
    /// Tagged node. Certain blessed tag names (see [`tag`]) trigger
    /// formatter behavior such as redaction or elision.
    Tagged(Cow<'static, str>, Box<DumpValue>),
}

impl DumpValue {
    /// Convenience constructor for a tagged node with a `'static` tag.
    pub fn tagged(tag: &'static str, value: DumpValue) -> Self {
        DumpValue::Tagged(Cow::Borrowed(tag), Box::new(value))
    }

    /// Convenience constructor for a tagged node with an owned tag.
    pub fn tagged_owned(tag: String, value: DumpValue) -> Self {
        DumpValue::Tagged(Cow::Owned(tag), Box::new(value))
    }
}

/// Blessed tag names that trigger specific formatter behavior.
///
/// Tags matching `^[a-z][a-z0-9_-]*$` are reserved for this crate.
/// User-defined tags should start with an uppercase ASCII letter or use
/// a `Namespace:name` form to avoid collisions.
pub mod tag {
    /// Formatter renders as `[REDACTED]` (unless redaction is disabled).
    pub const SECRET: &str = "secret";
    /// Inner value must be a `String` describing what was elided.
    pub const ELIDED: &str = "elided";
    /// Inner value must be a `Map` with entries `value`, `shown`, `total`.
    pub const TRUNCATED: &str = "truncated";
    /// Inner value must be a `String` from `format!("{:?}", x)`. Used by
    /// the Debug-fallback rung of the autoref ladder.
    pub const DEBUG: &str = "debug";
    /// Inner value must be a `String` describing a dump-impl failure.
    pub const ERROR: &str = "error";
}

#[cfg(test)]
#[path = "value_tests.rs"]
mod value_tests;
