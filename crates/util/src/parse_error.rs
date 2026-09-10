//! Content-safe description of a `serde_json` parse failure.
//!
//! `serde_json::Error`'s own `Display` quotes its input back — the offending
//! value for a data error, an arbitrary caller-supplied *string* for an
//! unknown variant or field — so `{e}` on a parse of anything secret-bearing
//! is a leak. Every JSON this workspace parses can hold one: the user's
//! config, an imported profile, the elevation payload, and the bridge's own
//! state files.
//!
//! Lives here, beside [`crate::redact`], rather than in `hole-common`,
//! because `tun-engine` parses secret-bearing state files too and does not
//! depend on `hole-common`. One implementation, so the classification cannot
//! drift between the crates that share the rule.

/// A `serde_json` parse failure, converted from the raw `serde_json::Error`
/// immediately at the parse site — category and position only, never a
/// source. Once a call site holds a `ParseFailure` instead of the raw error,
/// there is no live `serde_json::Error` left for a later edit to reach for
/// by accident (`{e}` on *this* type is safe by construction, not by
/// discipline): the leak-prone `Display` simply does not exist to be typoed
/// into.
///
/// Prefer converting at the parse site over calling [`describe_parse_error`]
/// at the log/error-construction site: a caller that instead binds the raw
/// `serde_json::Error` and calls `describe_parse_error(&e)` later still has
/// `e.to_string()` / `%e` one edit away from reopening the leak. Mirrors
/// `hole_common::config::ConfigError::Parse` /
/// `hole_common::import::ImportError::Parse`, which carry the same three
/// fields for the same reason.
#[derive(Debug, Clone, Copy)]
pub struct ParseFailure {
    kind: &'static str,
    line: usize,
    column: usize,
}

impl From<&serde_json::Error> for ParseFailure {
    fn from(e: &serde_json::Error) -> Self {
        Self {
            kind: parse_kind(e),
            line: e.line(),
            column: e.column(),
        }
    }
}

impl std::fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (line {}, column {})", self.kind, self.line, self.column)
    }
}

/// Category and position of a `serde_json` parse failure, never a fragment of
/// the input.
///
/// The one door for reporting a parse failure to a user, a toast, or a log.
pub fn describe_parse_error(e: &serde_json::Error) -> String {
    ParseFailure::from(e).to_string()
}

/// Content-safe label for a `serde_json` parse failure (never echoes the
/// input). Public alongside [`describe_parse_error`] so a caller that builds
/// its own error type can carry the same scalars as *fields* — dropping the
/// `serde_json::Error` entirely, which makes a `Debug` echo impossible too
/// (`hole_common::config::ConfigError::Parse`,
/// `hole_common::import::ImportError::Parse`).
pub fn parse_kind(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io => "I/O error",
        Category::Syntax => "syntax error",
        Category::Data => "data error",
        Category::Eof => "unexpected end of input",
    }
}

#[cfg(test)]
#[path = "parse_error_tests.rs"]
mod parse_error_tests;
