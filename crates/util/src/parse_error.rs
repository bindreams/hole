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

/// Category and position of a `serde_json` parse failure, never a fragment of
/// the input.
///
/// The one door for reporting a parse failure to a user, a toast, or a log.
pub fn describe_parse_error(e: &serde_json::Error) -> String {
    format!("{} (line {}, column {})", parse_kind(e), e.line(), e.column())
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
