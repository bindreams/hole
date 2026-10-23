//! Render an error with every cause in its `source()` chain.
//!
//! An error's `Display` is often a user-facing sentence (a toast) that leaves
//! its cause to the log; this is what puts the cause there.

use std::fmt;

/// `Display` adapter over an error and its `source()` chain, joined with ` -> `
/// from the outermost error to the root cause. Every link is printed as is: a
/// type that both embeds its source in its own text and returns it from
/// `source()` shows that cause twice.
pub struct ErrorChain<'a>(&'a (dyn std::error::Error + 'static));

/// Wrap `e` for a log field: `error = %error_chain(&e)`.
pub fn error_chain<'a>(e: &'a (dyn std::error::Error + 'static)) -> ErrorChain<'a> {
    ErrorChain(e)
}

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut current = self.0.source();
        while let Some(cause) = current {
            write!(f, " -> {cause}")?;
            current = cause.source();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "error_chain_tests.rs"]
mod error_chain_tests;
