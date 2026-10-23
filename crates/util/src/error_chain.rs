//! Render an error with every cause in its `source()` chain.
//!
//! An error's `Display` is often a user-facing sentence (a toast) that leaves
//! its cause to the log; this is what puts the cause there.

use std::fmt;

/// `Display` adapter over an error and its `source()` chain, joined with ` -> `
/// from the outermost error to the root cause. A cause whose text its parent's
/// text already contains (`#[error("...: {0}")]` over a `#[source]`) is not
/// repeated.
pub struct ErrorChain<'a>(&'a (dyn std::error::Error + 'static));

/// Wrap `e` for a log field: `error = %error_chain(&e)`.
pub fn error_chain<'a>(e: &'a (dyn std::error::Error + 'static)) -> ErrorChain<'a> {
    ErrorChain(e)
}

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parent_text = self.0.to_string();
        f.write_str(&parent_text)?;
        let mut current = self.0.source();
        while let Some(cause) = current {
            let text = cause.to_string();
            if !parent_text.contains(&text) {
                write!(f, " -> {text}")?;
            }
            parent_text = text;
            current = cause.source();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "error_chain_tests.rs"]
mod error_chain_tests;
