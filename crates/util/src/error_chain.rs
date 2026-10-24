//! Render an error with every cause in its `source()` chain.
//!
//! An error's `Display` is often a user-facing sentence (a toast) that leaves
//! its cause to the log; this is what puts the cause there.

use std::fmt;
use std::io;

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

/// The OS error code of `e`, or of the `io::Error` found in its `source()`
/// chain when `e` has none itself (an `io::Error` that wraps a description of
/// a failed OS call). A reader of a code must use this, not
/// [`io::Error::raw_os_error`], on an error that can have been wrapped.
pub fn raw_os_error(e: &io::Error) -> Option<i32> {
    if let Some(code) = e.raw_os_error() {
        return Some(code);
    }
    // `io::Error::source` skips the wrapped error, so descend through `get_ref`.
    let mut current: Option<&(dyn std::error::Error + 'static)> = e.get_ref().map(|inner| inner as _);
    while let Some(err) = current {
        if let Some(inner) = err.downcast_ref::<io::Error>() {
            return raw_os_error(inner);
        }
        current = err.source();
    }
    None
}
