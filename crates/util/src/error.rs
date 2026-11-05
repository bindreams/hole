//! Walks over an error's causes, and predicates over them.
//!
//! Two walks, because `io::Error` hides its payload from `source()`: it
//! delegates to the payload's own `source()`, so `io::Error::other(typed)`
//! skips `typed` itself.
//!
//! The walks reach only what each error exposes through `source()` (and, for
//! [`links`], an `io::Error`'s payload). An inner error a type does not expose
//! is invisible to both walks, and so to [`find`] and [`raw_os_error`], which
//! are predicates over [`links`].

use std::io;

/// `e`, then each error reachable by `source()`, outermost first.
pub fn chain<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> + 'a {
    std::iter::successors(Some(e), |link| link.source())
}

/// Every cause of `e` once, outermost first: an `io::Error` is followed by its
/// payload ([`io::Error::get_ref`]), any other error by its `source()`.
pub fn links<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> + 'a {
    std::iter::successors(Some(e), |link| match link.downcast_ref::<io::Error>() {
        Some(io_error) => io_error
            .get_ref()
            .map(|payload| payload as &(dyn std::error::Error + 'static)),
        None => link.source(),
    })
}

/// The outermost link of [`links`] that is a `T`.
pub fn find<'a, T: std::error::Error + 'static>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a T> {
    links(e).find_map(|link| link.downcast_ref::<T>())
}

/// The OS error code of the first `io::Error` in [`links`] that has one. A
/// reader of a code must use this, not [`io::Error::raw_os_error`], on an
/// error that can have been wrapped.
pub fn raw_os_error(e: &(dyn std::error::Error + 'static)) -> Option<i32> {
    links(e).find_map(|link| link.downcast_ref::<io::Error>()?.raw_os_error())
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
