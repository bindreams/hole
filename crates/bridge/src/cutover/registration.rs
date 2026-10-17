//! Memory an asynchronous callback may still name.
//!
//! `NotifyServiceStatusChangeW` keeps the notify buffer until its APC has run,
//! and closing the service handle recalls only an APC the SCM has not queued
//! yet. Memory an APC can still name therefore outlives its owner unless the
//! callback is known to have run, and only the value can know that.

use std::ptr::NonNull;

/// A value some other party may still read after its owner is gone.
pub trait Settle {
    /// Whether nothing can reach this value any more.
    fn is_settled(&self) -> bool;
}

/// Heap-pinned owner of a [`Settle`] value whose address was handed out.
///
/// Dropping it frees the value only if it is settled at that moment; otherwise
/// the value is leaked, for good. A leak is bounded by the registrations dropped
/// unsettled, one per drop; a freed value that is still named is a use-after-free.
/// There is no way to free an unsettled value, so no call site can choose to.
pub struct Registration<T: Settle> {
    ptr: NonNull<T>,
}

impl<T: Settle> Registration<T> {
    pub fn new(value: T) -> Self {
        Self {
            ptr: NonNull::from(Box::leak(Box::new(value))),
        }
    }

    pub fn get(&self) -> &T {
        // SAFETY: `ptr` came from a leaked `Box` that only `Drop` reclaims, and
        // `Drop` reclaims it only when settled.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Settle> Drop for Registration<T> {
    fn drop(&mut self) {
        if self.get().is_settled() {
            // SAFETY: `ptr` is the leaked `Box` from `new`, reclaimed at most once,
            // and settled means nothing else can reach it.
            drop(unsafe { Box::from_raw(self.ptr.as_ptr()) });
        }
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod registration_tests;
