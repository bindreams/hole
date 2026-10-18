//! Memory an asynchronous callback may still name.
//!
//! `NotifyServiceStatusChangeW` keeps the notify buffer until its APC has run.
//! The docs promise only that no *further* APC is queued once the service handle
//! closes; they do not say an APC already queued is recalled, nor that a failed
//! call queued none, so both are assumed possible. Memory an APC can still name
//! therefore outlives its owner unless the callback is known to have run, and
//! only the value can know that.
//!
//! The leak is bounded by the callers, not here: each [`Registration`] that
//! drops unsettled costs one value, so the total is one per call that did not
//! settle, and unbounded only if a caller keeps making such calls without limit.

use std::ptr::NonNull;

/// A value some other party may still read after its owner is gone.
///
/// # Safety
///
/// `is_settled` may return `true` only once nothing can reach the value any
/// more, and must keep returning `true` after that: [`Registration`] frees the
/// value on the strength of it.
pub unsafe trait Settle {
    /// Whether nothing can reach this value any more.
    fn is_settled(&self) -> bool;
}

/// Heap-pinned owner of a [`Settle`] value whose address was handed out.
///
/// Dropping it frees the value only if it is settled at that moment; otherwise
/// the value is leaked. No call site can free an unsettled value.
pub struct Registration<T: Settle> {
    ptr: NonNull<T>,
}

impl<T: Settle> Registration<T> {
    #[cfg(test)]
    pub fn new(value: T) -> Self {
        Self::new_with(value, |_| {})
    }

    /// Boxes `value`, running `init` on it at its final address
    /// first. `init` is the one point at which the value is certainly
    /// unregistered: nothing else can name it until this returns.
    pub fn new_with(value: T, init: impl FnOnce(&T)) -> Self {
        let ptr = NonNull::from(Box::leak(Box::new(value)));
        // SAFETY: `ptr` is the box just leaked, freed only by `Drop`.
        init(unsafe { ptr.as_ref() });
        Self { ptr }
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
        } else {
            tracing::warn!(
                value = std::any::type_name::<T>(),
                "dropping an unsettled registration: its value is leaked, not freed"
            );
        }
    }
}

/// The registration of an owner's latest attempt to arm, and whether that
/// attempt's call is known to have succeeded.
///
/// Only a confirmed registration is something to wait on. An unconfirmed one
/// stays owned all the same: a call that failed may still have registered it.
pub enum Arming<T: Settle> {
    /// No attempt yet.
    Idle,
    /// The call has not succeeded (yet, or at all).
    Unconfirmed(Registration<T>),
    /// The call succeeded.
    Confirmed(Registration<T>),
}

impl<T: Settle> Arming<T> {
    /// Adopts the registration of a new attempt, unconfirmed; the one it
    /// replaces retires by [`Registration`]'s rule.
    pub fn begin(&mut self, registration: Registration<T>) {
        *self = Self::Unconfirmed(registration);
    }

    /// Records that the latest attempt's call succeeded.
    pub fn confirm(&mut self) {
        match std::mem::replace(self, Self::Idle) {
            Self::Unconfirmed(registration) => *self = Self::Confirmed(registration),
            // Already confirmed: nothing to change.
            Self::Confirmed(registration) => *self = Self::Confirmed(registration),
            Self::Idle => debug_assert!(false, "confirm without a begun attempt"),
        }
    }

    /// Withdraws the wait on a confirmed registration, which stays owned.
    pub fn unconfirm(&mut self) {
        match std::mem::replace(self, Self::Idle) {
            Self::Confirmed(registration) => *self = Self::Unconfirmed(registration),
            // Already unconfirmed: nothing to change.
            Self::Unconfirmed(registration) => *self = Self::Unconfirmed(registration),
            Self::Idle => {}
        }
    }

    /// The value to wait on: the latest attempt's, if its call succeeded.
    pub fn confirmed(&self) -> Option<&T> {
        match self {
            Self::Confirmed(registration) => Some(registration.get()),
            Self::Idle | Self::Unconfirmed(_) => None,
        }
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod registration_tests;
