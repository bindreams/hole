//! An OS thread whose exit can only be awaited under a failure bound.
//!
//! # Why this exists
//!
//! [`crate::diagnostics::etw::EtwGuard`] tears its ETW session down inside
//! `Drop`, on the Windows service's shutdown path. `Drop` cannot be async,
//! cannot report failure and cannot be cancelled, so a `JoinHandle::join`
//! there is an *invisible* unbounded wait: `run_service` reports no
//! `StopPending`, which makes a service hung in teardown indistinguishable
//! from a healthy `Running` one, and the SCM `Stop` never completes — the
//! shape that wedges the MSI uninstall's custom action (bindreams/hole#978).
//!
//! # Why there is no `join`
//!
//! A [`BoundedThread`] never hands out a `JoinHandle`; the handle is detached
//! at [`spawn`]. Waiting on one of these threads without a bound is therefore
//! not something a caller can express, by accident or otherwise.
//!
//! # Why the bound is sanctioned
//!
//! Every *intra-process* rendezvous here is a real primitive: the body signals
//! a channel on its way out, so [`BoundedThread::wait`] returns the instant the
//! body finishes and never elapses `bound` on the healthy path. `bound` covers
//! only the case where the body is parked in a call **the process does not
//! own** — for the ETW consumer, `ProcessTrace`, which returns when the kernel
//! acknowledges `ControlTraceW(EVENT_TRACE_CONTROL_STOP)` and hands back the
//! last real-time buffer. That acknowledgement genuinely might never arrive,
//! and `bound` is the failure bound surfaced to a human: CONTRIBUTING.md's
//! "external event with graceful failure bound" exception, not a
//! synchronise-by-time.

use std::io;
use std::sync::mpsc;
use std::time::Duration;

/// How a [`BoundedThread`]'s body ended, as observed by
/// [`BoundedThread::wait`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadExit {
    /// The body returned normally.
    Finished,
    /// The body unwound: it dropped its completion sender without signalling.
    /// `std`'s panic hook has already printed the payload — a detached thread
    /// has no `JoinHandle` to carry it — so this variant is the fact of the
    /// panic, not its contents.
    Panicked,
    /// The body had not finished within the bound. It is **abandoned, not
    /// killed**: it keeps running, unreaped, for whatever is left of the
    /// process's life.
    Abandoned,
}

/// A detached OS thread, plus the rendezvous its body signals on the way out.
pub(crate) struct BoundedThread {
    done: mpsc::Receiver<()>,
}

/// Spawn `body` on a named, detached OS thread.
///
/// Fails only if the OS refuses the thread; the caller decides what a missing
/// thread means, exactly as `std::thread::Builder::spawn` would let it.
pub(crate) fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<BoundedThread> {
    let (tx, done) = mpsc::channel();
    // The handle is dropped, not returned: see the module doc's "Why there is
    // no `join`".
    std::thread::Builder::new().name(name.to_owned()).spawn(move || {
        // `tx` is owned by this closure, so an unwind out of `body` drops it
        // without a send and `wait` reads `Disconnected` — the panic signal a
        // detached thread has no `JoinHandle` to carry.
        body();
        let _ = tx.send(());
    })?;
    Ok(BoundedThread { done })
}

impl BoundedThread {
    /// Wait for the body to finish, giving up after `bound`.
    ///
    /// `bound` is a failure bound on an external event, never a
    /// synchronisation delay — see the module doc. Callers must act on the
    /// returned outcome; a silently discarded [`ThreadExit::Abandoned`] would
    /// restore exactly the invisibility this type exists to remove.
    #[must_use]
    pub(crate) fn wait(self, bound: Duration) -> ThreadExit {
        match self.done.recv_timeout(bound) {
            Ok(()) => ThreadExit::Finished,
            Err(mpsc::RecvTimeoutError::Disconnected) => ThreadExit::Panicked,
            Err(mpsc::RecvTimeoutError::Timeout) => ThreadExit::Abandoned,
        }
    }
}

#[cfg(test)]
#[path = "bounded_thread_tests.rs"]
mod bounded_thread_tests;
