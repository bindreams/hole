//! Retry a provisioning fetch until it succeeds.
//!
//! A runner that briefly loses its network must not fail a build step (#1067,
//! #670). There is no attempt cap: the step's own `timeout-minutes` is the bound,
//! and every failed attempt prints its cause so the log shows why it waited.
//!
//! Only for operations that are safe to repeat and fail on the network
//! (downloads, clones, module fetches), never for builds or tests. A missing
//! program is not the only failure no retry can fix: an operation marks any other
//! one [`permanent`], and a permanent failure ends the loop too. A server that
//! names how long to wait ([`retry_after`]) is waited for at least that long.
//! Ctrl-C ends the loop: xtask survives the signal by design (#568), so the loop
//! observes the recorded interrupt itself, between attempts and during the backoff.

use std::time::Duration;

use anyhow::Result;
use backon::{BackoffBuilder, ExponentialBuilder};

use crate::command::ProgramNotFound;
use crate::interrupt::{Interrupt, PROCESS};

/// Marks an error no retry can fix (a 404, a complete body with the wrong hash, a
/// working directory that does not exist). Attach it with [`permanent`].
#[derive(Debug)]
struct Permanent;

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not retried")
    }
}

/// Mark `err` as one [`until_ok`] must not retry. The cause stays in the chain.
pub fn permanent(err: anyhow::Error) -> anyhow::Error {
    err.context(Permanent)
}

/// The user interrupted the loop (Ctrl-C).
#[derive(Debug)]
struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted")
    }
}

/// Whether `err` is the interrupt that ended an [`until_ok`] loop.
pub fn is_interrupted(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Interrupted>().is_some()
}

/// Whether `err` is one no retry can fix: marked [`permanent`], a missing program, or an interrupt.
pub fn is_permanent(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Permanent>().is_some() || err.downcast_ref::<ProgramNotFound>().is_some() || is_interrupted(err)
}

/// The wait a server asked for (`Retry-After`), carried on a failure.
#[derive(Debug)]
struct RetryAfter(Duration);

impl std::fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the server asked for a wait of {:?}", self.0)
    }
}

/// Mark `err` as one the server asked to retry after `wait`. [`until_ok`] sleeps at least that long.
pub fn retry_after(err: anyhow::Error, wait: Duration) -> anyhow::Error {
    err.context(RetryAfter(wait))
}

/// The wait a server asked for on `err`, if it did.
pub fn requested_wait(err: &anyhow::Error) -> Option<Duration> {
    err.downcast_ref::<RetryAfter>().map(|r| r.0)
}

/// Backoff between attempts: 1 s, doubling to a 30 s ceiling, with jitter. The
/// ceiling bounds the delay between attempts, not the number of attempts.
fn backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_max_delay(Duration::from_secs(30))
        .with_jitter()
        .without_max_times()
}

/// Run `op` until it returns `Ok`, printing each failure (`what`, the error
/// chain and the delay before the next attempt) to stderr. Returns the error
/// only when it [`is_permanent`]; an interrupt (Ctrl-C) returns [`is_interrupted`].
pub fn until_ok<T>(what: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    until_ok_with(backoff(), &PROCESS, what, op)
}

pub(crate) fn until_ok_with<T>(
    builder: ExponentialBuilder,
    interrupt: &Interrupt,
    what: &str,
    mut op: impl FnMut() -> Result<T>,
) -> Result<T> {
    // backon's blocking retry takes a `'static` sleeper, which cannot borrow `interrupt`; its delay
    // schedule is all this needs.
    let mut delays = builder.build();
    let mut attempt = 0_u64;
    loop {
        // An attempt never starts once the interrupt is raised.
        if interrupt.is_raised() {
            return Err(anyhow::Error::msg(Interrupted));
        }
        let err = match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_permanent(&err) => return Err(err),
            Err(err) => err,
        };
        let Some(delay) = delays.next() else {
            return Err(err);
        };
        attempt += 1;
        let delay = delay.max(requested_wait(&err).unwrap_or_default());
        // A raise during the attempt (Ctrl-C also killed its child) is seen here, before any wait.
        if interrupt.is_raised() {
            eprintln!("xtask: {what}: attempt {attempt} failed: {err:#}; interrupted");
            return Err(anyhow::Error::msg(Interrupted));
        }
        eprintln!("xtask: {what}: attempt {attempt} failed: {err:#}; retrying in {delay:.1?}");
        if interrupt.sleep(delay) {
            return Err(anyhow::Error::msg(Interrupted));
        }
    }
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
