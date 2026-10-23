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

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Result;
use backon::{BlockingRetryable, ExponentialBuilder};

use crate::command::ProgramNotFound;

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

/// Whether `err` is one no retry can fix: marked [`permanent`], or a missing program.
pub fn is_permanent(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Permanent>().is_some() || err.downcast_ref::<ProgramNotFound>().is_some()
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
/// only when it [`is_permanent`].
pub fn until_ok<T>(what: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    until_ok_with(backoff(), what, op)
}

pub(crate) fn until_ok_with<T>(builder: ExponentialBuilder, what: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    let mut attempt = 0_u64;
    // backon's blocking retry has no hook to lengthen a delay, so `notify` hands the server's wait to the sleeper.
    let asked = Rc::new(Cell::new(Duration::ZERO));
    let notified = Rc::clone(&asked);
    op.retry(builder)
        .when(|err: &anyhow::Error| !is_permanent(err))
        .notify(|err: &anyhow::Error, delay| {
            attempt += 1;
            notified.set(requested_wait(err).unwrap_or_default());
            let delay = delay.max(notified.get());
            eprintln!("xtask: {what}: attempt {attempt} failed: {err:#}; retrying in {delay:.1?}");
        })
        .sleep(move |delay: Duration| std::thread::sleep(delay.max(asked.take())))
        .call()
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
