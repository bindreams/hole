//! Retry a provisioning fetch until it succeeds.
//!
//! A runner that briefly loses its network must not fail a build step (#1067,
//! #670). There is no attempt cap: the step's own `timeout-minutes` is the bound,
//! and every failed attempt prints its cause so the log shows why it waited.
//!
//! Only for operations that are safe to repeat and fail on the network
//! (downloads, clones, module fetches), never for builds or tests. A missing
//! program is the one failure no retry can fix, so it ends the loop.

use std::time::Duration;

use anyhow::Result;
use backon::{BlockingRetryable, ExponentialBuilder};

use crate::command::ProgramNotFound;

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
/// only when the program `op` runs is not installed.
pub fn until_ok<T>(what: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    until_ok_with(backoff(), what, op)
}

pub(crate) fn until_ok_with<T>(builder: ExponentialBuilder, what: &str, op: impl FnMut() -> Result<T>) -> Result<T> {
    let mut attempt = 0_u64;
    op.retry(builder)
        .when(|err: &anyhow::Error| err.downcast_ref::<ProgramNotFound>().is_none())
        .notify(|err: &anyhow::Error, delay| {
            attempt += 1;
            eprintln!("xtask: {what}: attempt {attempt} failed: {err:#}; retrying in {delay:.1?}");
        })
        .call()
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
