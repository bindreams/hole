#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::time::Duration;

use anyhow::anyhow;
use backon::ExponentialBuilder;

use super::*;
use crate::interrupt::Interrupt;

fn instant() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::ZERO)
        .with_max_delay(Duration::ZERO)
        .without_max_times()
}

#[skuld::test]
fn retries_past_any_number_of_failures() {
    // Well past backon's default of 3 attempts: nothing may cap the count.
    const FAILURES: u32 = 50;
    let mut calls = 0;
    let value = until_ok_with(instant(), &Interrupt::new(), "test fetch", || {
        calls += 1;
        if calls <= FAILURES {
            Err(anyhow!("network down"))
        } else {
            Ok(calls)
        }
    })
    .unwrap();
    assert_eq!(value, FAILURES + 1);
}

#[skuld::test]
fn returns_the_first_success_without_retrying() {
    let mut calls = 0;
    until_ok_with(instant(), &Interrupt::new(), "test fetch", || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
}

#[skuld::test]
fn gives_up_on_a_missing_program() {
    let mut calls = 0;
    let err = until_ok_with(instant(), &Interrupt::new(), "test fetch", || -> Result<()> {
        calls += 1;
        crate::command::run_inherited(&mut std::process::Command::new("hole-xtask-no-such-program"))
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(err.downcast_ref::<ProgramNotFound>().is_some(), "{err:#}");
}

#[skuld::test]
fn gives_up_on_a_permanent_failure() {
    let mut calls = 0;
    let err = until_ok_with(instant(), &Interrupt::new(), "test fetch", || -> Result<()> {
        calls += 1;
        Err(permanent(anyhow!("HTTP 404")))
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(is_permanent(&err));
    assert!(
        format!("{err:#}").contains("HTTP 404"),
        "the cause stays visible: {err:#}"
    );
}

#[skuld::test]
fn an_ordinary_failure_is_not_permanent() {
    assert!(!is_permanent(&anyhow!("network down")));
}

#[skuld::test]
fn waits_at_least_as_long_as_the_server_asked() {
    let mut calls = 0;
    let started = std::time::Instant::now();
    until_ok_with(instant(), &Interrupt::new(), "test fetch", || {
        calls += 1;
        if calls == 1 {
            Err(retry_after(anyhow!("HTTP 429"), Duration::from_secs(1)))
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert!(started.elapsed() >= Duration::from_secs(1), "{:?}", started.elapsed());
}

#[skuld::test]
fn a_retry_after_survives_added_context() {
    let err = retry_after(anyhow!("HTTP 429"), Duration::from_secs(7)).context("failed to download");
    assert_eq!(requested_wait(&err), Some(Duration::from_secs(7)));
    assert_eq!(requested_wait(&anyhow!("network down")), None);
}

#[skuld::test]
fn a_retry_after_does_not_make_a_failure_permanent() {
    assert!(!is_permanent(&retry_after(anyhow!("HTTP 429"), Duration::from_secs(1))));
}

/// A builder whose first backoff is an hour: a loop that fails to observe the interrupt hangs here.
fn an_hour() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(3600))
        .with_max_delay(Duration::from_secs(3600))
        .without_max_times()
}

#[skuld::test]
fn an_interrupt_during_the_backoff_ends_the_loop_with_the_interrupted_error() {
    let interrupt = Interrupt::new();
    let mut calls = 0;
    let err = std::thread::scope(|scope| {
        until_ok_with(an_hour(), &interrupt, "test fetch", || -> Result<()> {
            calls += 1;
            // The handler runs on its own thread, concurrently with the backoff that follows this failure.
            scope.spawn(|| interrupt.raise());
            Err(anyhow!("network down"))
        })
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(is_interrupted(&err), "{err:#}");
    assert!(
        is_permanent(&err),
        "an interrupted loop must not be retried by an outer one: {err:#}"
    );
}

#[skuld::test]
fn an_interrupt_during_an_attempt_stops_the_loop_after_it() {
    // Ctrl-C reaches the child and the handler together: the attempt fails, the next must not start.
    let interrupt = Interrupt::new();
    let mut calls = 0;
    let err = until_ok_with(an_hour(), &interrupt, "test fetch", || -> Result<()> {
        calls += 1;
        interrupt.raise();
        Err(anyhow!("child killed by Ctrl-C"))
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(is_interrupted(&err), "{err:#}");
}

#[skuld::test]
fn an_attempt_that_succeeds_after_an_interrupt_still_ends_the_loop() {
    // An attempt with no child to carry Ctrl-C (a download), or one that spawned its child after the
    // handler ran, succeeds anyway; the user's interrupt must not be swallowed by that success.
    let interrupt = Interrupt::new();
    let mut calls = 0;
    let err = until_ok_with(instant(), &interrupt, "test fetch", || {
        calls += 1;
        interrupt.raise();
        Ok(calls)
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(is_interrupted(&err), "{err:#}");
}

#[skuld::test]
fn a_permanent_failure_during_an_interrupt_still_reports_the_interrupt() {
    let interrupt = Interrupt::new();
    let err = until_ok_with(instant(), &interrupt, "test fetch", || -> Result<()> {
        interrupt.raise();
        Err(permanent(anyhow!("HTTP 404")))
    })
    .unwrap_err();
    assert!(is_interrupted(&err), "{err:#}");
}

#[skuld::test]
fn an_interrupt_raised_before_the_first_attempt_runs_nothing() {
    let interrupt = Interrupt::new();
    interrupt.raise();
    let mut calls = 0;
    let err = until_ok_with(instant(), &interrupt, "test fetch", || {
        calls += 1;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(calls, 0);
    assert!(is_interrupted(&err), "{err:#}");
}

#[skuld::test]
fn an_ordinary_failure_is_not_an_interrupt() {
    assert!(!is_interrupted(&anyhow!("network down")));
}
