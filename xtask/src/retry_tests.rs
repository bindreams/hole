#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::time::Duration;

use anyhow::anyhow;
use backon::ExponentialBuilder;

use super::*;

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
    let value = until_ok_with(instant(), "test fetch", || {
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
    until_ok_with(instant(), "test fetch", || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
}

#[skuld::test]
fn gives_up_on_a_missing_program() {
    let mut calls = 0;
    let err = until_ok_with(instant(), "test fetch", || -> Result<()> {
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
    let err = until_ok_with(instant(), "test fetch", || -> Result<()> {
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
