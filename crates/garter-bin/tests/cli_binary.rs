//! The informational flags exit 0 and print, through the built `garter` binary (text is checked in `cli_tests.rs`).

#![allow(clippy::disallowed_methods)] // spawns the binary under test, never privileged

use std::process::{Command, Stdio};

/// What the staged binary must do for the release probes: exit 0 and print to stdout.
fn exits_0_and_prints(flag: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_garter"))
        .arg(flag)
        .stdin(Stdio::null())
        .output()
        .expect("spawn garter");
    assert!(out.status.success(), "{:?}", out.status);
    assert!(!out.stdout.is_empty(), "no stdout for {flag}");
}

#[skuld::test]
fn version_exits_0_and_prints() {
    exits_0_and_prints("--version");
}

#[skuld::test]
fn help_exits_0_and_prints() {
    exits_0_and_prints("--help");
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
