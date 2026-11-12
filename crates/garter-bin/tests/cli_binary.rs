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

/// The shipped `garter` binary does not search its own folder for libraries (`build.rs` calls `libsearch_guard::bins()`).
/// Reads `CARGO_BIN_EXE_garter` at run time first: a nextest archive run remaps it.
#[skuld::test]
fn garter_is_hardened() {
    let exe = std::env::var_os("CARGO_BIN_EXE_garter").unwrap_or_else(|| env!("CARGO_BIN_EXE_garter").into());
    libsearch_guard::verify(&exe).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; the crate's build.rs must call libsearch_guard::bins()",
            exe.to_string_lossy()
        )
    });
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
