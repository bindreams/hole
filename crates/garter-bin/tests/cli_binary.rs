//! The informational flags, through the built `garter` binary.

#![allow(clippy::disallowed_methods)] // spawns the binary under test, never privileged

use std::process::{Command, Output, Stdio};

use garter_bin::cli::VERSION;

fn garter(flag: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_garter"))
        .arg(flag)
        .stdin(Stdio::null())
        .output()
        .expect("spawn garter")
}

#[skuld::test]
fn version_prints_the_stamped_version_and_exits_0() {
    let out = garter("--version");
    assert!(out.status.success(), "{:?}", out.status);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("garter {VERSION}"));
}

#[skuld::test]
fn help_names_both_flags_and_exits_0() {
    let out = garter("--help");
    assert!(out.status.success(), "{:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--version") && stdout.contains("--help"), "{stdout}");
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
