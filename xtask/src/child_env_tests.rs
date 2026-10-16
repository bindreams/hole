#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use crate::child_env::is_run_injected;
use crate::test_child::MODE_ENV;

#[skuld::test]
fn the_package_environment_cargo_run_injects_is_recognized() {
    // Measured: `cargo run` (cargo 1.99.0) exports exactly these to the program it launches.
    for name in [
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_PKG_AUTHORS",
        "CARGO_PKG_DESCRIPTION",
        "CARGO_PKG_HOMEPAGE",
        "CARGO_PKG_LICENSE",
        "CARGO_PKG_LICENSE_FILE",
        "CARGO_PKG_NAME",
        "CARGO_PKG_README",
        "CARGO_PKG_REPOSITORY",
        "CARGO_PKG_RUST_VERSION",
        "CARGO_PKG_VERSION",
        "CARGO_PKG_VERSION_MAJOR",
        "CARGO_PKG_VERSION_MINOR",
        "CARGO_PKG_VERSION_PATCH",
        "CARGO_PKG_VERSION_PRE",
    ] {
        assert!(is_run_injected(name), "{name}");
    }
}

/// Configuration the user or CI chose for every cargo they run is not injected,
/// and removing it would change what the child builds.
#[skuld::test]
fn settings_a_caller_chose_are_not_recognized() {
    for name in [
        "CARGO",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "CARGO_BUILD_JOBS",
        "RUSTC_WRAPPER",
        "RUSTFLAGS",
        "PATH",
        "HOME",
    ] {
        assert!(!is_run_injected(name), "{name}");
    }
}

/// Names of the variables a process launched in `mode` reports, with the
/// injected package environment and one caller setting present in its own.
fn reported_env_names(mode: &str) -> Vec<String> {
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .env(MODE_ENV, mode)
        .env("CARGO_MANIFEST_DIR", "/injected")
        .env("CARGO_PKG_NAME", "injected")
        .env("CARGO_INCREMENTAL", "0")
        .output()
        .expect("spawn the process under test");
    assert!(
        out.status.success(),
        "{mode}: {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8 names")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Stripping once at startup is what keeps every spawn clean: a process that has
/// stripped hands no child the injected variables, whatever spawns it, and keeps
/// the settings the caller chose. The control run shows the probe does see the
/// variables when nothing strips them.
#[skuld::test]
fn a_child_spawned_after_the_startup_strip_does_not_inherit_the_injected_variables() {
    let control = reported_env_names("list-env");
    assert!(
        control.iter().any(|n| n == "CARGO_MANIFEST_DIR"),
        "control saw {control:?}"
    );
    assert!(control.iter().any(|n| n == "CARGO_PKG_NAME"), "control saw {control:?}");

    let stripped = reported_env_names("strip-then-list-env-in-child");
    assert!(
        stripped.iter().any(|n| n == "CARGO_INCREMENTAL"),
        "a caller's setting must survive the strip, saw {stripped:?}"
    );
    let leaked: Vec<&String> = stripped
        .iter()
        .filter(|n| crate::child_env::is_run_injected(n))
        .collect();
    assert!(leaked.is_empty(), "children inherited {leaked:?}");
}

/// The strip is sound only while `main` is single-threaded, and `ctrlc` (behind
/// `install_transparent_interrupt`) starts a thread: the strip must be the
/// first statement of `main`, ahead of everything else.
#[skuld::test]
fn main_strips_before_anything_else_runs() {
    let main_rs = std::fs::read_to_string(crate::repo_root().expect("repo root").join("xtask/src/main.rs"))
        .expect("read xtask/src/main.rs");
    let body = main_rs
        .split_once("fn main() -> ExitCode {")
        .expect("main's signature")
        .1;
    let first_statement = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//"))
        .expect("main has a body");
    assert_eq!(first_statement, "xtask::child_env::strip_run_injected();");
}
