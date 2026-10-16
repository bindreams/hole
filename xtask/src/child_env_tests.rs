use std::ffi::OsStr;
use std::process::Command;

use crate::child_env::{is_run_injected, scrub_names};

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

#[skuld::test]
fn scrub_removes_exactly_the_injected_variables_from_the_child() {
    let inherited = ["PATH", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "CARGO_INCREMENTAL"].map(OsStr::new);
    let mut cmd = Command::new("true");
    scrub_names(&mut cmd, inherited);

    let removed: Vec<&OsStr> = cmd
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key)
        .collect();
    assert_eq!(
        removed,
        vec![OsStr::new("CARGO_MANIFEST_DIR"), OsStr::new("CARGO_PKG_NAME")]
    );
}

/// A variable the caller sets on the command itself afterwards wins: scrubbing
/// only clears what the child would have inherited.
#[skuld::test]
fn a_variable_set_explicitly_after_the_scrub_is_kept() {
    let mut cmd = Command::new("true");
    scrub_names(&mut cmd, [OsStr::new("CARGO_MANIFEST_DIR")]);
    cmd.env("CARGO_MANIFEST_DIR", "/chosen");
    let value = cmd
        .get_envs()
        .find(|(k, _)| *k == OsStr::new("CARGO_MANIFEST_DIR"))
        .and_then(|(_, v)| v);
    assert_eq!(value, Some(OsStr::new("/chosen")));
}
