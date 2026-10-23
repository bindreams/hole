//! `verify-run-injected-env`: the strip in [`crate::child_env`] covers what a
//! real `cargo run` adds to xtask's environment.
//!
//! [`is_run_injected`] is a prefix rule, so a test that feeds it a list of
//! names only restates it. This check runs in a real `cargo run --package
//! xtask`, from a CI step that first records its own environment with an
//! external `env -0`, before cargo is involved. Every name xtask was launched with
//! that the step did not have must be stripped ([`is_run_injected`]) or be on
//! [`KEPT_TOOLCHAIN`]; anything else is a variable cargo started injecting that
//! the strip does not know about, and fails the step by name.
//!
//! The strip runs first in `main`, so the set compared is the one it recorded
//! before removing anything ([`launch_env_names`]).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::child_env::{is_run_injected, launch_env_names};

/// Variables `cargo run` (cargo 1.98.0, the pinned toolchain, via the rustup proxy) adds that the
/// strip must keep. None is package environment: each is toolchain state that
/// does not depend on which package is run, and a child that runs cargo or
/// loads the toolchain's libraries needs it. Each is `(name, why it stays)`.
pub const KEPT_TOOLCHAIN: &[(&str, &str)] = &[
    (
        "CARGO",
        "path of the cargo binary; a child's own `cargo` must be this one",
    ),
    (
        "CARGO_HOME",
        "registry and git cache a child's cargo shares; a caller's setting",
    ),
    (
        "DYLD_FALLBACK_LIBRARY_PATH",
        "macOS search path for the toolchain's dylibs, which the programs cargo runs load",
    ),
    (
        "LD_LIBRARY_PATH",
        "search path for the toolchain's shared libraries; cargo sets it on Windows too (CI-measured)",
    ),
    (
        "RUST_RECURSION_COUNT",
        "rustup proxy's loop guard; dropping it lets a mis-set proxy recurse unbounded",
    ),
    (
        "RUSTUP_HOME",
        "where rustup finds toolchains; a child's `cargo` needs the same",
    ),
    (
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
        "path of rustup's fallback settings file (macOS runner, CI-measured); a child's rustup reads the same",
    ),
    (
        "RUSTUP_TOOLCHAIN",
        "the toolchain selected for this run; a child must not pick another",
    ),
    (
        "RUSTUP_TOOLCHAIN_SOURCE",
        "how that toolchain was selected; rustup reads it alongside RUSTUP_TOOLCHAIN",
    ),
];

/// Names in `launch` that are neither in `parent`, nor run-injected, nor kept;
/// sorted, no repeats. With `case_insensitive` (Windows), `Path` is `PATH`.
pub fn unexplained_additions_with(
    launch: &[OsString],
    parent: &BTreeSet<String>,
    case_insensitive: bool,
) -> Vec<String> {
    let fold = |name: &str| {
        if case_insensitive {
            name.to_ascii_uppercase()
        } else {
            name.to_string()
        }
    };
    let parent: BTreeSet<String> = parent.iter().map(|n| fold(n)).collect();
    launch
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| {
            !parent.contains(&fold(name))
                && !is_run_injected(name)
                && !KEPT_TOOLCHAIN.iter().any(|(kept, _)| fold(kept) == fold(name))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The names a baseline file holds. The file is `env -0` output: NUL-terminated
/// `NAME=value` entries, each named by the text before its first `=` (after a
/// leading one, which Windows keeps in `=C:`). An external `env` records what a
/// child sees, including names that are not shell identifiers
/// (`ProgramFiles(x86)`) which a shell builtin leaves out. A baseline that
/// holds a run-injected name was recorded inside `cargo run` and would hide it;
/// one with no names explains nothing; an entry with no `=` is not `env -0`
/// output.
pub fn parse_parent_names(text: &[u8]) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in text.split(|&b| b == 0).filter(|e| !e.is_empty()) {
        let skip = usize::from(entry[0] == b'=');
        let Some(eq) = entry[skip..].iter().position(|&b| b == b'=') else {
            bail!(
                "the parent-environment baseline has an entry with no `=` ({:?}): \
                 it must be the output of `env -0`",
                String::from_utf8_lossy(entry)
            );
        };
        names.insert(String::from_utf8_lossy(&entry[..skip + eq]).into_owned());
    }
    if names.is_empty() {
        bail!("the parent-environment baseline holds no names");
    }
    let injected: Vec<&String> = names.iter().filter(|n| is_run_injected(n)).collect();
    if !injected.is_empty() {
        bail!(
            "the parent-environment baseline holds run-injected names {injected:?}: \
             record it before `cargo run`, not inside it"
        );
    }
    Ok(names)
}

/// Fail unless every variable xtask was launched with is the parent's (the
/// names in `parent_names`), stripped, or kept.
pub fn verify(parent_names: &Path) -> Result<()> {
    let launch = launch_env_names().context("the startup strip has not recorded the launch environment")?;
    let text = std::fs::read(parent_names)
        .with_context(|| format!("reading the parent-environment baseline {}", parent_names.display()))?;
    let parent = parse_parent_names(&text).with_context(|| format!("in {}", parent_names.display()))?;
    let unexplained = unexplained_additions_with(launch, &parent, cfg!(windows));
    if !unexplained.is_empty() {
        bail!(
            "`cargo run` gave xtask variables the startup strip neither removes nor keeps: {}. \
             Package environment goes in `child_env::is_run_injected`; toolchain state \
             goes in `KEPT_TOOLCHAIN` with its reason.",
            unexplained.join(", ")
        );
    }
    println!(
        "xtask: all {} variables xtask was launched with are the parent's, stripped or kept",
        launch.len()
    );
    Ok(())
}

#[cfg(test)]
#[path = "run_injected_env_tests.rs"]
mod run_injected_env_tests;
