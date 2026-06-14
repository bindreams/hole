//! CI coverage analysis: which workspace packages does `.github/workflows/ci.yaml`
//! actually RUN tests for?
//!
//! Backs the `every_workspace_crate_runs_in_ci` conformance test, which fails CI
//! if a workspace crate's tests run on no platform — the "orphaned test" class
//! (recent: #519 util, #522 tombstone, this issue's #526 hole-test-observability).
//!
//! The analysis is per-COMMAND, not per-`run:`-block: each `run:` script is a
//! multi-statement shell snippet (`mkdir -p target/debug && cargo nextest run …`),
//! so a block is split on shell separators and every command judged on its own.
//! A package is credited only when a command that actually RUNS tests names it —
//! never from a `cargo clippy -p …` lint or a `--no-run` compile. Counting those
//! would let a crate that is merely linted/built masquerade as test-covered.
//!
//! Two layers:
//!   - [`package_tokens`] pulls cargo package names out of one command, from both
//!     `package(<name>)` (nextest filter expressions) and `-p <name>`.
//!   - [`ci_run_packages`] walks every `run:` step in `ci.yaml`, and for each
//!     command either harvests a test-running nextest invocation or resolves a
//!     `cargo xtask run <target>` through `build.yaml` and recurses into that
//!     target's `run:`/`build:` commands under the same per-command rule.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::manifest::{Manifest, Step};

/// Cargo package names referenced in `cmd`, from both `package(<name>)`
/// (nextest filter expressions, possibly several in one `-E '...'`) and
/// `-p <name>` (space-separated). A valid name is `[A-Za-z0-9_-]+`; tokens that
/// don't fully match (e.g. a `tombstone/crash-dumps` feature path) are ignored.
///
/// Assumes additive filters — every `package(...)` names something the command
/// RUNS. An exclusion expression (`not(package(x))`, `all() - package(x)`) would
/// be mis-credited; ci.yaml uses only `+` unions today, so revisit if that changes.
pub fn package_tokens(cmd: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();

    // `package(<name>)` — scan every occurrence, not just the first.
    let mut rest = cmd;
    while let Some(open) = rest.find("package(") {
        let after = &rest[open + "package(".len()..];
        if let Some(close) = after.find(')') {
            let inner = after[..close].trim();
            if is_package_name(inner) {
                out.insert(inner.to_string());
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }

    // `-p <name>` — the token immediately after a bare `-p`.
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    for (i, &tok) in toks.iter().enumerate() {
        if tok == "-p" {
            if let Some(&name) = toks.get(i + 1) {
                if is_package_name(name) {
                    out.insert(name.to_string());
                }
            }
        }
    }

    out
}

/// A valid cargo package name token: non-empty, all chars in `[A-Za-z0-9_-]`.
fn is_package_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// Minimal `ci.yaml` shape — serde ignores every field we don't name, so this
// tracks only `jobs.<id>.steps[].run`.

#[derive(Deserialize)]
struct CiYaml {
    jobs: IndexMap<String, Job>,
}

#[derive(Deserialize)]
struct Job {
    #[serde(default)]
    steps: Vec<CiStep>,
}

#[derive(Deserialize)]
struct CiStep {
    #[serde(default)]
    run: Option<String>,
}

/// The set of packages CI actually RUNS tests for. Each step's `run:` script is
/// split into commands; every command is judged on its own (see module docs).
pub fn ci_run_packages(ci_yaml: &str, manifest: &Manifest) -> Result<BTreeSet<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let mut covered = BTreeSet::new();

    for job in ci.jobs.values() {
        for step in &job.steps {
            let Some(run) = &step.run else { continue };
            let joined = join_line_continuations(run);
            for cmd in split_commands(&joined) {
                collect_from_command(&cmd, manifest, &mut covered, &mut BTreeSet::new());
            }
        }
    }

    Ok(covered)
}

/// Collapse shell backslash-newline line continuations into spaces, so a command
/// written across several lines (as the archive-lane nextest invocations are)
/// is one logical command before [`split_commands`] runs.
fn join_line_continuations(script: &str) -> String {
    script.replace("\\\r\n", " ").replace("\\\n", " ")
}

/// Credit `cmd`'s packages into `covered`. A test-running nextest invocation
/// contributes its [`package_tokens`]; a `cargo xtask run <target>` resolves the
/// target and recurses into its `run:`/`build:` commands. `visited` guards the
/// (currently unused) run→run chain against an accidental manifest cycle.
fn collect_from_command(
    cmd: &str,
    manifest: &Manifest,
    covered: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) {
    if is_nextest_run(cmd) {
        covered.extend(package_tokens(cmd));
    }

    if let Some(target) = xtask_run_target(cmd) {
        if visited.insert(target.to_string()) {
            if let Some(t) = manifest.get(target) {
                for step in t.run.iter().chain(t.build.iter()) {
                    let joined = join_line_continuations(&step_command(step));
                    for inner in split_commands(&joined) {
                        collect_from_command(&inner, manifest, covered, visited);
                    }
                }
            }
        }
    }
}

/// Split a (possibly multi-statement) shell script into individual commands on
/// the unquoted shell separators `&&`, `||`, `|`, `;`, and newlines. Separators
/// inside `'…'` / `"…"` are NOT command boundaries — this matters because a
/// nextest `-E '…'` filter expression (folded YAML) carries newlines inside its
/// single quotes. Tokens within a command stay whitespace-separated, so
/// downstream `split_whitespace` matching is unaffected.
fn split_commands(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;

    for c in script.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                '\n' | ';' | '|' | '&' => {
                    push_command(&mut out, &mut cur);
                }
                _ => cur.push(c),
            },
        }
    }
    push_command(&mut out, &mut cur);
    out
}

/// Flush the accumulated command into `out` if it is non-empty after trimming.
fn push_command(out: &mut Vec<String>, cur: &mut String) {
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    cur.clear();
}

/// Does this single command RUN tests? True iff it spawns nextest with the `run`
/// subcommand (`cargo nextest run` OR `cargo-nextest nextest run`) and is not a
/// `--no-run` compile-only invocation.
fn is_nextest_run(cmd: &str) -> bool {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    if toks.contains(&"--no-run") {
        return false;
    }
    toks.windows(2).any(|w| w[0] == "nextest" && w[1] == "run")
}

/// The target of a `cargo xtask run <target>` command, if `cmd` is one.
fn xtask_run_target(cmd: &str) -> Option<&str> {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    toks.windows(4)
        .find(|w| w[0] == "cargo" && w[1] == "xtask" && w[2] == "run")
        .map(|w| w[3])
}

/// The command-line text of a manifest step, for token extraction.
fn step_command(step: &Step) -> String {
    match step {
        Step::Bash { command, .. } => command.clone(),
        Step::Process { args, .. } => args.join(" "),
    }
}
