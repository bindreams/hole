//! Does a `.github/workflows/ci.yaml` test lane run the binaries it compiled?
//!
//! Backs the `ci_test_hole_steps_match_the_hole_tests_target` conformance test.
//! The `hole-` steps of the `ci` job compile once via `cargo xtask build
//! hole-tests`, then their nextest steps are only supposed to re-execute those
//! binaries. Cargo keys that reuse on
//! the resolved feature set, so a step missing one `--features` flag rebuilds the
//! whole workspace instead — silently, staying green at roughly twice the wall
//! clock, which is how #720 went unnoticed.
//!
//! [`TestJob`] therefore reports the chain, not just the commands: the build.yaml
//! target the job's `cargo xtask build` step names, and each nextest run to
//! compare against that target's own `run:`. Hardcoding the target on the test
//! side would let a retargeted build step empty the invariant while it still
//! passed.
//!
//! The two files state the same command with different quoting, folding and
//! environment conventions, so comparison is on a normalized form: line
//! continuations joined, whitespace collapsed, and a leading `sudo`/`env`/
//! `VAR=value` launcher prefix stripped (the macOS TUN step states inline what
//! its siblings state as step-level `env:`). Only [`FINGERPRINT_NEUTRAL_ENV`]
//! variables may be stripped or exported — anything else feeds cargo's
//! fingerprint, and normalizing it away would hide the very rebuild being
//! guarded against. Two launcher forms are exempt because they cannot change
//! what cargo builds: the [`NO_COMPILE_GATE`] wrapper, and the forward
//! `${NAME+"NAME=$NAME"}`, which hands the child the variable as it already is,
//! set or unset. The latter is how a `sudo env` child gets back a variable
//! `sudo` dropped.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::ci_coverage::{
    is_nextest_run, join_line_continuations, scoped_steps, split_commands, step_command, step_environment, unquote,
};
use crate::ci_timeouts::xtask_target;
use crate::manifest::Manifest;

/// Environment variables a compared step may set — the two files are free to
/// state these differently.
///
/// Admission criterion: does it reach cargo's fingerprint, and if so does it
/// INVALIDATE rather than corrupt it? `PATH` passes on the second clause (a
/// different rustc changes the fingerprint's version hash, so cargo rebuilds
/// instead of reusing stale units), `HOME` only relocates `CARGO_HOME`, and
/// `SKULD_LABELS` is read by skuld at test runtime. `NEXTEST_PROFILE` is read
/// by nextest itself at its own run/list time (`.config/nextest.toml`'s
/// `[profile.<name>]` selection) — cargo never sees it, so it cannot affect
/// what gets compiled. `CARGO_LOG` selects cargo's own tracing output (the
/// fingerprint dirty-reasons the gate's failure message relies on) and is read
/// by no build. `RUSTFLAGS`, `RUSTC_WRAPPER` and `CARGO_TARGET_DIR` fail
/// it. The test is asymmetric: rejecting a neutral variable is loud and costs
/// one line here, admitting a relevant one is silent.
pub const FINGERPRINT_NEUTRAL_ENV: [&str; 5] = ["HOME", "PATH", "SKULD_LABELS", "NEXTEST_PROFILE", "CARGO_LOG"];

/// The wrapper that runs a command and fails if cargo compiled anything while
/// it ran. It changes neither the command nor its environment.
pub const NO_COMPILE_GATE: &str = ".github/scripts/fail-on-compile.sh";

// Minimal `ci.yaml` shape — serde ignores every field we don't name, so this
// tracks only `jobs.<id>.steps[].{name,id,run,env}`.

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
    name: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    run: Option<String>,
    /// Values stay uninterpreted: only the variable NAMES matter here, and a
    /// non-string scalar on an unrelated step must not abort the parse.
    #[serde(default)]
    env: IndexMap<String, serde_yml::Value>,
}

/// The compile-then-run chain of a ci.yaml test job.
#[derive(Debug)]
pub struct TestJob {
    /// build.yaml target whose `cargo xtask build|run` step compiled the
    /// binaries — the only defensible thing to compare the runs against.
    pub target: String,
    /// `(step label, normalized nextest command)` per RUN step, in workflow order.
    pub runs: Vec<(String, String)>,
    /// How each RUN step in [`TestJob::runs`] is launched, in the same order.
    pub launches: Vec<(String, Launch)>,
}

/// What precedes the cargo command of a nextest run: the launcher prefix that
/// [`TestJob::runs`] strips from the compared text.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Launch {
    /// Started through [`NO_COMPILE_GATE`].
    pub gated: bool,
    /// Started through `sudo`.
    pub privileged: bool,
    /// Variables handed on with `${NAME+"NAME=$NAME"}`, i.e. restored to the ambient state.
    pub forwarded: BTreeSet<String>,
}

/// Resolve `job_id`'s chain: the single build.yaml target it compiles, and every
/// nextest RUN command it then executes, over the steps `step_prefix` selects
/// (see [`scoped_steps`]).
///
/// `--no-run` compiles are not runs — compiling is a separate operation, stated
/// separately in build.yaml as `build:`.
pub fn test_job(ci_yaml: &str, job_id: &str, step_prefix: Option<&str>) -> Result<TestJob> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = ci
        .jobs
        .get(job_id)
        .with_context(|| format!("ci.yaml declares no job {job_id:?}"))?;

    let mut target: Option<String> = None;
    let mut runs = Vec::new();
    let mut launches = Vec::new();

    let in_scope = scoped_steps(job_id, &job.steps, |s| s.id.as_deref(), step_prefix)?;
    for (i, step) in in_scope {
        let Some(run) = &step.run else { continue };
        let label = step_label(step, i);
        for cmd in split_commands(&join_line_continuations(run)) {
            if is_nextest_run(&cmd) {
                check_env(&label, step.env.keys().map(String::as_str))?;
                let (launch, normalized) = split_launch(&cmd)?;
                runs.push((label.clone(), normalized));
                launches.push((label.clone(), launch));
                continue;
            }
            let Some(found) = xtask_target(&cmd)? else { continue };
            if let Some(prev) = &target {
                bail!("ci.yaml job {job_id:?} builds both {prev:?} and {found:?}; which one its tests re-execute is ambiguous");
            }
            check_env(&label, step.env.keys().map(String::as_str))?;
            target = Some(found.to_string());
        }
    }

    let target = target.with_context(|| {
        format!("ci.yaml job {job_id:?} invokes no `cargo xtask build|run`, so nothing ties its test steps to a build.yaml target")
    })?;
    Ok(TestJob { target, runs, launches })
}

/// The nextest-RUN command of build.yaml target `name`, normalized the same way
/// as [`test_job`]'s. Exactly one is required: zero or several make "the command
/// this target runs" ambiguous, and guessing would compare the CI steps against
/// something nobody chose.
pub fn target_nextest_run(manifest: &Manifest, name: &str) -> Result<String> {
    let target = manifest
        .get(name)
        .with_context(|| format!("build.yaml declares no target {name:?}"))?;

    let mut found = Vec::new();
    for step in &target.run {
        for cmd in split_commands(&join_line_continuations(&step_command(step))) {
            if is_nextest_run(&cmd) {
                check_env(name, step_environment(step).keys().map(String::as_str))?;
                found.push(split_launch(&cmd)?.1);
            }
        }
    }

    if found.len() != 1 {
        bail!(
            "build.yaml target {name:?} has {} nextest run commands in its `run:` steps, expected exactly one",
            found.len()
        );
    }
    Ok(found.remove(0))
}

/// Reject any exported variable outside [`FINGERPRINT_NEUTRAL_ENV`].
fn check_env<'a>(label: &str, names: impl Iterator<Item = &'a str>) -> Result<()> {
    for name in names {
        if !FINGERPRINT_NEUTRAL_ENV.contains(&name) {
            bail!(
                "{label:?} exports {name:?}, which is outside the fingerprint-neutral set \
                 {FINGERPRINT_NEUTRAL_ENV:?} — it can change what cargo builds, so the compiled \
                 and executed binaries can no longer be assumed to be the same ones"
            );
        }
    }
    Ok(())
}

/// A step's identity in a failure message: its `name`, else its `id`, else its
/// position. Every step has one of the three.
fn step_label(step: &CiStep, index: usize) -> String {
    step.name
        .clone()
        .or_else(|| step.id.clone())
        .unwrap_or_else(|| format!("steps[{index}]"))
}

/// One command split into its launcher prefix and the comparable remainder:
/// whitespace collapsed to single spaces, launchers dropped.
fn split_launch(cmd: &str) -> Result<(Launch, String)> {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let mut launch = Launch::default();
    let mut start = 0;
    while let Some(tok) = toks.get(start) {
        match classify(tok) {
            Token::Gate => launch.gated = true,
            Token::Sudo => launch.privileged = true,
            Token::Launcher => {}
            Token::Forward(name) => {
                launch.forwarded.insert(name.to_string());
            }
            Token::Command => break,
            Token::ForeignEnv(name) => bail!(
                "command {cmd:?} sets {name:?} inline, which is outside the fingerprint-neutral \
                 set {FINGERPRINT_NEUTRAL_ENV:?} — stripping it would hide a cargo rebuild \
                 (forward the ambient value with ${{{name}+\"{name}=${name}\"}})"
            ),
        }
        start += 1;
    }
    Ok((launch, toks[start..].join(" ")))
}

enum Token<'a> {
    /// The [`NO_COMPILE_GATE`] wrapper.
    Gate,
    /// `sudo`: the command runs with a replaced environment.
    Sudo,
    /// Sets up the environment rather than naming the command.
    Launcher,
    /// `${NAME+"NAME=$NAME"}`: the child gets the variable as the ambient environment has it.
    Forward(&'a str),
    /// An assignment of a variable cargo's fingerprint may depend on.
    ForeignEnv(&'a str),
    /// The command itself — everything from here on is compared.
    Command,
}

fn classify(tok: &str) -> Token<'_> {
    let stripped = unquote(tok);
    if stripped == NO_COMPILE_GATE {
        return Token::Gate;
    }
    if stripped == "sudo" {
        return Token::Sudo;
    }
    if stripped == "env" {
        return Token::Launcher;
    }
    if let Some(key) = forwarded_name(tok) {
        return forward(key);
    }
    match stripped.split_once('=') {
        Some((key, _)) if is_env_var_name(key) => {
            if FINGERPRINT_NEUTRAL_ENV.contains(&key) {
                Token::Launcher
            } else {
                Token::ForeignEnv(key)
            }
        }
        _ => Token::Command,
    }
}

/// A forward is a launcher whatever the name, but only a name outside
/// [`FINGERPRINT_NEUTRAL_ENV`] is worth reporting as one.
fn forward(key: &str) -> Token<'_> {
    if FINGERPRINT_NEUTRAL_ENV.contains(&key) {
        Token::Launcher
    } else {
        Token::Forward(key)
    }
}

/// `NAME` of the raw token `${NAME+"NAME=$NAME"}`, the one form that hands the
/// child the variable unchanged: `"NAME=$NAME"` would set an unset one to empty.
fn forwarded_name(tok: &str) -> Option<&str> {
    let (key, word) = tok.strip_prefix("${")?.strip_suffix('}')?.split_once('+')?;
    (is_env_var_name(key) && word == format!("\"{key}=${key}\"")).then_some(key)
}

/// A POSIX environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
