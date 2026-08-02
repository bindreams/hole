//! Which `.github/workflows/ci.yaml` jobs assemble a release installer, and what
//! timeout budget does each one carry?
//!
//! Backs the `ci_installer_assembly_jobs_share_a_timeout_budget` conformance
//! test. Assembling an installer is the most expensive thing CI does — a full
//! release build of `hole`, then the bundler, then the package's own test suite
//! — so those jobs sit closest to their `timeout-minutes` wall. When two jobs do
//! that same work but disagree on the budget, the smaller one is killed
//! mid-compile on the slower runner while its sibling passes.
//!
//! The test asserts EQUALITY, not a floor: there is no defensible magic number
//! for "long enough", but there is a defensible invariant that sibling jobs
//! doing the same work on the same runner matrix get the same budget. Raising
//! the class budget stays a one-line edit; under-budgeting one member does not.
//!
//! Scope is `ci.yaml` deliberately. The release workflows also assemble
//! installers, but on a cold cache and with extra packaging work, so their
//! budget is a separate question and equality with the CI jobs would be wrong.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::ci_coverage::{join_line_continuations, split_commands, step_command};
use crate::manifest::Manifest;

// Minimal `ci.yaml` shape — serde ignores every field we don't name, so this
// tracks only `jobs.<id>.{timeout-minutes,steps[].run}`.

#[derive(Deserialize)]
struct CiYaml {
    jobs: IndexMap<String, Job>,
}

#[derive(Deserialize)]
struct Job {
    #[serde(rename = "timeout-minutes")]
    timeout_minutes: Option<u64>,
    #[serde(default)]
    steps: Vec<CiStep>,
}

#[derive(Deserialize)]
struct CiStep {
    #[serde(default)]
    run: Option<String>,
}

/// Strip one matched pair of surrounding shell quotes.
///
/// [`split_commands`] preserves quote characters, so `cargo xtask build
/// "hole-msi"` yields the token `"hole-msi"`. Comparing that raw against a
/// target name silently drops the command out of every match below — the exact
/// invisible-miss the conformance test exists to prevent.
fn unquote(tok: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = tok.strip_prefix(q).and_then(|t| t.strip_suffix(q)) {
            return inner;
        }
    }
    tok
}

/// Does `cmd` assemble an installer package?
///
/// The signature is `uv run --directory <name>-installer build` — the entry
/// point both `hole-msi` and `hole-dmg` use to hand off to their packaging
/// project. The trailing `build` is load-bearing: `hole-dmg-tests` runs
/// `uv run --directory dmg-installer pytest`, which consumes the package rather
/// than assembling it, and must not be credited on its own.
pub fn assembles_installer(cmd: &str) -> bool {
    let toks: Vec<&str> = cmd.split_whitespace().map(unquote).collect();
    toks.windows(3)
        .any(|w| w[0] == "--directory" && w[1].ends_with("-installer") && w[2] == "build")
}

/// The build.yaml target of a `cargo xtask run <target>` / `cargo xtask build
/// <target>` command, if `cmd` is one. Both spellings enter the same cascade;
/// `test-installer` uses `build`, `test-dmg-signing` uses `run`.
///
/// Errors on a target name carrying a `${{ … }}` expression: it cannot be
/// resolved against build.yaml statically, and silently treating it as
/// "not an installer job" is how a job disappears from the class unnoticed.
pub fn xtask_target(cmd: &str) -> Result<Option<&str>> {
    let toks: Vec<&str> = cmd.split_whitespace().map(unquote).collect();
    let Some(target) = toks
        .windows(4)
        .find(|w| w[0] == "cargo" && w[1] == "xtask" && matches!(w[2], "run" | "build"))
        .map(|w| w[3])
    else {
        return Ok(None);
    };
    if target.contains("${{") {
        bail!(
            "cannot resolve templated xtask target {target:?} in command {cmd:?} — \
             a workflow-expression target defeats static analysis of the build graph"
        );
    }
    Ok(Some(target))
}

/// CI job id → declared `timeout-minutes`, for every job whose xtask cascade
/// transitively assembles an installer package. A `None` value means the job
/// declares no timeout at all (GitHub then applies its 6-hour default, which is
/// never what this class wants).
pub fn installer_assembly_job_timeouts(ci_yaml: &str, manifest: &Manifest) -> Result<BTreeMap<String, Option<u64>>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let mut out = BTreeMap::new();

    for (id, job) in &ci.jobs {
        let mut assembles = false;
        for run in job.steps.iter().filter_map(|s| s.run.as_ref()) {
            for cmd in split_commands(&join_line_continuations(run)) {
                if command_reaches_installer(&cmd, manifest, &mut BTreeSet::new())
                    .with_context(|| format!("in job {id:?}"))?
                {
                    assembles = true;
                }
            }
        }
        if assembles {
            out.insert(id.clone(), job.timeout_minutes);
        }
    }

    Ok(out)
}

/// Does `cmd` — directly, or through the build.yaml target it invokes and that
/// target's transitive `depends` and nested `cargo xtask` steps — assemble an
/// installer package?
fn command_reaches_installer(cmd: &str, manifest: &Manifest, visited: &mut BTreeSet<String>) -> Result<bool> {
    if assembles_installer(cmd) {
        return Ok(true);
    }
    let Some(target) = xtask_target(cmd)? else {
        return Ok(false);
    };
    target_reaches_installer(target, manifest, visited)
}

/// Walk `target`'s own steps (recursing into any `cargo xtask run|build` they
/// invoke) and its transitive `depends`. `visited` guards against a manifest
/// cycle and against re-walking a diamond dependency.
fn target_reaches_installer(target: &str, manifest: &Manifest, visited: &mut BTreeSet<String>) -> Result<bool> {
    if !visited.insert(target.to_string()) {
        return Ok(false);
    }
    let Some(t) = manifest.get(target) else {
        return Ok(false);
    };

    for step in t.run.iter().chain(t.build.iter()) {
        for cmd in split_commands(&join_line_continuations(&step_command(step))) {
            if command_reaches_installer(&cmd, manifest, visited)? {
                return Ok(true);
            }
        }
    }

    for dep in &t.depends {
        if target_reaches_installer(dep, manifest, visited)? {
            return Ok(true);
        }
    }

    Ok(false)
}
