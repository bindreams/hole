//! Which `.github/workflows/ci.yaml` steps assemble a release installer, what
//! timeout budget does each carry, and does every step of the unified `ci` job
//! carry one?
//!
//! Backs the `ci_installer_assembly_steps_share_a_timeout_budget`,
//! `ci_steps_declare_a_literal_timeout` and
//! `ci_step_budgets_sit_on_the_five_minute_grid` conformance tests. Assembling an
//! installer is the most expensive thing CI does — a full release build of
//! `hole`, then the bundler, then the package's own test suite — so those steps
//! sit closest to their `timeout-minutes`. When two of them do that same work
//! but disagree on the budget, the smaller one is killed mid-compile on the
//! slower runner while its sibling passes.
//!
//! The test asserts EQUALITY, not a floor: there is no defensible magic number
//! for "long enough", but there is a defensible invariant that steps doing the
//! same work get the same budget. Raising the class budget stays a one-line
//! edit; under-budgeting one member does not.
//!
//! Budgets live on steps, not on the job: the unified job's own
//! `timeout-minutes` is a per-leg matrix expression (the wall), and a step with
//! no bound of its own runs to that wall, which cancels every lane after it.
//!
//! Scope is `ci.yaml` deliberately. The release workflows also assemble
//! installers, but on a cold cache and with extra packaging work, so their
//! budget is a separate question and equality with the CI steps would be wrong.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::ci_coverage::{join_line_continuations, split_commands, step_command, unquote};
use crate::manifest::Manifest;

// Minimal `ci.yaml` shape — serde ignores every field we don't name, so this
// tracks only `jobs.<id>.steps[].{id,name,run,timeout-minutes}`.

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
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    run: Option<String>,
    /// Left uninterpreted so an unexpected scalar on an unrelated step cannot
    /// abort the whole document — see [`resolve_timeout`].
    #[serde(default, rename = "timeout-minutes")]
    timeout_minutes: Option<serde_yml::Value>,
}

impl CiStep {
    /// The step's identity in a report: its `id`, else its `name`, else its
    /// position. Every step has one of the three.
    fn label(&self, index: usize) -> String {
        self.id
            .clone()
            .or_else(|| self.name.clone())
            .unwrap_or_else(|| format!("steps[{index}]"))
    }
}

/// A declared `timeout-minutes` as a literal minute count.
///
/// GitHub accepts a number or a workflow expression here. An expression cannot
/// be compared against a sibling statically, so it is an error for a step in
/// the class — but only there, which is why the value is interpreted at use
/// rather than at deserialization.
///
/// Classification is on the `${{` syntax, matching [`xtask_target`], not on
/// which serde shape the scalar took: `"60"` is a quoted literal, not an
/// expression.
fn resolve_timeout(label: &str, value: &serde_yml::Value) -> Result<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    if let Some(s) = value.as_str() {
        if s.contains("${{") {
            bail!(
                "step {label:?} declares timeout-minutes as the expression {s:?} — \
                 it cannot be compared against its siblings' budgets statically"
            );
        }
        if let Ok(n) = s.parse::<u64>() {
            return Ok(n);
        }
    }
    bail!("step {label:?} declares timeout-minutes as {value:?}, which is not a whole number of minutes")
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
/// the MSI step uses `build`, the DMG step `run`.
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

/// (job id, step label) → declared `timeout-minutes`, for every step whose xtask
/// cascade transitively assembles an installer package. A `None` value means
/// the step declares no timeout at all (it then runs to the job wall, which is
/// never what this class wants).
pub fn installer_assembly_step_timeouts(
    ci_yaml: &str,
    manifest: &Manifest,
) -> Result<BTreeMap<(String, String), Option<u64>>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let mut out = BTreeMap::new();

    for (job_id, job) in &ci.jobs {
        for (i, step) in job.steps.iter().enumerate() {
            let Some(run) = &step.run else { continue };
            let label = step.label(i);
            let mut assembles = false;
            for cmd in split_commands(&join_line_continuations(run)) {
                if command_reaches_installer(&cmd, manifest, &mut BTreeSet::new())
                    .with_context(|| format!("in step {label:?} of job {job_id:?}"))?
                {
                    assembles = true;
                }
            }
            if !assembles {
                continue;
            }
            let minutes = step
                .timeout_minutes
                .as_ref()
                .map(|v| resolve_timeout(&label, v))
                .transpose()?;
            out.insert((job_id.clone(), label), minutes);
        }
    }

    Ok(out)
}

/// Step label → declared `timeout-minutes`, for the steps of `job_id` that
/// declare a literal one.
pub fn step_timeouts(ci_yaml: &str, job_id: &str) -> Result<BTreeMap<String, u64>> {
    Ok(step_timeouts_in_order(ci_yaml, job_id)?.into_iter().collect())
}

/// [`step_timeouts`] in file order.
fn step_timeouts_in_order(ci_yaml: &str, job_id: &str) -> Result<Vec<(String, u64)>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = ci
        .jobs
        .get(job_id)
        .with_context(|| format!("ci.yaml declares no job {job_id:?}"))?;
    let mut out = Vec::new();
    for (i, step) in job.steps.iter().enumerate() {
        let label = step.label(i);
        if let Some(Ok(minutes)) = step.timeout_minutes.as_ref().map(|v| resolve_timeout(&label, v)) {
            out.push((label, minutes));
        }
    }
    Ok(out)
}

/// Labels of the steps of `job_id` that declare no literal `timeout-minutes` —
/// absent, an expression, or not a whole number. A step with no bound of its
/// own runs to the job wall, and a wall that fires destroys the step's log
/// (#989). `uses:` steps count: they hang too.
pub fn steps_without_literal_timeout(ci_yaml: &str, job_id: &str) -> Result<Vec<String>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = ci
        .jobs
        .get(job_id)
        .with_context(|| format!("ci.yaml declares no job {job_id:?}"))?;

    Ok(job
        .steps
        .iter()
        .enumerate()
        .filter(|(i, step)| {
            let label = step.label(*i);
            !step
                .timeout_minutes
                .as_ref()
                .is_some_and(|v| resolve_timeout(&label, v).is_ok())
        })
        .map(|(i, step)| step.label(i))
        .collect())
}

/// The step-budget granule in `ci.yaml`'s header: budgets round up to it, and a
/// step measured under four minutes gets one granule.
const BUDGET_GRID: u64 = 5;

/// (label, minutes) of the steps of `job_id` whose literal `timeout-minutes`
/// is below `BUDGET_GRID` or not a multiple of it, against the step-budget
/// rule in `ci.yaml`'s header. A step with no literal budget is not named here;
/// [`steps_without_literal_timeout`] reports it.
pub fn steps_off_the_budget_grid(ci_yaml: &str, job_id: &str) -> Result<Vec<(String, u64)>> {
    Ok(step_timeouts_in_order(ci_yaml, job_id)?
        .into_iter()
        .filter(|(_, minutes)| *minutes < BUDGET_GRID || minutes % BUDGET_GRID != 0)
        .collect())
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
