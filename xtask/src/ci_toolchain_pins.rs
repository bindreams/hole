//! Does every CI step that installs a toolchain name the repo's pin?
//!
//! Backs the `ci_toolchain_steps_name_the_pin` conformance test. Rust and Go
//! are pinned in-tree (`rust-toolchain.toml`, the `toolchain` directive in
//! `crates/ex-ray/go.mod`), but a pin only holds where the installing step
//! actually reads it: `dtolnay/rust-toolchain@stable` and
//! `actions/setup-go` with a bare `go-version` both silently resolve a
//! release at job time, which is how a rustc release turned `main` red on
//! unchanged code.
//!
//! Manual vigilance does not survive a new workflow, so the invariant is
//! structural: any step in `.github/` that installs one of these two
//! toolchains must name where the version comes from. Scope is both shapes
//! that can carry steps — workflow `jobs.<id>.steps[]` and composite-action
//! `runs.steps[]` — because `setup-build` is where most jobs get their
//! toolchain and it is an action, not a workflow.
//!
//! This checks that a step *reads* the pin, not that it reads a particular
//! version: the version itself lives in one file per language, so agreement
//! is by construction once the step points at it.
//!
//! Backs `ci_toolchain_reads_are_checkout_gated` too: naming the pin only
//! matters if the file it names is actually there, so that test additionally
//! checks that a step reading a repository file never runs under a weaker
//! condition than the checkout it depends on (see the "Checkout-gating"
//! section below — this is what closed #859).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

/// The only `go-version-file` a `setup-go` step may name. `go.mod` carries the
/// `toolchain` directive, so `go` on a developer's PATH and CI resolve the
/// same release.
pub const GO_VERSION_FILE: &str = "crates/ex-ray/go.mod";

/// Action repos that install a toolchain, matched on the `owner/name` before
/// any `@ref`.
const SETUP_GO: &str = "actions/setup-go";
const RUST_TOOLCHAIN: &str = "dtolnay/rust-toolchain";

/// Either shape that can carry steps. Serde ignores everything unnamed, so a
/// workflow deserializes with `runs: None` and an action with empty `jobs`.
#[derive(Deserialize)]
struct StepBearing {
    #[serde(default)]
    jobs: IndexMap<String, Steps>,
    #[serde(default)]
    runs: Option<Steps>,
}

#[derive(Deserialize)]
struct Steps {
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "if")]
    if_: Option<String>,
    #[serde(default)]
    uses: Option<String>,
    #[serde(default)]
    run: Option<String>,
    /// Left as raw values: `toolchain:` is usually a `${{ }}` expression, and
    /// we only care that it is present and non-empty.
    #[serde(default)]
    with: Option<BTreeMap<String, serde_yml::Value>>,
}

/// One step that installs a toolchain without naming the pin.
#[derive(Debug, PartialEq, Eq)]
pub struct Unpinned {
    pub file: String,
    pub uses: String,
    pub why: String,
}

/// `owner/name` of an action reference, dropping `@ref` and any subdirectory.
fn action_repo(uses: &str) -> String {
    let no_ref = uses.split('@').next().unwrap_or(uses);
    no_ref.split('/').take(2).collect::<Vec<_>>().join("/")
}

/// The `with:` value for `key` as a string, if present and non-empty.
fn with_str<'a>(step: &'a Step, key: &str) -> Option<&'a str> {
    let raw = step.with.as_ref()?.get(key)?.as_str()?.trim();
    (!raw.is_empty()).then_some(raw)
}

/// Audit one `.github/` YAML document. `file` is used only for reporting.
pub fn audit_document(file: &str, contents: &str) -> Result<Vec<Unpinned>> {
    let doc: StepBearing = serde_yml::from_str(contents).with_context(|| format!("parse {file}"))?;

    let steps = doc.jobs.values().chain(doc.runs.iter()).flat_map(|s| s.steps.iter());

    let mut out = Vec::new();
    for step in steps {
        let Some(uses) = step.uses.as_deref() else {
            continue;
        };
        let repo = action_repo(uses);

        if repo == SETUP_GO {
            match with_str(step, "go-version-file") {
                Some(GO_VERSION_FILE) => {}
                Some(other) => out.push(Unpinned {
                    file: file.to_owned(),
                    uses: uses.to_owned(),
                    why: format!("go-version-file is `{other}`, expected `{GO_VERSION_FILE}`"),
                }),
                None => out.push(Unpinned {
                    file: file.to_owned(),
                    uses: uses.to_owned(),
                    why: format!("no `go-version-file: {GO_VERSION_FILE}` — a bare `go-version` resolves at job time"),
                }),
            }
        }

        if repo == RUST_TOOLCHAIN && with_str(step, "toolchain").is_none() {
            out.push(Unpinned {
                file: file.to_owned(),
                uses: uses.to_owned(),
                why: "no `toolchain:` input — the action's ref alone resolves at job time".to_owned(),
            });
        }
    }
    Ok(out)
}

// Checkout-gating =====================================================================================================
//
// A step naming the pin (above) is only half the invariant: the file it
// reads has to actually be on disk when the step runs. #859 was exactly
// this — a step reading `rust-toolchain.toml` with no `if:` at all, sitting
// right after an `actions/checkout` that *did* have one, so on every run
// where the checkout was skipped the step read a workspace with no
// `rust-toolchain.toml` in it and failed.
//
// The rule: within one job (or one composite action's `runs.steps`), a step
// that reads a repository file must run under the exact same condition as
// the nearest preceding `actions/checkout` step.
//
// What this does not catch --------------------------------------------------------------------------------------------
//
// "Reads a repository file" is not something a shell script declares — it's
// inferred, and the inference has real edges:
//
// - Direct detection is a literal-text match for `rust-toolchain.toml`
//   inside a step's `run:` (the same heuristic the byte-equal-readers check
//   in the test file already relies on). A step that reaches the file
//   through a variable, a wrapper script, or any file other than the one
//   pin this module tracks is invisible to it.
// - Indirect detection follows local composite actions (`uses: ./...`)
//   transitively: if a local action's own steps (directly or through
//   further local actions it calls) read the pin, every call site is
//   treated as a reader too. Only *local* actions are followed — a
//   third-party or `workflow_call` boundary that reads the file internally
//   is invisible to it.
// - The comparison is exact-text equality of the `if:` strings (after
//   trimming), not logical implication. This is deliberately conservative:
//   it accepts only the one shape this repo's call sites actually use (a
//   reader immediately gated on its checkout's own condition, verbatim),
//   and it will false-positive on a reader whose condition is a strictly
//   narrower — but differently worded — subset of its checkout's condition.
//   No such case exists in this repo today; if one shows up, loosen this
//   then, with a test proving the new shape is actually safe.
// - A job with no preceding `actions/checkout` step at all is skipped:
//   there's nothing to compare against, which is correct for a composite
//   action's own `runs.steps` (it always executes inside the caller's
//   already-checked-out workspace).

/// One step that reads (directly or via a local composite action) a
/// repository file under a condition weaker than — or merely different
/// from — the checkout that must produce it.
#[derive(Debug, PartialEq, Eq)]
pub struct UngatedRead {
    pub file: String,
    pub job: String,
    /// The step's `id:`, or failing that its `uses:`, for reporting.
    pub step: String,
    pub step_if: Option<String>,
    pub checkout_if: Option<String>,
}

/// Does this step, by itself, read `rust-toolchain.toml`?
fn step_reads_pin_file_directly(step: &Step) -> bool {
    step.run.as_deref().is_some_and(|r| r.contains("rust-toolchain.toml"))
}

/// Is this step an `actions/checkout` call?
fn is_checkout(step: &Step) -> bool {
    step.uses
        .as_deref()
        .is_some_and(|u| action_repo(u) == "actions/checkout")
}

/// Normalizes a local composite-action `uses:` reference (e.g.
/// `./.github/actions/setup-rust`) to the key used to look it up in the
/// reader graph. Returns `None` for anything that isn't a local path —
/// third-party actions are out of scope (see module doc).
fn local_action_path(uses: &str) -> Option<String> {
    uses.starts_with("./")
        .then(|| uses.split('@').next().unwrap_or(uses).trim_end_matches('/').to_owned())
}

/// Resolves which local composite actions read the Rust toolchain pin file,
/// directly or transitively through calls to other local composite actions.
///
/// `actions` maps each local action's `uses:` key (e.g.
/// `./.github/actions/setup-rust`) to that action's own `action.yaml`
/// contents.
pub fn resolve_local_pin_readers(actions: &BTreeMap<String, String>) -> Result<BTreeMap<String, bool>> {
    let mut graph: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for (key, contents) in actions {
        let doc: StepBearing = serde_yml::from_str(contents).with_context(|| format!("parse {key}"))?;
        let steps = doc.runs.map(|s| s.steps).unwrap_or_default();

        let mut direct = false;
        let mut calls = Vec::new();
        for step in &steps {
            if step_reads_pin_file_directly(step) {
                direct = true;
            }
            if let Some(callee) = step.uses.as_deref().and_then(local_action_path) {
                calls.push(callee);
            }
        }
        graph.insert(key.clone(), (direct, calls));
    }

    let mut reads: BTreeMap<String, bool> = graph.iter().map(|(k, (direct, _))| (k.clone(), *direct)).collect();

    // Fixpoint over the local-action call graph. Bounded by the graph's own
    // size (the number of local actions in the repo), not an arbitrary
    // retry budget — each pass either flips at least one more entry to
    // `true` or the loop breaks, so this always converges in at most
    // `graph.len()` passes.
    for _ in 0..graph.len() {
        let mut changed = false;
        for (key, (_, calls)) in &graph {
            if reads[key] {
                continue;
            }
            if calls.iter().any(|callee| reads.get(callee).copied().unwrap_or(false)) {
                reads.insert(key.clone(), true);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    Ok(reads)
}

/// Audits one `.github/` YAML document for reads gated more weakly than the
/// checkout they depend on. `local_pin_readers` is the graph built by
/// [`resolve_local_pin_readers`] — pass an empty map to only check direct
/// reads.
pub fn audit_checkout_gating(
    file: &str,
    contents: &str,
    local_pin_readers: &BTreeMap<String, bool>,
) -> Result<Vec<UngatedRead>> {
    let doc: StepBearing = serde_yml::from_str(contents).with_context(|| format!("parse {file}"))?;

    let jobs = doc.jobs.iter().map(|(name, steps)| (name.as_str(), steps));
    let composite = doc.runs.iter().map(|steps| ("<composite action>", steps));

    let mut out = Vec::new();
    for (job_name, steps) in jobs.chain(composite) {
        let mut last_checkout_if: Option<Option<String>> = None;

        for step in &steps.steps {
            if is_checkout(step) {
                last_checkout_if = Some(step.if_.as_deref().map(str::trim).map(str::to_owned));
                continue;
            }

            let reads_pin = step_reads_pin_file_directly(step)
                || step
                    .uses
                    .as_deref()
                    .and_then(local_action_path)
                    .is_some_and(|callee| local_pin_readers.get(&callee).copied().unwrap_or(false));
            if !reads_pin {
                continue;
            }

            let Some(checkout_if) = &last_checkout_if else {
                continue;
            };

            let step_if = step.if_.as_deref().map(str::trim).map(str::to_owned);
            if &step_if != checkout_if {
                out.push(UngatedRead {
                    file: file.to_owned(),
                    job: job_name.to_owned(),
                    step: step.id.clone().or_else(|| step.uses.clone()).unwrap_or_default(),
                    step_if,
                    checkout_if: checkout_if.clone(),
                });
            }
        }
    }

    Ok(out)
}
