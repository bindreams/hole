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
//! section below).

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
    name: Option<String>,
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
// reads has to actually be on disk when the step runs. The rule has two
// independent shapes:
//
//   1. a step that reads a pin file directly (or via a local composite
//      action that does) must run under the same condition as the nearest
//      preceding `actions/checkout` that puts the file at the workspace
//      root — and no such checkout at all, in a workflow job, is itself a
//      violation, not an exemption;
//   2. a step that consumes another step's `steps.<id>.outputs.*` — e.g. an
//      install step reading the toolchain a read step produced — must run
//      under the same condition as that producer step, independent of any
//      checkout.
//
// What this does not catch --------------------------------------------------------------------------------------------
//
// "Reads a repository file" is not something a shell script declares — it's
// inferred, and the inference has real edges:
//
// - Direct detection matches a literal `rust-toolchain.toml` in a step's
//   `run:`, or a `go-version-file:`/`node-version-file:` input naming a real
//   path rather than a `${{ }}` expression. A step reaching a pin file
//   through a variable, a wrapper script, or any file this module doesn't
//   track is invisible to it.
// - Indirect detection follows local composite actions (`uses: ./...`)
//   transitively: if a local action's own steps (directly, or through
//   further local actions it calls) read a pin, every call site is treated
//   as a reader too. Only *local* actions are followed — a third-party
//   action or a `workflow_call` boundary that reads a pin internally is
//   invisible to it.
// - The output-consumer shape (2, above) is a literal-text search for
//   `steps.<id>.outputs` in a step's `run:` or `with:` values. A consumer
//   that reaches the same data some other way (threaded through an `env:`
//   var by an intermediate wrapper action, say) is invisible to it.
// - Both comparisons are exact-text equality of the `if:` expression, after
//   stripping one enclosing `${{ }}` and collapsing whitespace (GitHub
//   Actions treats `if: X` and `if: ${{ X }}` identically, and this repo
//   mixes both styles), not logical implication. This is deliberately
//   conservative: it accepts only the shape this repo's call sites actually
//   use (a reader gated on the exact same condition as what it depends on),
//   and it will false-positive on a condition that is a strictly narrower —
//   but semantically distinct — subset. No such case exists in this repo
//   today; if one shows up, loosen this then, with a test proving the new
//   shape is actually safe.
// - A checkout is only a valid baseline for a root-relative read when it
//   actually puts the tree there: one with `path:`, `repository:`, or
//   `sparse-checkout:` doesn't establish (or re-establish) the baseline.

/// One step whose read of a pin file — or of another step's output derived
/// from one — runs under a condition that doesn't match what it depends on.
#[derive(Debug, PartialEq, Eq)]
pub struct UngatedRead {
    pub file: String,
    pub job: String,
    /// The step's `id:`, its `name:`, or failing both its `uses:`.
    pub step: String,
    pub step_if: Option<String>,
    /// The condition of whatever this step depends on: a checkout's `if:`,
    /// or (for an output consumer) the producer step's `if:`. `None` when a
    /// workflow job reads a pin file with no checkout preceding it at all.
    pub depends_on_if: Option<String>,
}

/// Does this step, by itself, read a tracked pin file: `rust-toolchain.toml`
/// via `run:`, or a `go-version-file:`/`node-version-file:` input naming a
/// real path rather than a `${{ }}` expression?
fn step_reads_pin_file_directly(step: &Step) -> bool {
    if step.run.as_deref().is_some_and(|r| r.contains("rust-toolchain.toml")) {
        return true;
    }
    ["go-version-file", "node-version-file"]
        .iter()
        .any(|key| with_str(step, key).is_some_and(|v| !v.contains("${{")))
}

/// Is this step an `actions/checkout` call?
fn is_checkout(step: &Step) -> bool {
    step.uses
        .as_deref()
        .is_some_and(|u| action_repo(u) == "actions/checkout")
}

/// Does this `actions/checkout` step put the tree at the workspace root? A
/// `path:`, `repository:`, or `sparse-checkout:` input means the tree (or a
/// subset of it) lands somewhere a root-relative read doesn't expect.
fn checkout_covers_root(step: &Step) -> bool {
    let Some(with) = step.with.as_ref() else {
        return true;
    };
    !["path", "repository", "sparse-checkout"]
        .iter()
        .any(|key| with.contains_key(*key))
}

/// Normalizes a local composite-action `uses:` reference (e.g.
/// `./.github/actions/setup-rust`) to the key used to look it up in the
/// reader graph. Returns `None` for anything that isn't a local path —
/// third-party actions are out of scope (see module doc).
fn local_action_path(uses: &str) -> Option<String> {
    uses.starts_with("./")
        .then(|| uses.split('@').next().unwrap_or(uses).trim_end_matches('/').to_owned())
}

/// Does this step's `run:` or any `with:` value reference
/// `steps.<id>.outputs`?
fn step_references_output_of(step: &Step, id: &str) -> bool {
    let needle = format!("steps.{id}.outputs");
    if step.run.as_deref().is_some_and(|r| r.contains(&needle)) {
        return true;
    }
    step.with
        .as_ref()
        .is_some_and(|with| with.values().any(|v| yaml_value_contains(v, &needle)))
}

/// Recursively searches a YAML value for a substring — `with:` values are
/// sometimes lists or maps, not just strings.
fn yaml_value_contains(value: &serde_yml::Value, needle: &str) -> bool {
    match value {
        serde_yml::Value::String(s) => s.contains(needle),
        serde_yml::Value::Sequence(seq) => seq.iter().any(|v| yaml_value_contains(v, needle)),
        serde_yml::Value::Mapping(map) => map.values().any(|v| yaml_value_contains(v, needle)),
        _ => false,
    }
}

/// Normalizes an `if:` expression for comparison: strips one enclosing
/// `${{ ... }}` (GitHub Actions treats `if: X` and `if: ${{ X }}`
/// identically) and collapses whitespace runs to a single space.
fn normalize_if_expr(raw: &str) -> String {
    let trimmed = raw.trim();
    let unwrapped = trimmed
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .map(str::trim)
        .unwrap_or(trimmed);
    unwrapped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Do two `if:` conditions (each `None` when the step carries no `if:` at
/// all) gate on the same thing?
fn if_conditions_match(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => normalize_if_expr(x) == normalize_if_expr(y),
        _ => false,
    }
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

/// Audits one `.github/` YAML document for reads gated more weakly than what
/// they depend on (a checkout, or another step's output). `local_pin_readers`
/// is the graph built by [`resolve_local_pin_readers`] — pass an empty map to
/// only check direct reads.
pub fn audit_checkout_gating(
    file: &str,
    contents: &str,
    local_pin_readers: &BTreeMap<String, bool>,
) -> Result<Vec<UngatedRead>> {
    let doc: StepBearing = serde_yml::from_str(contents).with_context(|| format!("parse {file}"))?;

    let jobs = doc.jobs.iter().map(|(name, steps)| (name.as_str(), steps, false));
    let composite = doc.runs.iter().map(|steps| ("<composite action>", steps, true));

    let mut out = Vec::new();
    for (job_name, steps, is_composite) in jobs.chain(composite) {
        let mut last_checkout_if: Option<Option<String>> = None;
        let mut reader_if: BTreeMap<String, Option<String>> = BTreeMap::new();

        for step in &steps.steps {
            if is_checkout(step) {
                if checkout_covers_root(step) {
                    last_checkout_if = Some(step.if_.as_deref().map(str::trim).map(str::to_owned));
                }
                continue;
            }

            let step_if = step.if_.as_deref().map(str::trim).map(str::to_owned);
            let step_label = || -> String {
                step.id
                    .clone()
                    .or_else(|| step.name.clone())
                    .or_else(|| step.uses.clone())
                    .unwrap_or_else(|| "<unnamed step>".to_owned())
            };

            // Shape 1: reads a pin file directly, or via a local action known to.
            let reads_pin_directly = step_reads_pin_file_directly(step)
                || step
                    .uses
                    .as_deref()
                    .and_then(local_action_path)
                    .is_some_and(|callee| local_pin_readers.get(&callee).copied().unwrap_or(false));

            if reads_pin_directly {
                match &last_checkout_if {
                    Some(checkout_if) if !if_conditions_match(&step_if, checkout_if) => {
                        out.push(UngatedRead {
                            file: file.to_owned(),
                            job: job_name.to_owned(),
                            step: step_label(),
                            step_if: step_if.clone(),
                            depends_on_if: checkout_if.clone(),
                        });
                    }
                    Some(_) => {}
                    // A workflow job with no checkout at all before this point has an
                    // empty workspace — always a violation. A composite action's own
                    // steps always run in the caller's already-checked-out workspace,
                    // so there's nothing to compare against.
                    None if !is_composite => {
                        out.push(UngatedRead {
                            file: file.to_owned(),
                            job: job_name.to_owned(),
                            step: step_label(),
                            step_if: step_if.clone(),
                            depends_on_if: None,
                        });
                    }
                    None => {}
                }

                if let Some(id) = &step.id {
                    reader_if.insert(id.clone(), step_if.clone());
                }
            }

            // Shape 2: consumes a known reader's output, independent of any checkout.
            if let Some((_, producer_if)) = reader_if.iter().find(|(id, _)| step_references_output_of(step, id)) {
                if !if_conditions_match(&step_if, producer_if) {
                    out.push(UngatedRead {
                        file: file.to_owned(),
                        job: job_name.to_owned(),
                        step: step_label(),
                        step_if: step_if.clone(),
                        depends_on_if: producer_if.clone(),
                    });
                }
            }
        }
    }

    Ok(out)
}
