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
    uses: Option<String>,
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
