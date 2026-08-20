//! Does every CI-facing workflow/action reach its Rust or Go compiler through
//! the pinned files (`rust-toolchain.toml`, `crates/ex-ray/go.mod`), or does
//! one float?
//!
//! Backs the `toolchain_pin_*` conformance tests. Pinning the toolchains once
//! (#855) does not stop the next workflow edit from reintroducing a float —
//! a fresh `dtolnay/rust-toolchain@stable` step, a `go-version: stable`, or a
//! `GOTOOLCHAIN`/`RUSTUP_TOOLCHAIN` env override all silently undo it. These
//! scanners parse `.github/**` with `serde_yml` (not a text/regex scan — see
//! [`steps_of`]'s doc for why) and fail loudly when one appears.
//!
//! **Scope: the Rust and Go compiler toolchains only**, and only within
//! `.github/workflows/**` plus every `action.y[a]ml` under `.github/`. Not
//! covered, and still able to float: the runner images themselves
//! (`windows-latest` and friends — what actually delivered Go 1.27 and Rust
//! 1.98 on 2026-08-16, and not something Renovate can manage), `python-version:
//! "3.x"`, unpinned `uv tool install prek`, unpinned `taiki-e/install-action`
//! tool versions, `brew install bash`, `uv run --with …`, GitHub Action tags
//! floating within a major, the golangci-lint version constant in
//! `xtask/src/golangci_lint.rs`, and `prek.toml`'s hook `rev` pins. A reader
//! relying on this module for toolchain hygiene should keep looking past it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

/// One step from either a workflow job (`jobs.<id>.steps[]`) or a composite
/// action (`runs.steps[]`). `with`/`env` are left as [`serde_yml::Value`] so a
/// flow mapping (`with: { go-version: stable }`) parses identically to a block
/// mapping — YAML's flow and block forms are the same data model, so no
/// special-casing is needed.
#[derive(Deserialize)]
pub struct Step {
    #[serde(default)]
    pub uses: Option<String>,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default)]
    pub with: BTreeMap<String, serde_yml::Value>,
    #[serde(default)]
    pub env: BTreeMap<String, serde_yml::Value>,
}

/// Where an `env:` block was found. `GOTOOLCHAIN`/`RUSTUP_TOOLCHAIN` set at
/// any of these scopes applies to every `go`/`cargo`/`rustup` invocation
/// beneath it, overriding the pinned file at every call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvScope {
    /// The workflow document's top-level `env:`.
    Workflow,
    /// `jobs.<id>.env:`.
    Job(String),
    /// A single step's `env:`, indexed the same way [`steps_of`] flattens
    /// steps: in document order, jobs before `runs.steps`.
    Step(usize),
}

impl std::fmt::Display for EnvScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvScope::Workflow => write!(f, "workflow"),
            EnvScope::Job(id) => write!(f, "job {id}"),
            EnvScope::Step(i) => write!(f, "{i}"),
        }
    }
}

#[derive(Deserialize, Default)]
struct JobDoc {
    #[serde(default)]
    steps: Vec<Step>,
    #[serde(default)]
    env: BTreeMap<String, serde_yml::Value>,
}

#[derive(Deserialize, Default)]
struct RunsDoc {
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    env: BTreeMap<String, serde_yml::Value>,
    #[serde(default)]
    jobs: Option<IndexMap<String, JobDoc>>,
    #[serde(default)]
    runs: Option<RunsDoc>,
}

/// Every step in `yaml`, flattened in document order: each job's steps (jobs
/// in file order), then a composite action's `runs.steps`. A file is either a
/// workflow or a composite action, never both, but reading both shapes here
/// means one walk covers either.
pub fn steps_of(yaml: &str) -> Result<Vec<Step>> {
    let doc: Doc = serde_yml::from_str(yaml).context("parsing steps")?;
    let mut out = Vec::new();
    if let Some(jobs) = doc.jobs {
        for job in jobs.into_values() {
            out.extend(job.steps);
        }
    }
    if let Some(runs) = doc.runs {
        out.extend(runs.steps);
    }
    Ok(out)
}

/// Every `env:` block in `yaml` with the scope it applies to: the document
/// root, each `jobs.<id>`, and each step (indexed as [`steps_of`] flattens
/// them). `env` is not a step-only key — a workflow- or job-level override
/// reaches every step beneath it, so a `Vec<Step>` alone cannot represent it.
pub fn env_scopes_of(yaml: &str) -> Result<Vec<(EnvScope, BTreeMap<String, serde_yml::Value>)>> {
    let doc: Doc = serde_yml::from_str(yaml).context("parsing env scopes")?;
    let mut out = vec![(EnvScope::Workflow, doc.env)];
    let mut step_index = 0usize;
    if let Some(jobs) = &doc.jobs {
        for (id, job) in jobs {
            out.push((EnvScope::Job(id.clone()), job.env.clone()));
            for step in &job.steps {
                out.push((EnvScope::Step(step_index), step.env.clone()));
                step_index += 1;
            }
        }
    }
    if let Some(runs) = &doc.runs {
        for step in &runs.steps {
            out.push((EnvScope::Step(step_index), step.env.clone()));
            step_index += 1;
        }
    }
    Ok(out)
}

/// Every workflow (`.github/workflows/**/*.y[a]ml`) plus every composite
/// action (`action.yaml`/`action.yml`, anywhere under `.github/` — a local
/// action can live at any path, so this is recursive rather than a one-level
/// `.github/actions/*/` glob). Deliberately excludes the rest of `.github/`
/// (e.g. `release-categories.yaml`, whose top-level key is `categories:`, not
/// `jobs:`/`runs:`) — those aren't CI config and this module doesn't scan them.
///
/// Every file this DOES collect must parse and carry a top-level `jobs:` or
/// `runs:`; one that has neither is a hard error, never a silent skip — a
/// workflow or action that fails to look like one is more likely a real bug
/// than an intentional exclusion.
pub fn ci_config_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = std::collections::BTreeSet::new();
    for pattern in [
        ".github/workflows/**/*.yaml",
        ".github/workflows/**/*.yml",
        ".github/**/action.yaml",
        ".github/**/action.yml",
    ] {
        let abs_pattern = repo_root.join(pattern);
        let pattern_str = abs_pattern
            .to_str()
            .with_context(|| format!("glob pattern is not valid UTF-8: {abs_pattern:?}"))?;
        for entry in glob::glob(pattern_str).with_context(|| format!("invalid glob pattern: {pattern_str}"))? {
            files.insert(entry?);
        }
    }

    #[derive(Deserialize, Default)]
    struct WorkflowOrActionShape {
        #[serde(default)]
        jobs: Option<serde_yml::Value>,
        #[serde(default)]
        runs: Option<serde_yml::Value>,
    }

    for file in &files {
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let doc: WorkflowOrActionShape =
            serde_yml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
        if doc.jobs.is_none() && doc.runs.is_none() {
            bail!(
                "{} is under .github/ and matched the workflow/action glob, but has neither a \
                 top-level `jobs:` nor `runs:` — ci_config_files only scans workflows and \
                 composite actions",
                file.display()
            );
        }
    }

    Ok(files.into_iter().collect())
}

/// The one file every other scanner in this module treats as sanctioned: the
/// sole place allowed to install a Rust toolchain directly (Task 3's
/// `setup-rust` composite action). Compared by suffix so it matches
/// regardless of the absolute prefix `ci_config_files` returns.
const SANCTIONED_RUST_INSTALLER: &str = ".github/actions/setup-rust/action.yaml";

fn is_sanctioned_rust_installer(file: &Path) -> bool {
    file.to_string_lossy()
        .replace('\\', "/")
        .ends_with(SANCTIONED_RUST_INSTALLER)
}

/// Does `step` install a Rust toolchain, by any mechanism this module knows:
/// the two GitHub Actions that do it (`dtolnay/rust-toolchain`,
/// `actions-rust-lang/setup-rust-toolchain`), or a hand-rolled `rustup
/// toolchain install` in a `run:` step.
fn installs_rust_toolchain(step: &Step) -> bool {
    if let Some(uses) = step.uses.as_deref() {
        let base = uses.split('@').next().unwrap_or(uses);
        if base.eq_ignore_ascii_case("dtolnay/rust-toolchain")
            || base.eq_ignore_ascii_case("actions-rust-lang/setup-rust-toolchain")
        {
            return true;
        }
    }
    if let Some(run) = step.run.as_deref() {
        if run.contains("rustup toolchain install") {
            return true;
        }
    }
    false
}

/// Every file among `files` containing at least one step that installs a Rust
/// toolchain by any mechanism [`installs_rust_toolchain`] recognises —
/// including the sanctioned one. Asserted elsewhere to be exactly the one
/// file that is allowed to do this.
pub fn files_installing_a_rust_toolchain(files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for file in files {
        let yaml = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let steps = steps_of(&yaml).with_context(|| format!("parsing steps in {}", file.display()))?;
        if steps.iter().any(installs_rust_toolchain) {
            out.push(file.clone());
        }
    }
    Ok(out)
}

/// Every `"<file>:<step index>"` among `files`, excluding
/// [`SANCTIONED_RUST_INSTALLER`], where a step installs a Rust toolchain by
/// hand instead of delegating to `setup-rust` — a raw `rustup toolchain
/// install`, or a direct use of `dtolnay/rust-toolchain` /
/// `actions-rust-lang/setup-rust-toolchain` outside the one file that is
/// allowed to.
pub fn hand_rolled_rust_toolchain_sites(files: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for file in files {
        if is_sanctioned_rust_installer(file) {
            continue;
        }
        let yaml = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let steps = steps_of(&yaml).with_context(|| format!("parsing steps in {}", file.display()))?;
        for (i, step) in steps.iter().enumerate() {
            if installs_rust_toolchain(step) {
                out.push(format!("{}:{i}", file.display()));
            }
        }
    }
    Ok(out)
}

/// The `go` directive CI is meant to target: `crates/ex-ray/go.mod`'s own,
/// via `go-version-file`. The only value `floating_go_sites` accepts.
const EX_RAY_GO_MOD: &str = "crates/ex-ray/go.mod";

fn is_setup_go_step(step: &Step) -> bool {
    step.uses
        .as_deref()
        .is_some_and(|uses| uses.split('@').next().unwrap_or(uses) == "actions/setup-go")
}

/// Every `"<file>:<step index>"` among `files` where an `actions/setup-go`
/// step does not pin to `crates/ex-ray/go.mod`: it names a bare `go-version`,
/// points `go-version-file` somewhere else (e.g. a vendored `third_party`
/// tree's `go.mod`, which Renovate does not manage — see
/// `.github/renovate.json`), or gives neither key.
pub fn floating_go_sites(files: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for file in files {
        let yaml = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let steps = steps_of(&yaml).with_context(|| format!("parsing steps in {}", file.display()))?;
        for (i, step) in steps.iter().enumerate() {
            if !is_setup_go_step(step) {
                continue;
            }
            let floats = if step.with.contains_key("go-version") {
                true
            } else if let Some(v) = step.with.get("go-version-file") {
                v.as_str() != Some(EX_RAY_GO_MOD)
            } else {
                true
            };
            if floats {
                out.push(format!("{}:{i}", file.display()));
            }
        }
    }
    Ok(out)
}

const TOOLCHAIN_ENV_KEYS: [&str; 2] = ["GOTOOLCHAIN", "RUSTUP_TOOLCHAIN"];

/// Every `"<file>:<scope>"` among `files` where a `GOTOOLCHAIN` or
/// `RUSTUP_TOOLCHAIN` env override exists at any scope [`env_scopes_of`]
/// walks. Either variable overrides the pinned file at every invocation
/// beneath its scope, so this is a complete bypass regardless of level.
pub fn toolchain_env_sites(files: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for file in files {
        let yaml = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let scopes = env_scopes_of(&yaml).with_context(|| format!("parsing env scopes in {}", file.display()))?;
        for (scope, env) in scopes {
            if TOOLCHAIN_ENV_KEYS.iter().any(|k| env.contains_key(*k)) {
                out.push(format!("{}:{scope}", file.display()));
            }
        }
    }
    Ok(out)
}

/// The `run:` bodies of `action_yaml`'s non-`uses` steps, in order. Used to
/// confirm the sanctioned Rust installer actually reads the pin file rather
/// than merely looking like it does (`with.toolchain` being an expression
/// proves nothing about what that expression evaluates from).
pub fn pin_step_scripts(action_yaml: &str) -> Result<Vec<String>> {
    let steps = steps_of(action_yaml)?;
    Ok(steps
        .into_iter()
        .filter(|s| s.uses.is_none())
        .filter_map(|s| s.run)
        .collect())
}
