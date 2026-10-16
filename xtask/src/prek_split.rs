//! Which prek hooks run once, and which on every platform.
//!
//! The unified `ci` job runs the hooks whose verdict is the same on any host
//! once, in the linux/amd64 leg (`portable`), and the hooks that depend on the
//! host in every leg (`platform-dependent`, today golangci-lint, which
//! type-checks under the host's `GOOS`). `.github/lint.toml` lists the
//! platform-dependent hooks; every other hook is portable by default, so a new
//! hook is checked once without being named anywhere. Both runs are derived
//! from that one list, and a listed id that `prek.toml` does not have is an
//! error rather than a hook that quietly never runs.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use clap::ValueEnum;
use serde::Deserialize;

/// The hook the per-leg `clippy-*` steps run instead of prek, so neither prek
/// run does.
pub const CLIPPY_HOOK: &str = "cargo-clippy";

/// Which of the two derived runs to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrekRun {
    /// Every hook that is not platform-dependent (run once).
    Portable,
    /// The platform-dependent hooks (run on every leg).
    PlatformDependent,
}

/// Every hook id `prek.toml` configures, from both `[[repos.hooks]]` tables and
/// inline `hooks = [ ... ]` arrays. A hook configured twice (the two `mdformat`
/// environments) is one id.
pub fn hook_ids(prek_toml: &str) -> Result<BTreeSet<String>> {
    let doc: toml::Table = prek_toml.parse().context("parsing prek.toml")?;
    let repos = doc
        .get("repos")
        .and_then(toml::Value::as_array)
        .context("prek.toml has no [[repos]]")?;
    let mut out = BTreeSet::new();
    for repo in repos {
        let hooks = repo.get("hooks").and_then(toml::Value::as_array).into_iter().flatten();
        for hook in hooks {
            let id = hook
                .get("id")
                .and_then(toml::Value::as_str)
                .context("a prek.toml hook has no string `id`")?;
            out.insert(id.to_string());
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LintToml {
    #[serde(rename = "platform-dependent")]
    platform_dependent: Vec<String>,
}

/// The split read from `.github/lint.toml` and checked against `prek.toml`.
#[derive(Debug)]
pub struct LintSplit {
    platform_dependent: Vec<String>,
}

impl LintSplit {
    /// Parse `lint_toml` and require every listed id to be a hook of `prek_toml`.
    pub fn parse(lint_toml: &str, prek_toml: &str) -> Result<Self> {
        let parsed: LintToml = toml::from_str(lint_toml).context("parsing .github/lint.toml")?;
        let hooks = hook_ids(prek_toml)?;
        ensure!(
            hooks.contains(CLIPPY_HOOK),
            "prek.toml has no {CLIPPY_HOOK:?} hook, which the portable run skips by id"
        );
        let mut platform_dependent: Vec<String> = Vec::new();
        for id in parsed.platform_dependent {
            ensure!(
                hooks.contains(&id),
                ".github/lint.toml lists {id:?} as platform-dependent, but prek.toml has no such hook"
            );
            ensure!(
                id != CLIPPY_HOOK,
                ".github/lint.toml lists {CLIPPY_HOOK:?}, which the per-leg clippy steps already run"
            );
            if !platform_dependent.contains(&id) {
                platform_dependent.push(id);
            }
        }
        Ok(Self { platform_dependent })
    }

    /// The listed hook ids, in file order.
    pub fn platform_dependent(&self) -> &[String] {
        &self.platform_dependent
    }

    /// Arguments of the `prek` call that runs every other hook.
    pub fn portable_args(&self) -> Vec<String> {
        let mut args: Vec<String> = ["run", "--all-files", "--show-diff-on-failure"]
            .map(String::from)
            .into();
        for id in std::iter::once(CLIPPY_HOOK).chain(self.platform_dependent.iter().map(String::as_str)) {
            args.extend(["--skip".to_string(), id.to_string()]);
        }
        args
    }

    /// Arguments of the `prek` call that runs the listed hooks; `None` when the
    /// list is empty (a bare `prek run` would run every hook).
    pub fn platform_dependent_args(&self) -> Option<Vec<String>> {
        if self.platform_dependent.is_empty() {
            return None;
        }
        let mut args = vec!["run".to_string()];
        args.extend(self.platform_dependent.iter().cloned());
        args.extend(["--all-files".to_string(), "--show-diff-on-failure".to_string()]);
        Some(args)
    }
}

/// Perform `which` against the repository at `repo_root`.
pub fn run(which: PrekRun, repo_root: &Path) -> Result<()> {
    let read = |rel: &str| std::fs::read_to_string(repo_root.join(rel)).with_context(|| format!("reading {rel}"));
    let split = LintSplit::parse(&read(".github/lint.toml")?, &read("prek.toml")?)?;
    let args = match which {
        PrekRun::Portable => split.portable_args(),
        PrekRun::PlatformDependent => match split.platform_dependent_args() {
            Some(args) => args,
            None => {
                println!("xtask: .github/lint.toml lists no platform-dependent hook; nothing to run");
                return Ok(());
            }
        },
    };
    println!("xtask: prek {}", args.join(" "));
    let mut cmd = Command::new("prek");
    let status = cmd
        .args(&args)
        .current_dir(repo_root)
        .status()
        .context("running prek (is it installed? `uv tool install prek`)")?;
    if !status.success() {
        bail!("prek {} failed: {status}", args.join(" "));
    }
    Ok(())
}
