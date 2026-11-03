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

use anyhow::{ensure, Context, Result};
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

impl LintSplit {
    /// `prek install-hooks` over the hooks [`Self::portable_args`] runs.
    pub fn portable_prepare_args(&self) -> Vec<String> {
        prepare_args(&self.portable_args())
    }

    /// `prek install-hooks` over the hooks [`Self::platform_dependent_args`] runs.
    pub fn platform_dependent_prepare_args(&self) -> Option<Vec<String>> {
        self.platform_dependent_args().map(|args| prepare_args(&args))
    }
}

/// The `install-hooks` call covering the same hooks as the `run` call `run_args`.
fn prepare_args(run_args: &[String]) -> Vec<String> {
    std::iter::once("install-hooks".to_string())
        .chain(
            run_args
                .iter()
                .skip(1)
                .filter(|a| !matches!(a.as_str(), "--all-files" | "--show-diff-on-failure"))
                .cloned(),
        )
        .collect()
}

/// Perform `which` against the repository at `repo_root`.
pub fn run(which: PrekRun, repo_root: &Path) -> Result<()> {
    run_with(which, repo_root, &mut |args| run_prek(args, repo_root))
}

/// [`run`] with the `prek` invocation as a parameter, so the order and retrying of its calls can be checked.
pub(crate) fn run_with(which: PrekRun, repo_root: &Path, prek: &mut dyn FnMut(&[String]) -> Result<()>) -> Result<()> {
    let read = |rel: &str| std::fs::read_to_string(repo_root.join(rel)).with_context(|| format!("reading {rel}"));
    let split = LintSplit::parse(&read(".github/lint.toml")?, &read("prek.toml")?)?;
    let (prepare, args) = match which {
        PrekRun::Portable => (split.portable_prepare_args(), split.portable_args()),
        PrekRun::PlatformDependent => {
            match (split.platform_dependent_prepare_args(), split.platform_dependent_args()) {
                (Some(prepare), Some(args)) => (prepare, args),
                _ => {
                    println!("xtask: .github/lint.toml lists no platform-dependent hook; nothing to run");
                    return Ok(());
                }
            }
        }
    };
    // A config prek cannot parse fails the same way on every attempt, so check it
    // locally before the retry loop below.
    prek(&["validate-config".to_string(), "prek.toml".to_string()])?;
    // Hook repositories and environments come from the network: fetch them under
    // retry, then run the hooks once. Retrying the run would retry a lint failure.
    println!("xtask: prek {}", prepare.join(" "));
    crate::retry::until_ok("prek install-hooks", || prek(&prepare))?;
    println!("xtask: prek {}", args.join(" "));
    prek(&args)
}

fn run_prek(args: &[String], repo_root: &Path) -> Result<()> {
    crate::command::run_inherited(Command::new("prek").args(args).current_dir(repo_root))
        .map_err(|e| crate::command::hint_if_not_found(e, "is prek installed? `uv tool install prek`"))
}
