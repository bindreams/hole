//! Which prek hooks run once, and which on every platform.
//!
//! Backs the conformance tests in `prek_split_tests.rs`. The unified `ci` job
//! runs `prek-portable` (every hook whose verdict is the same on any host) in
//! the linux/amd64 leg only, and `prek-host-bound` (hooks whose verdict depends
//! on the host's OS or arch, such as golangci-lint, which type-checks under the
//! host's `GOOS`) in every leg. The two build.yaml targets state the split; the
//! readers here let a test hold them to a per-hook classification.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};

use crate::ci_coverage::{join_line_continuations, split_commands, step_command, step_environment};
use crate::manifest::{Manifest, Step};

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

fn prek_run_step<'a>(manifest: &'a Manifest, target: &str) -> Result<(&'a Step, String)> {
    let t = manifest
        .get(target)
        .with_context(|| format!("build.yaml declares no target {target:?}"))?;
    for step in &t.run {
        for cmd in split_commands(&join_line_continuations(&step_command(step))) {
            let toks: Vec<&str> = cmd.split_whitespace().collect();
            if toks.windows(2).any(|w| w[0] == "prek" && w[1] == "run") {
                return Ok((step, cmd));
            }
        }
    }
    bail!("build.yaml target {target:?} has no `prek run` step")
}

/// The hook ids target `target`'s `prek run` step skips through `SKIP`
/// (comma-separated, as prek reads it).
pub fn portable_skip(manifest: &Manifest, target: &str) -> Result<BTreeSet<String>> {
    let (step, _) = prek_run_step(manifest, target)?;
    Ok(step_environment(step)
        .get("SKIP")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default())
}

/// The hook ids target `target`'s `prek run` step names, i.e. its positional
/// arguments. A bare `prek run` names none and would run every hook, so it is an
/// error here rather than an empty set.
pub fn host_bound_hooks(manifest: &Manifest, target: &str) -> Result<BTreeSet<String>> {
    let (_, cmd) = prek_run_step(manifest, target)?;
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let run_at = toks
        .windows(2)
        .position(|w| w[0] == "prek" && w[1] == "run")
        .expect("prek_run_step found it")
        + 2;
    let ids: BTreeSet<String> = toks[run_at..]
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(|t| t.to_string())
        .collect();
    if ids.is_empty() {
        bail!("build.yaml target {target:?} runs `prek run` without naming a hook, so it runs every hook");
    }
    Ok(ids)
}
