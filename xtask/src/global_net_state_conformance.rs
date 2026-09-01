//! Guard 2: binds `.config/nextest.toml`'s `global_net_state` test-group's
//! *name-substring* membership to the `global_net_state` skuld label attached
//! at each test's own definition site (bindreams/hole#894).
//!
//! `.config/nextest.toml` cannot be eliminated — it is what gives nextest's
//! own `max-threads = 1` scheduling its cross-binary serialization, and
//! nextest's filterset DSL has no `test-group(...)` predicate to derive that
//! membership from anything else. What IS checkable: whether the group's own
//! *name-substring* filter (`cfg.filter`) and the *label* select the exact
//! same tests, live, for `job_id`'s test-hole leg — and whether the group's
//! `max-threads` is still `1`, without which the group's whole purpose (cross-
//! binary serialization of tests that mutate global OS network state) is
//! silently gone.
//!
//! [`group_config`] reads both axes from `.config/nextest.toml`.
//! [`job_list_template`] resolves `job_id`'s own `cargo nextest run`
//! command(s) into the one shared `cargo nextest list` argv template — erring
//! loudly on any divergence (bindreams/hole#894 round-2 finding F5) rather
//! than silently picking one. [`narrow_filter`] scopes that template to the
//! nextest.toml name-substring filter; [`set_mismatch`] diffs the two live
//! listings. [`verify`] orchestrates all four and fails loudly, by exact test
//! name in both directions, on any divergence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};

use crate::ci_coverage;
use crate::manifest::Manifest;
use crate::skuld_label_coverage::{run_nextest_list, to_list_command};

/// Matches the renamed nextest.toml test-group key exactly (bindreams/hole#894
/// Task 7) — so no separate `GROUP_NAME` constant or divergence-rationale
/// comment is needed; this IS both the group name and the skuld label name.
const LABEL_NAME: &str = "global_net_state";

// group_config ========================================================================================================

/// The `global_net_state` group's two load-bearing axes read live from
/// `.config/nextest.toml`: the name-substring `filter` its
/// `[[profile.default.overrides]]` entry matches on, and the `max-threads`
/// value that makes the group's cross-binary serialization real.
#[derive(Debug)]
pub(crate) struct GroupConfig {
    pub filter: String,
    pub max_threads: i64,
}

/// Parse `.config/nextest.toml` and read `group_name`'s `filter` (from its
/// sole `[[profile.default.overrides]]` entry) and `max-threads` (from its
/// `[test-groups.<group_name>]` table). Errs if zero or more than one
/// matching override exists, or if the `[test-groups.<group_name>]` table or
/// its `max-threads` key is absent.
pub(crate) fn group_config(nextest_toml: &str, group_name: &str) -> Result<GroupConfig> {
    let table: toml::Table = nextest_toml.parse().context("parsing .config/nextest.toml")?;

    let overrides = table
        .get("profile")
        .and_then(|v| v.get("default"))
        .and_then(|v| v.get("overrides"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let matching: Vec<&toml::Value> = overrides
        .iter()
        .filter(|o| o.get("test-group").and_then(|v| v.as_str()) == Some(group_name))
        .collect();
    let filter = match matching.as_slice() {
        [one] => one
            .get("filter")
            .and_then(|v| v.as_str())
            .with_context(|| format!("[[profile.default.overrides]] entry for test-group {group_name:?} has no filter"))?
            .to_string(),
        [] => bail!(".config/nextest.toml has no [[profile.default.overrides]] entry with test-group = {group_name:?}"),
        many => bail!(
            ".config/nextest.toml has {} [[profile.default.overrides]] entries with test-group = {group_name:?}, expected exactly one",
            many.len()
        ),
    };

    let max_threads = table
        .get("test-groups")
        .and_then(|v| v.get(group_name))
        .with_context(|| format!(".config/nextest.toml has no [test-groups.{group_name}] table"))?
        .get("max-threads")
        .with_context(|| format!("[test-groups.{group_name}] has no max-threads key"))?
        .as_integer()
        .with_context(|| format!("[test-groups.{group_name}] max-threads is not an integer"))?;

    Ok(GroupConfig { filter, max_threads })
}

// job_list_template ===================================================================================================

/// `job_id`'s shared `cargo nextest list` argv template: every test-running
/// command `ci_run_commands_for_job` returns for the job, mapped through
/// [`to_list_command`], must resolve to the SAME argv (full, `-E` included —
/// bindreams/hole#894 round-2 finding F5). Errs on zero commands or any
/// divergence, rather than silently picking one.
pub(crate) fn job_list_template(ci_yaml: &str, manifest: &Manifest, job_id: &str) -> Result<Vec<String>> {
    let raw = ci_coverage::ci_run_commands_for_job(ci_yaml, manifest, job_id)?;
    ensure!(
        !raw.is_empty(),
        "job {job_id:?} has no test-running nextest commands to derive a list template from"
    );

    let mut templates = raw.iter().map(|cmd| to_list_command(cmd));
    let first = templates.next().expect("checked non-empty above")?;
    for other in templates {
        let other = other?;
        ensure!(
            other == first,
            "job {job_id:?}'s test-running commands do not share one argv shape — \
             {first:?} vs {other:?} — guard 2 cannot pick one of them arbitrarily",
        );
    }
    Ok(first)
}

// narrow_filter =======================================================================================================

/// A copy of `list_command` with its `-E` flag's value replaced by
/// `(<old>) & (<extra>)`. Errs if `list_command` has no `-E` flag.
pub(crate) fn narrow_filter(list_command: &[String], extra: &str) -> Result<Vec<String>> {
    let idx = list_command
        .iter()
        .position(|t| t == "-E")
        .context("list command has no -E flag to narrow")?;
    let value_idx = idx + 1;
    ensure!(value_idx < list_command.len(), "list command's -E flag has no value");

    let mut out = list_command.to_vec();
    out[value_idx] = format!("({}) & ({extra})", list_command[value_idx]);
    Ok(out)
}

// set_mismatch ========================================================================================================

/// Per binary-id, `(name_only, label_only)`: tests `name_matched` selected
/// that `label_matched` didn't, and vice versa. A binary in full agreement
/// (including both sides empty) contributes no entry.
pub(crate) fn set_mismatch(
    name_matched: &BTreeMap<String, BTreeSet<String>>,
    label_matched: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let empty = BTreeSet::new();
    let mut binary_ids: BTreeSet<&String> = BTreeSet::new();
    binary_ids.extend(name_matched.keys());
    binary_ids.extend(label_matched.keys());

    let mut out = BTreeMap::new();
    for binary_id in binary_ids {
        let names = name_matched.get(binary_id).unwrap_or(&empty);
        let labels = label_matched.get(binary_id).unwrap_or(&empty);
        let name_only: BTreeSet<String> = names.difference(labels).cloned().collect();
        let label_only: BTreeSet<String> = labels.difference(names).cloned().collect();
        if !name_only.is_empty() || !label_only.is_empty() {
            out.insert(binary_id.clone(), (name_only, label_only));
        }
    }
    out
}

// verify ==============================================================================================================

/// Run guard 2 for `job_id`: confirm the `global_net_state` test-group's
/// `max-threads` is still `1`, then confirm its nextest.toml name-substring
/// filter and its skuld label select the exact same live tests. Fails
/// loudly, by exact test name in both directions per binary, on any
/// divergence.
pub fn verify(repo_root: &Path, job_id: &str) -> Result<()> {
    let ci_yaml = std::fs::read_to_string(repo_root.join(".github/workflows/ci.yaml")).context("read ci.yaml")?;
    let nextest_toml =
        std::fs::read_to_string(repo_root.join(".config/nextest.toml")).context("read .config/nextest.toml")?;
    let manifest = Manifest::parse(&std::fs::read_to_string(repo_root.join("build.yaml")).context("read build.yaml")?)
        .context("parse build.yaml")?;

    let cfg = group_config(&nextest_toml, LABEL_NAME)?;
    ensure!(
        cfg.max_threads == 1,
        "test-group {LABEL_NAME:?} has max-threads={}, not 1 — cross-binary serialization of the \
         global OS network state these tests mutate is OFF (bindreams/hole#894)",
        cfg.max_threads
    );

    let template = job_list_template(&ci_yaml, &manifest, job_id)?;
    let name_matched = run_nextest_list(repo_root, &narrow_filter(&template, &cfg.filter)?, None)?;
    let label_matched = run_nextest_list(repo_root, &template, Some(LABEL_NAME))?;

    // A silent empty/empty pass (both sides select nothing everywhere) would
    // defeat this guard exactly as a zero-match `SKULD_LABELS` does elsewhere
    // in this codebase (bindreams/hole#865 audit finding 4) — assert real
    // signal exists before trusting the diff below.
    let any_name_matched = name_matched.values().any(|s| !s.is_empty());
    let any_label_matched = label_matched.values().any(|s| !s.is_empty());
    ensure!(
        any_name_matched || any_label_matched,
        "job {job_id:?}: neither the nextest.toml filter {:?} nor the {LABEL_NAME:?} label selected \
         ANY test — guard 2 has nothing to verify, which defeats it as surely as a real divergence \
         would (bindreams/hole#894)",
        cfg.filter
    );

    let mismatches = set_mismatch(&name_matched, &label_matched);
    if mismatches.is_empty() {
        println!(
            "xtask: global_net_state label conformance OK for job {job_id:?} — the nextest.toml \
             filter and the {LABEL_NAME:?} label select the exact same tests"
        );
        return Ok(());
    }

    let mut msg = format!(
        "job {job_id:?}: the .config/nextest.toml filter {:?} and the {LABEL_NAME:?} skuld label \
         select DIFFERENT tests — a rename or a missing/extra label has drifted the group's \
         membership (bindreams/hole#894):\n",
        cfg.filter
    );
    for (binary_id, (name_only, label_only)) in &mismatches {
        msg.push_str(&format!("  {binary_id}:\n"));
        for name in name_only {
            msg.push_str(&format!(
                "    matched by nextest.toml filter, missing the label: {name}\n"
            ));
        }
        for name in label_only {
            msg.push_str(&format!(
                "    carries the label, missing from the nextest.toml filter: {name}\n"
            ));
        }
    }
    bail!(msg)
}
