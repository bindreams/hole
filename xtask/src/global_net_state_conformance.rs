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
//!
//! Guard 3 (bindreams/hole#999) answers a different question: not "is the
//! `global_net_state` group's membership correct" (guard 2), but "did the
//! tests it selected on THIS run actually execute" — closing the gap where a
//! job that silently ran zero of them would still look green. [`run_nextest_list`]
//! (reused from guard 1/2) gives the `global_net_state`-labeled tests a given
//! `job_id` step template *should* select; [`junit_executed_tests`] reads
//! nextest's own JUnit report (`.config/nextest.toml`'s
//! `[profile.default.junit]`) for the tests that actually ran (present,
//! un-skipped); [`set_missing`] diffs the two one-directionally.
//!
//! A single JUnit report is not always enough: `[profile.default.junit]`
//! overwrites the same file on every `cargo nextest run` invocation, and not
//! every `global_net_state`-labeled test is privileged — some are mocked
//! unit tests that preserve the nextest.toml filter's membership without
//! carrying `TUN` (bindreams/hole#894 "Option B"), so they run in the
//! non-TUN partition and never in the TUN one. [`verify_executed`] therefore
//! takes one JUnit path per nextest-run step that might contain a
//! `global_net_state` test and [`merge_executed`] unions their executed sets
//! before diffing — a lone report from whichever step ran last would
//! otherwise call an earlier-only test "missing" despite it having passed.
//! [`verify_executed`] orchestrates all four and fails loudly, by exact test
//! name, on any test that was selected but never shows up as executed in any
//! of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use roxmltree::Document;

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

// junit_executed_tests (bindreams/hole#999) ===========================================================================

/// Per `<testsuite>`'s testcases' `classname` — nextest emits the same
/// `binary_id` shape here as `cargo nextest list --message-format json`'s
/// map key (e.g. `hole-bridge::cutover_leak_privileged`), confirmed against
/// nextest-runner's own JUnit writer — the set of `name`s that appear as
/// EXECUTED: present in the report and carrying no `<skipped>` child. A
/// `<failure>` child still counts as executed; only `<skipped>` does not
/// (nextest's `report-skipped` policy defaults to emitting none of these at
/// all, so in practice a skipped entry here means an explicit opt-in
/// elsewhere — the check does not assume that policy).
pub(crate) fn junit_executed_tests(xml: &str) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let doc = Document::parse(xml).context("parsing JUnit XML report")?;

    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("testcase")) {
        let classname = node
            .attribute("classname")
            .context("JUnit report has a <testcase> with no classname attribute")?;
        let name = node
            .attribute("name")
            .context("JUnit report has a <testcase> with no name attribute")?;
        let skipped = node.children().any(|c| c.is_element() && c.has_tag_name("skipped"));
        if skipped {
            continue;
        }
        out.entry(classname.to_string()).or_default().insert(name.to_string());
    }
    Ok(out)
}

// set_missing (bindreams/hole#999) ====================================================================================

/// Per binary-id, the `expected` tests that `executed` doesn't have — the
/// one-directional counterpart of [`set_mismatch`]: `executed` may
/// legitimately be a superset (other labels ran in the same job), only
/// "selected but never ran" is a finding here.
pub(crate) fn set_missing(
    expected: &BTreeMap<String, BTreeSet<String>>,
    executed: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let empty = BTreeSet::new();
    let mut out = BTreeMap::new();
    for (binary_id, names) in expected {
        let ran = executed.get(binary_id).unwrap_or(&empty);
        let missing: BTreeSet<String> = names.difference(ran).cloned().collect();
        if !missing.is_empty() {
            out.insert(binary_id.clone(), missing);
        }
    }
    out
}

// merge_executed (bindreams/hole#999) =================================================================================

/// Union several [`junit_executed_tests`] maps into one, per binary-id. Not
/// every `global_net_state`-labeled test is privileged: the group also
/// deliberately carries mocked, non-privileged tests that preserve the
/// `.config/nextest.toml` name-substring filter's membership without
/// mutating real OS state (bindreams/hole#894 "Option B" — e.g.
/// `release_all_first_delete_failure_reports_the_first_real_error_and_inspects_every_code`,
/// which never carries `TUN` and so runs only in the non-TUN partition,
/// never the TUN one). A JUnit report is one nextest invocation's output
/// (`[profile.default.junit]` overwrites the same file on every `cargo
/// nextest run`), so proving every labeled test executed *somewhere* across
/// `job_id`'s several nextest-run steps needs each step's report unioned —
/// a lone report from the last step to run would otherwise call a test that
/// only ran earlier "missing", despite it having passed.
pub(crate) fn merge_executed(
    maps: impl IntoIterator<Item = BTreeMap<String, BTreeSet<String>>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for map in maps {
        for (binary_id, names) in map {
            out.entry(binary_id).or_default().extend(names);
        }
    }
    out
}

// verify_executed (bindreams/hole#999) ================================================================================

/// `.config/nextest.toml`'s standard JUnit report path, used when
/// [`verify_executed`] is given no `--junit` path at all.
const DEFAULT_JUNIT_PATH: &str = "target/nextest/default/junit.xml";

/// Run guard 3 for `job_id`: list the tests the `global_net_state` skuld
/// label selects for `job_id`'s own nextest command template (the same
/// listing guard 2's `label_matched` computes), then confirm every one of
/// them appears as executed (non-skipped) in at least one of `junit_paths`'
/// JUnit reports (each resolved relative to `repo_root` if not absolute;
/// defaults to the one standard path if `junit_paths` is empty). Fails
/// loudly, by exact test name, on any that don't — proving the privileged
/// lane didn't just SELECT these tests but actually RAN them.
pub fn verify_executed(repo_root: &Path, job_id: &str, junit_paths: &[PathBuf]) -> Result<()> {
    let ci_yaml = std::fs::read_to_string(repo_root.join(".github/workflows/ci.yaml")).context("read ci.yaml")?;
    let manifest = Manifest::parse(&std::fs::read_to_string(repo_root.join("build.yaml")).context("read build.yaml")?)
        .context("parse build.yaml")?;

    let template = job_list_template(&ci_yaml, &manifest, job_id)?;
    let expected = run_nextest_list(repo_root, &template, Some(LABEL_NAME))?;

    // Same defense as guard 2 (bindreams/hole#865 audit finding 4): a
    // vacuously-empty expectation would make an all-zero JUnit report pass
    // just as cleanly as a real one.
    let any_expected = expected.values().any(|s| !s.is_empty());
    ensure!(
        any_expected,
        "job {job_id:?}: the {LABEL_NAME:?} label selected ZERO tests — guard 3 has nothing to confirm \
         actually ran, which defeats it as surely as a real execution gap would (bindreams/hole#999)"
    );

    let default_paths = [PathBuf::from(DEFAULT_JUNIT_PATH)];
    let junit_paths: &[PathBuf] = if junit_paths.is_empty() {
        &default_paths
    } else {
        junit_paths
    };

    let mut junit_abs_paths = Vec::with_capacity(junit_paths.len());
    let mut executed_maps = Vec::with_capacity(junit_paths.len());
    for junit_path in junit_paths {
        let junit_abs = if junit_path.is_absolute() {
            junit_path.clone()
        } else {
            repo_root.join(junit_path)
        };
        let junit_xml = std::fs::read_to_string(&junit_abs)
            .with_context(|| format!("reading JUnit report at {}", junit_abs.display()))?;
        executed_maps.push(junit_executed_tests(&junit_xml)?);
        junit_abs_paths.push(junit_abs);
    }
    let executed = merge_executed(executed_maps);
    let junit_paths_display = junit_abs_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let missing = set_missing(&expected, &executed);
    if missing.is_empty() {
        let total: usize = expected.values().map(BTreeSet::len).sum();
        println!(
            "xtask: global_net_state execution proof OK for job {job_id:?} — all {total} {LABEL_NAME:?}-labeled \
             test(s) appear as executed (non-skipped) across the JUnit report(s) at {junit_paths_display}"
        );
        return Ok(());
    }

    let missing_count: usize = missing.values().map(BTreeSet::len).sum();
    let mut msg = format!(
        "job {job_id:?}: {missing_count} {LABEL_NAME:?}-labeled test(s) were selected but do NOT appear as \
         executed (non-skipped) in any of the JUnit report(s) at {junit_paths_display} — a green job that \
         silently ran zero (or fewer than expected) of these tests (bindreams/hole#999):\n"
    );
    for (binary_id, names) in &missing {
        msg.push_str(&format!("  {binary_id}:\n"));
        for name in names {
            msg.push_str(&format!("    {name}\n"));
        }
    }
    bail!(msg)
}
