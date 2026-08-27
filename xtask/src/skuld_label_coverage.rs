//! Guards `.github/workflows/ci.yaml`'s complementary `SKULD_LABELS` step
//! pair against going stale (bindreams/hole#891).
//!
//! `test-hole` splits ten packages across two `cargo nextest run` steps —
//! `SKULD_LABELS: "!tun"`, then `SKULD_LABELS: "tun"` last for #200 — and
//! skuld drops label-filtered-out tests before libtest ever sees them. A value
//! that selects nothing therefore produces no signal: no `filtered out` count,
//! and nextest only refuses a run selecting zero tests *in total*, which the
//! other nine packages hide.
//!
//! [`verify`] asserts three properties. Two are static, read out of ci.yaml
//! itself (via `extract_lane_candidates`) so this guard cannot drift from
//! the steps it checks:
//!
//! - the job's nextest-run steps agree on one package set and declare exactly
//!   two `SKULD_LABELS` values over it, which **parse** to exact logical
//!   complements. Parsed, not textual: skuld binds `!` tighter than `&`/`|`,
//!   so comparing `off` against `"!"` + `on` accepts `"tun | slow"` /
//!   `"!tun | slow"` — and a test carrying both labels then runs in *both*
//!   steps, the #200 ordering hazard the split exists to prevent.
//! - duplicate steps declaring the same lane (Windows and macOS both run
//!   `"tun"`) must be identical, since only one of them is listed.
//!
//! The third runs against the compiled binaries and is what catches a label
//! renamed on one side of the ci.yaml/source boundary only: **each side must
//! still select at least one compiled-in test**. `"!tnu"` / `"tnu"` is a
//! perfectly good complement that matches nothing at all — an absent terminal
//! evaluates to `false`, so `"!tnu"` absorbs the whole suite and the
//! privileged lane runs nothing.
//!
//! `stranded_tests` additionally asserts nothing compiled in is selected by
//! neither side. Given a parsed complement that is implied — it cross-checks
//! skuld's runtime filter evaluation against the parse, and is not itself a
//! drift detector.
//!
//! Not checked: which *packages* contribute. Most of the ten carry no `tun`
//! test, and platform gating zeroes out the rest (on darwin every
//! `tun`-labelled test in `hole-bridge`'s lib binary is
//! `cfg(target_os = "windows")`), so "this package contributed nothing" is
//! indistinguishable from correct. Pinning which ones must contribute needs a
//! hardcoded list — the thing reading ci.yaml exists to avoid — and could not
//! catch a rename anyway, since the scan for the label moves along with it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use skuld::LabelFilter;

use crate::ci_coverage::{is_nextest_run, join_line_continuations, package_tokens, split_commands, unquote};

// ci.yaml shape (local, minimal) — mirrors the pattern in `ci_coverage.rs` /
// `ci_nextest_parity.rs`: serde ignores every field this module doesn't name. =========================================

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
    run: Option<String>,
    #[serde(default)]
    env: IndexMap<String, serde_yml::Value>,
}

// Lane extraction =====================================================================================================

/// One `cargo nextest run` command found in a ci.yaml job, reduced to what
/// this guard needs: the packages it selects, the `SKULD_LABELS` value it
/// runs under, and the equivalent `nextest list` command (launcher prefix
/// stripped — listing needs no root even when the source step ran under
/// `sudo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneCandidate {
    pub label_value: String,
    pub packages: BTreeSet<String>,
    pub list_command: Vec<String>,
}

/// Every `cargo nextest run` command in `job_id`, each paired with the
/// `SKULD_LABELS` value it runs under. Errors if a nextest-run command sets
/// no `SKULD_LABELS` at all — this guard has nothing to check without one.
pub(crate) fn extract_lane_candidates(ci_yaml: &str, job_id: &str) -> Result<Vec<LaneCandidate>> {
    let ci: CiYaml = serde_yml::from_str(ci_yaml).context("parsing ci.yaml")?;
    let job = ci
        .jobs
        .get(job_id)
        .with_context(|| format!("ci.yaml declares no job {job_id:?}"))?;

    let mut out = Vec::new();
    for step in &job.steps {
        let Some(run) = &step.run else { continue };
        let joined = join_line_continuations(run);
        for cmd in split_commands(&joined) {
            if !is_nextest_run(&cmd) {
                continue;
            }
            let packages = package_tokens(&cmd);
            if packages.is_empty() {
                continue;
            }
            let label_value = skuld_labels_value(&step.env, &cmd).with_context(|| {
                format!("job {job_id:?} has a `cargo nextest run` step with no SKULD_LABELS set: {cmd:?}")
            })?;
            let list_command = to_list_command(&cmd)?;
            out.push(LaneCandidate {
                label_value,
                packages,
                list_command,
            });
        }
    }
    Ok(out)
}

/// The `SKULD_LABELS` value a nextest-run command executes under: from the
/// step's YAML `env:` block, or — for steps that state it inline (the macOS
/// TUN step runs under `sudo env ... SKULD_LABELS=tun cargo nextest run`,
/// since `sudo` does not inherit a step-level `env:`) — the first
/// `SKULD_LABELS=` token in the command itself.
fn skuld_labels_value(env: &IndexMap<String, serde_yml::Value>, cmd: &str) -> Option<String> {
    if let Some(v) = env.get("SKULD_LABELS") {
        return v.as_str().map(str::to_string);
    }
    cmd.split_whitespace()
        .map(unquote)
        .find_map(|tok| tok.strip_prefix("SKULD_LABELS=").map(str::to_string))
}

/// Split a shell command line into argv, honoring single- and double-quoted
/// spans (their content, minus the quote characters, is taken literally — no
/// escape sequences, no `$var` expansion). ci.yaml's nextest-run commands
/// only ever need that much: an unquoted flag/value stream plus one
/// single-quoted `-E '...'` filter and, on the macOS TUN step, a couple of
/// double-quoted `"VAR=value"` launcher tokens that [`to_list_command`]
/// discards anyway. A real shell would additionally expand variables and
/// honor backslash escapes; ci.yaml's steps never need either here.
fn shell_tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;

    for c in s.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                in_token = true;
            }
            None if c.is_whitespace() => {
                if in_token {
                    out.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            None => {
                cur.push(c);
                in_token = true;
            }
        }
    }
    if in_token {
        out.push(cur);
    }
    out
}

/// A launcher-prefix token: `sudo`, `env`, or an inline `VAR=value`. Anything
/// else immediately before `nextest` is the program that runs it.
fn is_launcher_token(tok: &str) -> bool {
    tok == "sudo" || tok == "env" || tok.contains('=')
}

/// Rewrite a nextest-run command into the argv for the equivalent `nextest
/// list --message-format json`, dropping any launcher prefix (`sudo`, `env`,
/// bare `VAR=value` tokens) — listing tests takes no root and needs none of
/// that.
///
/// Anchors on the same `nextest`,`run` token pair [`is_nextest_run`] matches,
/// so both launcher shapes in ci.yaml survive: `cargo nextest run`, and the
/// archive lanes' `cargo-nextest nextest run --archive-file ...`, which has no
/// `cargo` token at all. The program is whatever token precedes `nextest`,
/// unless that is itself a launcher token — then nextest is invoked directly.
fn to_list_command(cmd: &str) -> Result<Vec<String>> {
    let toks = shell_tokenize(cmd);
    let nextest_idx = toks
        .windows(2)
        .position(|w| w[0] == "nextest" && w[1] == "run")
        .with_context(|| format!("command has no `nextest run` token pair: {cmd:?}"))?;
    let start = match nextest_idx.checked_sub(1) {
        Some(prev) if !is_launcher_token(&toks[prev]) => prev,
        _ => nextest_idx,
    };

    let mut out: Vec<String> = Vec::new();
    let mut i = start;
    while i < toks.len() {
        if toks[i] == "nextest" && toks.get(i + 1).map(String::as_str) == Some("run") {
            out.extend(["nextest", "list", "--message-format", "json"].map(String::from));
            i += 2;
            continue;
        }
        out.push(toks[i].clone());
        i += 1;
    }
    Ok(out)
}

// Pairing =============================================================================================================

/// Find `job_id`'s complementary `SKULD_LABELS` pair: exactly one package set
/// shared by all its nextest-run steps, and exactly two distinct label values
/// over it that parse to exact logical complements.
///
/// Grouping by package set first — rather than searching for any complementary
/// pair among all candidates — matters: the real ci.yaml has *two* steps
/// declaring `"tun"` (Windows and macOS TUN), both over the same packages. If
/// only one of them drifted (say the Windows step typo'd to `"tnu"`), a search
/// for *some* complementary pair would find the macOS step's still-correct
/// `"tun"` and silently report success. Requiring *exactly two* distinct
/// values for the one package set catches that: a third, unpaired value in the
/// same group is the error, not a candidate to skip past.
///
/// The returned order is presentational: skuld's canonical filter form has no
/// inherent polarity, so the `!`-leading side is reported first.
pub(crate) fn pick_complementary_pair(candidates: &[LaneCandidate]) -> Result<(&LaneCandidate, &LaneCandidate)> {
    // Collapse steps declaring the same lane. Ones that agree on label value
    // and packages but would list different commands are rejected, not
    // silently collapsed: only the first is ever listed, so the rest would go
    // unchecked — this guard's own failure mode, one level up.
    let mut distinct: Vec<&LaneCandidate> = Vec::new();
    for c in candidates {
        match distinct
            .iter()
            .find(|d| d.label_value == c.label_value && d.packages == c.packages)
        {
            Some(prev) if **prev != *c => bail!(
                "two nextest-run steps run SKULD_LABELS={:?} over the same packages but would list \
                 different commands, so checking one leaves the other unverified:\n  {:?}\n  {:?}",
                c.label_value,
                prev.list_command,
                c.list_command
            ),
            Some(_) => {}
            None => distinct.push(c),
        }
    }

    let mut groups: Vec<(&BTreeSet<String>, Vec<&LaneCandidate>)> = Vec::new();
    for c in &distinct {
        match groups.iter_mut().find(|(pkgs, _)| **pkgs == c.packages) {
            Some((_, members)) => members.push(c),
            None => groups.push((&c.packages, vec![c])),
        }
    }

    let group = match groups.len() {
        0 => bail!(
            "the job has no `cargo nextest run` step that both sets SKULD_LABELS and selects \
             packages, so there is no label partition to check"
        ),
        1 => groups.remove(0).1,
        n => bail!(
            "the job's nextest-run steps declare {n} different package sets, expected exactly one \
             shared package set (the TUN lane's filter): {:?}",
            groups.iter().map(|(pkgs, _)| pkgs).collect::<Vec<_>>()
        ),
    };

    let (a, b) = match group.len() {
        2 => (group[0], group[1]),
        n => bail!(
            "the shared package set has {n} distinct SKULD_LABELS values among its nextest-run \
             steps, expected exactly two (a complementary pair): {:?}",
            group.iter().map(|c| c.label_value.as_str()).collect::<Vec<_>>()
        ),
    };

    if parse_filter(&a.label_value)? != !parse_filter(&b.label_value)? {
        bail!(
            "the shared package set's two SKULD_LABELS values, {:?} and {:?}, are not exact \
             negations of each other",
            a.label_value,
            b.label_value
        );
    }

    if b.label_value.starts_with('!') {
        Ok((b, a))
    } else {
        Ok((a, b))
    }
}

/// Parse a `SKULD_LABELS` value with skuld's own parser, so comparisons run on
/// the canonical (BDD-normalized) form rather than the source text.
fn parse_filter(value: &str) -> Result<LabelFilter> {
    LabelFilter::parse(value).map_err(|e| anyhow!("SKULD_LABELS={value:?} is not a valid label filter: {e}"))
}

// `cargo nextest list --message-format json` parsing ==================================================================

#[derive(Deserialize)]
struct ListOutput {
    #[serde(rename = "rust-suites")]
    rust_suites: BTreeMap<String, Suite>,
}

#[derive(Deserialize)]
struct Suite {
    testcases: BTreeMap<String, TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "filter-match")]
    filter_match: FilterMatch,
}

#[derive(Deserialize)]
struct FilterMatch {
    status: String,
}

/// Per test binary, the names of the tests `cargo nextest list
/// --message-format json` actually selected (`filter-match.status ==
/// "matches"`). skuld drops label-excluded tests before nextest's discovery
/// ever sees them, so in practice every listed entry already has this
/// status — the filter is defensive, not load-bearing on skuld's current
/// behavior.
pub(crate) fn matching_test_names(list_json: &str) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let parsed: ListOutput =
        serde_json::from_str(list_json).context("parsing `cargo nextest list --message-format json` output")?;
    Ok(parsed
        .rust_suites
        .into_iter()
        .map(|(binary_id, suite)| {
            let names = suite
                .testcases
                .into_iter()
                .filter(|(_, tc)| tc.filter_match.status == "matches")
                .map(|(name, _)| name)
                .collect();
            (binary_id, names)
        })
        .collect())
}

// Selection checks ====================================================================================================

/// Whether one side of the pair selected no test at all, in any binary — the
/// drift signature: a still-complementary pair whose values name nothing the
/// source declares, so the other side absorbs the whole suite.
pub(crate) fn selects_nothing(side: &BTreeMap<String, BTreeSet<String>>) -> bool {
    side.values().all(BTreeSet::is_empty)
}

/// Per test binary, the tests `baseline` (SKULD_LABELS unset — every
/// compiled-in test) lists that neither `off` nor `on` selects. Empty when
/// every compiled test is covered by at least one of the two complementary
/// steps — including binaries with an empty `on` set entirely, which is the
/// expected shape for most `test-hole` packages (no `tun`-labeled tests at
/// all, on any platform).
pub(crate) fn stranded_tests(
    baseline: &BTreeMap<String, BTreeSet<String>>,
    off: &BTreeMap<String, BTreeSet<String>>,
    on: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let empty = BTreeSet::new();
    let mut out = BTreeMap::new();
    for (binary_id, all) in baseline {
        let off_set = off.get(binary_id).unwrap_or(&empty);
        let on_set = on.get(binary_id).unwrap_or(&empty);
        let missing: BTreeSet<String> = all
            .iter()
            .filter(|name| !off_set.contains(*name) && !on_set.contains(*name))
            .cloned()
            .collect();
        if !missing.is_empty() {
            out.insert(binary_id.clone(), missing);
        }
    }
    out
}

// Runtime driver ======================================================================================================

fn run_nextest_list(
    repo_root: &Path,
    list_command: &[String],
    skuld_labels: Option<&str>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let (program, args) = list_command.split_first().context("empty nextest list command")?;

    let mut command = Command::new(program);
    command.args(args).current_dir(repo_root);
    match skuld_labels {
        Some(v) => {
            command.env("SKULD_LABELS", v);
        }
        None => {
            command.env_remove("SKULD_LABELS");
        }
    }

    let output = command
        .output()
        .with_context(|| format!("running `{}`", list_command.join(" ")))?;
    if !output.status.success() {
        bail!(
            "`{}` (SKULD_LABELS={skuld_labels:?}) failed: {}\n{}",
            list_command.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    matching_test_names(&String::from_utf8_lossy(&output.stdout))
}

/// Run the guard for `job_id`'s label lane: read ci.yaml, find the
/// complementary `SKULD_LABELS` step pair, list each side plus an unfiltered
/// baseline, and fail if either side selects nothing or any compiled-in test
/// is selected by neither.
pub fn verify(repo_root: &Path, job_id: &str) -> Result<()> {
    let ci_yaml = std::fs::read_to_string(repo_root.join(".github/workflows/ci.yaml")).context("read ci.yaml")?;
    let candidates = extract_lane_candidates(&ci_yaml, job_id)?;
    let (off, on) = pick_complementary_pair(&candidates)?;

    let baseline = run_nextest_list(repo_root, &off.list_command, None)?;
    let off_names = run_nextest_list(repo_root, &off.list_command, Some(&off.label_value))?;
    let on_names = run_nextest_list(repo_root, &on.list_command, Some(&on.label_value))?;

    for (value, side) in [(&off.label_value, &off_names), (&on.label_value, &on_names)] {
        if selects_nothing(side) {
            bail!(
                "SKULD_LABELS={value:?} selects NO test compiled into job {job_id:?}'s packages \
                 {:?}, so that step is a no-op and the other one absorbs the entire suite. The two \
                 values are still exact complements, so this is a value that no longer names \
                 anything the source declares — a label renamed or typo'd on one side of the \
                 ci.yaml/source boundary only, or its tests moved out of the package set.",
                off.packages
            );
        }
    }

    let stranded = stranded_tests(&baseline, &off_names, &on_names);
    if !stranded.is_empty() {
        let mut msg = format!(
            "SKULD_LABELS={:?} and SKULD_LABELS={:?} together select NEITHER of these tests, even \
             though they are compiled into the binary for job {job_id:?} — skuld's runtime filter \
             evaluation disagrees with parsing the two values as exact complements:\n",
            off.label_value, on.label_value
        );
        for (binary_id, names) in &stranded {
            msg.push_str(&format!("  {binary_id}:\n"));
            for name in names {
                msg.push_str(&format!("    {name}\n"));
            }
        }
        bail!(msg);
    }

    println!(
        "xtask: skuld label partition OK for job {job_id:?} — SKULD_LABELS={:?} and \
         SKULD_LABELS={:?} each select some test in {:?}, and between them every compiled test",
        off.label_value, on.label_value, off.packages
    );
    Ok(())
}
