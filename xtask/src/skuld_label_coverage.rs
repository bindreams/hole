//! Guards against a `SKULD_LABELS` value in `.github/workflows/ci.yaml` going
//! stale (bindreams/hole#891).
//!
//! `test-hole`'s TUN lane runs two complementary `cargo nextest run` steps —
//! one with `SKULD_LABELS: "!tun"`, one with `SKULD_LABELS: "tun"` — over the
//! same package set. skuld drops label-filtered-out tests *before* libtest
//! ever sees them (`collect_inventory_tests` in skuld itself), so a test
//! excluded from both steps produces no signal anywhere: no `filtered out`
//! count (skuld already removed it), and nextest only refuses a *whole run*
//! that selects zero tests — with ten packages named, one package (or one
//! test) silently contributing nothing to a step stays invisible.
//!
//! There is no way to tell, from a single step in isolation, whether a
//! package's zero count under one label is a bug or by design — most of the
//! ten `test-hole` packages never carry the `tun` label at all, and that is
//! correct (platform gating also legitimately zeroes out privileged tests on
//! platforms where they are `#[cfg]`'d away entirely). The one thing that
//! *is* structurally checkable, independent of any hardcoded list: `"!tun"`
//! and `"tun"` are exact logical complements, so every test compiled into a
//! binary must be selected by exactly one of the two steps. A test selected
//! by *neither* fell through — the two ci.yaml values stopped being real
//! complements of each other (a typo in one, or a rename applied to only
//! one), which is exactly the failure mode described above. A test that
//! belongs to neither the TUN nor the non-TUN world doesn't exist; if it's
//! compiled in, it's one or the other.
//!
//! [`verify`] computes that conservation check per binary and fails loudly on
//! any shortfall: it lists (via three `cargo nextest list
//! --message-format json` calls — SKULD_LABELS unset, `!tun`, `tun`) the
//! tests each step would actually select, and asserts the two label-filtered
//! sets union back to the unfiltered baseline. The label values and package
//! set are read from ci.yaml itself (via [`extract_lane_candidates`]), not
//! duplicated here, so the guard cannot itself drift from the steps it
//! checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

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

/// Rewrite a `cargo nextest run ...` command into the argv for the equivalent
/// `cargo nextest list --message-format json ...`, dropping any launcher
/// prefix (`sudo`, `env`, bare `VAR=value` tokens) before the `cargo` token —
/// listing tests takes no root and needs none of that.
pub(crate) fn to_list_command(cmd: &str) -> Result<Vec<String>> {
    let toks = shell_tokenize(cmd);
    let cargo_idx = toks
        .iter()
        .position(|t| t == "cargo")
        .with_context(|| format!("nextest run command has no `cargo` token: {cmd:?}"))?;

    let mut out: Vec<String> = Vec::new();
    let mut i = cargo_idx;
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
/// over it, one the exact negation of the other (`"!tun"` / `"tun"`).
///
/// Grouping by package set first — rather than searching for any matching
/// `"!X"`/`"X"` pair among all candidates — matters: the real ci.yaml has
/// *two* steps declaring `"tun"` (Windows and macOS TUN), both over the same
/// packages. If only one of them drifted (say the Windows step typo'd to
/// `"tnu"`), a search that just looks for *some* matching pair would find the
/// macOS step's still-correct `"tun"` and silently report success — the
/// Windows step's own drift would never surface. Requiring *exactly two*
/// distinct values for the one package set catches that: a third, unpaired
/// value in the same group is the error, not a candidate to skip past.
pub(crate) fn pick_complementary_pair(candidates: &[LaneCandidate]) -> Result<(&LaneCandidate, &LaneCandidate)> {
    let mut distinct: Vec<&LaneCandidate> = Vec::new();
    for c in candidates {
        if !distinct
            .iter()
            .any(|d| d.label_value == c.label_value && d.packages == c.packages)
        {
            distinct.push(c);
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
        1 => groups.remove(0).1,
        n => bail!(
            "the job's nextest-run steps declare {n} different package sets, expected exactly one \
             shared package set (the TUN lane's filter): {:?}",
            groups.iter().map(|(pkgs, _)| pkgs).collect::<Vec<_>>()
        ),
    };

    let (off, on) = match group.len() {
        2 => (group[0], group[1]),
        n => bail!(
            "the shared package set has {n} distinct SKULD_LABELS values among its nextest-run \
             steps, expected exactly two (a complementary pair): {:?}",
            group.iter().map(|c| c.label_value.as_str()).collect::<Vec<_>>()
        ),
    };

    if off.label_value == format!("!{}", on.label_value) {
        Ok((off, on))
    } else if on.label_value == format!("!{}", off.label_value) {
        Ok((on, off))
    } else {
        bail!(
            "the shared package set's two SKULD_LABELS values, {:?} and {:?}, are not exact \
             negations of each other",
            off.label_value,
            on.label_value
        )
    }
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

// Conservation check ==================================================================================================

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

// Guard 1: TUN-lane non-emptiness (bindreams/hole#894) ================================================================

/// `true` iff at least one binary's set in `on` is non-empty — i.e. at least
/// one test, anywhere, was selected under the `on` side's `SKULD_LABELS`
/// value on this leg. `false` for an entirely-empty map or one whose every
/// binary maps to an empty set: the platform's whole privileged lane has
/// gone empty (bindreams/hole#894, #865 audit finding 3).
pub(crate) fn on_side_is_nonempty(on: &BTreeMap<String, BTreeSet<String>>) -> bool {
    on.values().any(|names| !names.is_empty())
}

// Runtime driver ======================================================================================================

pub(crate) fn run_nextest_list(
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

/// Run the guard for `job_id`'s TUN lane: read ci.yaml, find the
/// complementary `SKULD_LABELS` step pair, list each side plus an unfiltered
/// baseline, and fail if any compiled-in test is selected by neither side.
pub fn verify(repo_root: &Path, job_id: &str) -> Result<()> {
    let ci_yaml = std::fs::read_to_string(repo_root.join(".github/workflows/ci.yaml")).context("read ci.yaml")?;
    let candidates = extract_lane_candidates(&ci_yaml, job_id)?;
    let (off, on) = pick_complementary_pair(&candidates)?;

    let baseline = run_nextest_list(repo_root, &off.list_command, None)?;
    let off_names = run_nextest_list(repo_root, &off.list_command, Some(&off.label_value))?;
    let on_names = run_nextest_list(repo_root, &on.list_command, Some(&on.label_value))?;

    // Guard 1 (bindreams/hole#894): the `on` side's own listing — the
    // platform's privileged/TUN lane — must select at least one test. An
    // entirely-conserved-by-the-off-side result (every compiled test found
    // by SKULD_LABELS=off) would pass the conservation check below while the
    // TUN lane silently went empty on this platform; report that more
    // specific, more actionable failure first.
    ensure!(
        on_side_is_nonempty(&on_names),
        "SKULD_LABELS={:?} selected ZERO tests for job {job_id:?} on this leg — the tun-labeled \
         lane has gone entirely empty on this platform (bindreams/hole#894)",
        on.label_value
    );

    let stranded = stranded_tests(&baseline, &off_names, &on_names);
    if stranded.is_empty() {
        println!(
            "xtask: skuld label partition OK for job {job_id:?} — every compiled test in {:?} is \
             selected by SKULD_LABELS={:?} or SKULD_LABELS={:?}",
            off.packages, off.label_value, on.label_value
        );
        return Ok(());
    }

    let mut msg = format!(
        "SKULD_LABELS={:?} and SKULD_LABELS={:?} together select NEITHER of these tests, even though \
         they are compiled into the binary for job {job_id:?} — the two ci.yaml SKULD_LABELS values \
         have drifted apart (a typo in one, or a rename applied to only one):\n",
        off.label_value, on.label_value
    );
    for (binary_id, names) in &stranded {
        msg.push_str(&format!("  {binary_id}:\n"));
        for name in names {
            msg.push_str(&format!("    {name}\n"));
        }
    }
    bail!(msg)
}
