//! Is `typify` still the reason `schemars` is held at 0.8?
//!
//! Backs the `schemars_pin_still_tracks_typify` conformance test and the
//! `cargo xtask check-schemars-pin` prek hook.
//!
//! `crates/common/build.rs` generates the wire types from `api/openapi.yaml`
//! through `typify::TypeSpace`, and every ingestion path that type offers
//! (`add_ref_types`, `add_type`, `add_type_with_name`, `add_root_schema`)
//! takes a `schemars` schema. `typify` does not re-export `schemars`, so the
//! version is not ours to choose: we must name it ourselves and it must be the
//! one typify speaks. `schemars` 0.9 and 1.x both made the `schema` module
//! private, so any bump past 0.8 fails the build script with `E0603`
//! regardless of what the rest of the workspace wants.
//!
//! **The real protection is that `E0603`, not this module.** A wrong pin does
//! not ship silently: it fails `crates/common/build.rs` to compile, on every
//! platform, unconditionally. This module exists one layer up from that: to
//! keep the *annoyance* of a reopened bindreams/hole#379 self-resolving
//! instead of a standing trap nobody notices, by catching upstream moving
//! before Renovate proposes the impossible bump at all.
//!
//! Cargo cannot see the compile failure coming. Three semver-incompatible
//! `schemars` already coexist in this tree — 0.8.22, 0.9.0 and 1.2.1 — with
//! `serde_with` 3.18.0 declaring all three as optional features and resolving
//! to two of them, 0.9.0 and 1.2.1. So 1.x is already vendored, a bump
//! resolves cleanly, and the only failure is at compile time. Renovate cannot
//! see the constraint either, which is why `.github/renovate.json` carries an
//! `allowedVersions` rule for it.
//!
//! ## The Renovate rule is best-effort, and is not modelled here
//!
//! This module used to also verify that Renovate would actually *apply* that
//! `allowedVersions` rule: a hand-rolled model of Renovate's own packageRule
//! selector resolution — which selectors reach `schemars`, glob/regex
//! dependency-name matching, negation precedence, last-wins merging across
//! nested and manager-scoped rules. Three independent review rounds each found
//! a fresh divergence from Renovate's real behaviour (empty selector arrays
//! matching nothing, minimatch's `*` not crossing `/`, `ignoreDeps` invisible
//! to it, `matchDepTypes` on `build-dependencies` producing a false red, case
//! folding) — an arms race against a moving upstream, fought with machinery
//! that itself needed guarding as much as the thing it guarded.
//!
//! That model has been removed. The Renovate rule is now **best-effort noise
//! suppression, and nothing more is claimed of it**: if it is ever malformed,
//! scoped away from `schemars`, or shadowed by a later rule, the worst case is
//! that Renovate reopens bindreams/hole#379 as an ordinary PR. `E0603` refuses
//! the bump regardless of why Renovate proposed it, so a *dead* Renovate rule
//! costs a noisy reopened PR — never a broken build, and never a shipped
//! defect. Guarding the guard was the part of this that needed to stop.
//!
//! `.github/renovate.json` is still schema-validated — the `Validate renovate
//! config` CI job runs `renovate-config-validator --strict` against it — so a
//! typo that Renovate's schema itself rejects is still caught. What is gone is
//! this module deciding, on Renovate's behalf, whether a *schema-valid* rule
//! would actually reach `schemars`.
//!
//! ## The fact this module still guards
//!
//! [`PINNED_SERIES`] is that fact — the one hand-written copy of it.
//! `crates/common/Cargo.toml`'s `schemars = "0.8"` is a consequence of it and
//! is checked *against* it ([`check_local_pin`]), not compared textually: a
//! constant edited out from under the guard would otherwise leave it policing
//! the wrong series without anything noticing.
//!
//! If the upstream fact stops holding — `typify` no longer requires 0.8 — the
//! pin, the Renovate rule and this module have all become friction with no
//! fact behind them, and should be deleted rather than defended; see
//! [`WHEN_UPSTREAM_MOVES`].
//!
//! ## Two upstream signals, and why both
//!
//! - **Declared** ([`declared_schemars_requirements`], from `cargo metadata`):
//!   what `typify-impl` says it accepts. This is the signal that catches
//!   upstream *widening* — admitting 1.x alongside 0.8, the shape `serde_with`
//!   already has.
//! - **Resolved** ([`upstream_schemars`], from `Cargo.lock`): which `schemars`
//!   the graph actually settled on. This catches upstream being *forced* off
//!   0.8, and it catches schemars leaving typify-impl's normal dependencies
//!   altogether (demoted to dev, or made optional and left unenabled — both
//!   drop the edge from the lock).
//!
//! Neither subsumes the other. A widened requirement leaves the lock entry
//! untouched — cargo keeps a locked version that still satisfies the new range
//! — so the resolved signal stays green through exactly the change the pin
//! exists to catch.
//!
//! **Why the split is by lane, not by strength:** the declared signal *could*
//! run in the archive lane. `Test tooling` has network, and a cold-`CARGO_HOME`
//! `cargo metadata --locked` was measured there at 16.5 s, exit 0 — the
//! `--offline` failure on `cosca` is real but [`cargo_metadata_json`]
//! deliberately does not pass `--offline`. It does not run there because a
//! conformance test is the wrong place to spend a registry round trip, and
//! because this repo's tests do not shell out to cargo at all
//! (bindreams/hole#496, enforced by its own prek hook). So:
//!
//! - `schemars_pin_still_tracks_typify` (this crate's tests, and therefore the
//!   archive lane) checks everything readable from tracked files: the resolved
//!   version and the local pin.
//! - `cargo xtask check-schemars-pin` checks that *plus* the declared
//!   requirement, and runs where a registry exists: the `check-schemars-pin`
//!   prek hook, which `prek.toml` gates by `files` to commits touching
//!   `Cargo.lock`, `.github/renovate.json`, `crates/common/Cargo.toml` or this
//!   module — and unconditionally in the `Lint` CI job, which runs prek
//!   `--all-files`.
//!
//! Nothing is skipped: each lane runs every check it can source data for, and
//! the declared-requirement check fails loudly rather than passing when
//! `cargo metadata` cannot run.
//!
//! ## What this does NOT check, and why
//!
//! That `crates/common/Cargo.toml` agrees with *typify*. It cannot: a mismatch
//! fails `crates/common/build.rs` to compile with the very `E0603` above, so
//! any run of this test already proves that agreement. An assertion that can
//! only execute when it is already true detects nothing — the shape
//! bindreams/hole#894 exists to stop. [`check_local_pin`] compares that
//! manifest against [`PINNED_SERIES`] instead, which is a different question
//! and is not compiler-covered.
//!
//! ## Why this is a test and not a comment
//!
//! The pin is correct only while the upstream fact holds. Left as prose it
//! would outlive that fact silently: the `allowedVersions` rule would keep
//! suppressing a bump that had become possible, and nobody would notice,
//! because a suppressed update produces no signal at all.
//!
//! Note the eventual fix is not expected to be a `schemars` bump. Typify's
//! maintainer has said the schemars schema structures "have been removed. We
//! will roll our own IR" (oxidecomputer/typify#886), so when this fires, read
//! that issue before assuming the answer is `schemars = "1"`.

use std::cmp::Ordering;
use std::ops::Bound::{self, Excluded, Included, Unbounded};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use cargo_metadata::semver::{BuildMetadata, Comparator, Version, VersionReq};
use serde::Deserialize;

/// The crate whose choice decides ours. `typify-impl` rather than the `typify`
/// facade: the facade's own `schemars` entry is a dev-dependency (its
/// doctests), while `typify-impl` is what holds the schema types in its public
/// API.
pub const UPSTREAM: &str = "typify-impl";

/// The major.minor series `crates/common/build.rs` compiles against. The one
/// hand-written copy of the fact; everything else is derived from it.
pub const PINNED_SERIES: &str = "0.8";

/// What a reader should do when the upstream half of this guard fires. Shared
/// by every arm so the instruction cannot drift between them.
const WHEN_UPSTREAM_MOVES: &str = "\
Read oxidecomputer/typify#886 before assuming the answer is `schemars = \"1\"`: the stated plan is to drop \
schemars' schema types for typify's own IR, in which case crates/common/build.rs changes shape rather than \
changing version. Once the pin is genuinely unnecessary, delete the `allowedVersions` rule from \
.github/renovate.json, the `schemars` build-dependency comment in crates/common/Cargo.toml, this module and \
its prek hook — and let bindreams/hole#379 be re-proposed.";

// Series arithmetic ===================================================================================================

/// [`PINNED_SERIES`] as `(floor, next breaking version)` — `0.8` yields
/// `(0.8.0, 0.9.0)`.
///
/// For a `0.x` crate the minor IS the breaking axis, which is the whole reason
/// this pin exists; above `0.x` the major is. Panics rather than returning an
/// error: [`PINNED_SERIES`] is a constant in this file, so a malformed one is a
/// compile-time editing mistake, not a runtime condition a caller can handle.
fn pinned_bounds() -> (Version, Version) {
    let (major, minor) = PINNED_SERIES
        .split_once('.')
        .and_then(|(major, minor)| Some((major.parse::<u64>().ok()?, minor.parse::<u64>().ok()?)))
        .unwrap_or_else(|| panic!("PINNED_SERIES must be `major.minor`, got {PINNED_SERIES:?}"));

    let floor = Version::new(major, minor, 0);
    let next = if major == 0 {
        Version::new(0, minor + 1, 0)
    } else {
        Version::new(major + 1, 0, 0)
    };
    (floor, next)
}

/// The interval `(lower, upper)` a single comparator admits.
///
/// Deliberately an interval computation and not a set of probe versions: a
/// probe set is only ever a sample, and `^1.0.2` — a perfectly ordinary way for
/// an upstream to move — admits nothing at `1.0.0`, `2.0.0` or any other round
/// number one would think to try. Sampling a range that is *defined* by its
/// endpoints is how a guard ends up green on the change it exists to catch.
///
/// [`Bound`]s rather than a pair of versions because an endpoint's inclusivity
/// is not always expressible by moving to a neighbour: `<=0.9.0-alpha` ends
/// *at* `0.9.0-alpha`, which has no successor to make exclusive, and which
/// [`version_tracks_pin`] puts inside the pin. Rounding that endpoint up to
/// `0.9.1` reports a widening that is not there.
fn comparator_bounds(c: &Comparator) -> Result<(Bound<Version>, Bound<Version>)> {
    use cargo_metadata::semver::Op;

    let (major, minor, patch) = (c.major, c.minor, c.patch);
    let at = |minor: u64, patch: u64| Version::new(major, minor, patch);
    // The exclusive upper bound of "everything this prefix covers": `1.2.3` ends
    // at 1.2.4, `1.2` at 1.3.0, `1` at 2.0.0.
    let prefix_end = || match (minor, patch) {
        (Some(minor), Some(patch)) => at(minor, patch + 1),
        (Some(minor), None) => at(minor + 1, 0),
        (None, _) => Version::new(major + 1, 0, 0),
    };
    // The version the comparator names, pre-release and all.
    let named = Version {
        major,
        minor: minor.unwrap_or(0),
        patch: patch.unwrap_or(0),
        pre: c.pre.clone(),
        build: BuildMetadata::EMPTY,
    };
    // A pre-release endpoint is the endpoint. `<=0.9.0-alpha` does not reach
    // 0.9.0, and `=0.9.0-alpha` admits that one version rather than the 0.9.0
    // patch line.
    let pre = !c.pre.is_empty();
    let bottom = Included(Version::new(0, 0, 0));

    Ok(match c.op {
        Op::Exact | Op::Wildcard if pre => (Included(named.clone()), Included(named)),
        Op::Exact | Op::Wildcard => (Included(named), Excluded(prefix_end())),
        Op::Greater if pre => (Excluded(named), Unbounded),
        Op::Greater => (Included(prefix_end()), Unbounded),
        Op::GreaterEq => (Included(named), Unbounded),
        Op::Less => (bottom, Excluded(named)),
        Op::LessEq if pre => (bottom, Included(named)),
        Op::LessEq => (bottom, Excluded(prefix_end())),
        Op::Tilde => (
            Included(named),
            Excluded(match minor {
                Some(minor) => at(minor + 1, 0),
                None => Version::new(major + 1, 0, 0),
            }),
        ),
        // Cargo's caret: the leftmost non-zero component is the breaking axis,
        // which is why `^0.8.22` holds this pin and `^1.0.2` would not.
        Op::Caret => {
            let end = match (major, minor, patch) {
                (0, Some(0), Some(patch)) => at(0, patch + 1),
                (0, Some(minor), _) => at(minor + 1, 0),
                _ => Version::new(major + 1, 0, 0),
            };
            (Included(named), Excluded(end))
        }
        other => bail!(
            "this guard does not understand the semver operator in `{c}` ({other:?}). It compares a \
             requirement's interval against PINNED_SERIES ({PINNED_SERIES}), so an operator it cannot bound \
             must be taught here rather than assumed harmless."
        ),
    })
}

/// The interval a whole requirement admits: comparators are ANDed, so each
/// bound narrows to the tighter of the two. No comparators (`*`, or an empty
/// requirement) means unbounded above and from zero below.
fn requirement_bounds(req: &VersionReq) -> Result<(Bound<Version>, Bound<Version>)> {
    let mut lower = Included(Version::new(0, 0, 0));
    let mut upper = Unbounded;
    for comparator in &req.comparators {
        let (comparator_lower, comparator_upper) = comparator_bounds(comparator)?;
        lower = tighter_lower(lower, comparator_lower);
        upper = tighter_upper(upper, comparator_upper);
    }
    Ok((lower, upper))
}

/// Of two lower bounds, the one that admits less. On the same version,
/// excluding it is the tighter.
fn tighter_lower(a: Bound<Version>, b: Bound<Version>) -> Bound<Version> {
    match (&a, &b) {
        (Unbounded, _) => b,
        (_, Unbounded) => a,
        (Included(x) | Excluded(x), Included(y) | Excluded(y)) => match x.cmp(y) {
            Ordering::Less => b,
            Ordering::Greater => a,
            Ordering::Equal if matches!(b, Excluded(_)) => b,
            Ordering::Equal => a,
        },
    }
}

/// Of two upper bounds, the one that admits less. `Unbounded` always loses.
fn tighter_upper(a: Bound<Version>, b: Bound<Version>) -> Bound<Version> {
    match (&a, &b) {
        (Unbounded, _) => b,
        (_, Unbounded) => a,
        (Included(x) | Excluded(x), Included(y) | Excluded(y)) => match x.cmp(y) {
            Ordering::Less => a,
            Ordering::Greater => b,
            Ordering::Equal if matches!(b, Excluded(_)) => b,
            Ordering::Equal => a,
        },
    }
}

/// Is `version` at or above `lower`?
fn at_or_above(lower: &Bound<Version>, version: &Version) -> bool {
    match lower {
        Unbounded => true,
        Included(bound) => version >= bound,
        Excluded(bound) => version > bound,
    }
}

/// Does the interval reach `version`, or anything past it?
fn reaches(upper: &Bound<Version>, version: &Version) -> bool {
    match upper {
        Unbounded => true,
        Included(bound) => bound >= version,
        Excluded(bound) => bound > version,
    }
}

/// Does this interval contain no version at all?
fn is_empty(lower: &Bound<Version>, upper: &Bound<Version>) -> bool {
    match (lower, upper) {
        (Unbounded, _) | (_, Unbounded) => false,
        (Included(low) | Excluded(low), Included(high) | Excluded(high)) => match low.cmp(high) {
            Ordering::Greater => true,
            Ordering::Equal => !matches!((lower, upper), (Included(_), Included(_))),
            Ordering::Less => false,
        },
    }
}

/// How much of [`PINNED_SERIES`] a requirement still admits.
///
/// The only distinction [`requirement_admits_series_patches`] reads out of
/// this is whether it is [`SeriesReach::WholeTail`] — a range that caps the
/// series short or misses it entirely is equally a failure to admit every
/// {PINNED_SERIES}.x patch, so the two non-tail cases carry no payload to
/// report a finding with.
enum SeriesReach {
    /// Every release from some floor upward, however high the patch number
    /// climbs.
    WholeTail,
    /// In-series releases only up to some point short of the next series.
    CappedAt,
    /// Nothing inside the series at all.
    Nothing,
}

/// Which part of [`PINNED_SERIES`] `req` still admits.
///
/// An interval computation for the same reason [`comparator_bounds`] is one. A
/// probe at a single high in-series version cannot tell `>=0.8, <0.8.30`, which
/// admits 0.8.23 through 0.8.29, from a range that admits nothing at all — and
/// a guard that answers with one then reports the second about the first.
///
/// The property is the whole *tail*, not "more than one release": the number
/// the next security patch will carry is not knowable in advance, so any
/// ceiling below the next series can block it. A bound's pre-release does not
/// count towards that ceiling — `<=0.9.0-alpha` stops at an endpoint that
/// already sorts above every `0.8.x` release, so it caps nothing.
///
/// Everything here is counted in *releases*. A pre-release is not a patch
/// anyone can receive — Renovate does not propose one by default — so an
/// interval that contains only pre-releases admits nothing, however non-empty
/// it is as a set of versions. `=0.9.0-alpha` is the case that makes the
/// difference visible: it sits inside `[0.8.0, 0.9.0)` by semver ordering, and
/// reading that as "still admits the series" would call the tightest possible
/// freeze a healthy pin.
fn series_reach(req: &VersionReq) -> Result<SeriesReach> {
    let (floor, next) = pinned_bounds();
    let (lower, upper) = requirement_bounds(req)?;
    // The lowest in-series *release* at or above the floor this range sets.
    let candidate = match &lower {
        Unbounded => floor.clone(),
        // A pre-release bound sorts below the release it names, so that release
        // is the first one at or above it whether the bound is open or closed.
        Included(bound) | Excluded(bound) if !bound.pre.is_empty() => {
            Version::new(bound.major, bound.minor, bound.patch)
        }
        Included(bound) => bound.clone(),
        Excluded(bound) => Version::new(bound.major, bound.minor, bound.patch + 1),
    };
    let lowest = std::cmp::max(candidate, floor);
    let within_upper = match &upper {
        Unbounded => true,
        Included(bound) => lowest <= *bound,
        Excluded(bound) => lowest < *bound,
    };
    if lowest >= next || !within_upper {
        return Ok(SeriesReach::Nothing);
    }
    let reaches_tail =
        |bound: &Version| (bound.major, bound.minor, bound.patch) >= (next.major, next.minor, next.patch);
    Ok(match upper {
        Unbounded => SeriesReach::WholeTail,
        Included(bound) | Excluded(bound) if reaches_tail(&bound) => SeriesReach::WholeTail,
        Included(_) | Excluded(_) => SeriesReach::CappedAt,
    })
}

/// Is this concrete, resolved version inside [`PINNED_SERIES`]?
///
/// Full semver, not a string prefix: `0.81.0` starts with `0.8` and is a
/// different series.
pub fn version_tracks_pin(version: &str) -> Result<bool> {
    let version = Version::parse(version).with_context(|| format!("`{version}` is not a semver version"))?;
    let (floor, next) = pinned_bounds();
    Ok(version >= floor && version < next)
}

/// Does `req` admit anything outside [`PINNED_SERIES`]? Returns a version it
/// lets through, or `None` if it confines to the pin.
///
/// This is the effectiveness question, asked of a Renovate `allowedVersions`
/// range and of an upstream's declared requirement alike. A range is not
/// "constraining schemars" because it exists — `"<2"`, `"*"` and `"^0.8.22"`
/// are all constraints, and only the last one holds the pin.
pub fn requirement_admits_beyond_pin(req: &str) -> Result<Option<Version>> {
    let parsed = parse_requirement(req)?;
    let (_, next) = pinned_bounds();
    let (lower, upper) = requirement_bounds(&parsed)?;
    // A range whose bounds cross is self-contradictory: it admits nothing at
    // all, and so admits nothing beyond the pin either. That it also blocks
    // every in-series patch is [`requirement_admits_series_patches`]'s finding
    // to report, with the message that fits.
    if is_empty(&lower, &upper) || !reaches(&upper, &next) {
        return Ok(None);
    }
    // Report a version the caller can act on rather than the bound itself. The
    // interval is contiguous, so the first admitted version at or past the pin
    // is either the next series' first release or the range's own floor.
    let witness = if at_or_above(&lower, &next) {
        next.clone()
    } else {
        match &lower {
            Unbounded => next.clone(),
            Included(bound) => bound.clone(),
            // A pre-release floor has no successor to name; the release it
            // leads to is the next thing the range admits.
            Excluded(bound) => Version::new(bound.major, bound.minor, bound.patch),
        }
    };
    // The witness is the finding, so it has to be real. Where the interval says
    // "reaches past the pin" and no version can be named to show it, that is a
    // gap in this module's model of semver, not a verdict on the range — and
    // reporting a version the requirement does not admit is worse than either.
    if !parsed.matches(&witness) {
        bail!(
            "`{req}` has an interval that reaches past the {PINNED_SERIES} series, but this guard cannot name \
             a version it admits there: {witness}, the first candidate in that interval, is not a match. Teach \
             `comparator_bounds` the shape rather than reading this as a pass."
        );
    }
    Ok(Some(witness))
}

/// Does `req` still let every patch release inside [`PINNED_SERIES`] through?
///
/// The Renovate rule is deliberately a range and not `enabled: false` so a
/// 0.8.x security patch still reaches us. A range that has tightened onto one
/// exact version has quietly become that `enabled: false`; so has one that
/// merely caps the series short, because the patch carrying the fix may be
/// numbered above the cap. See [`series_reach`].
pub fn requirement_admits_series_patches(req: &str) -> Result<bool> {
    Ok(matches!(
        series_reach(&parse_requirement(req)?)?,
        SeriesReach::WholeTail
    ))
}

/// Renovate reads `allowedVersions` for a cargo dependency through
/// `modules/versioning/cargo`, which converts the range to npm's spelling and
/// hands it to node-semver. node-semver separates ANDed comparators with
/// whitespace; Rust's `semver` insists on a comma. `>=0.8.22 <0.9` is a working
/// pin that `renovate-config-validator --strict` accepts, so rejecting it is a
/// red on a config that holds — put the comma in rather than refuse to read it.
///
/// Only a separator is rewritten: the space in `>= 0.8.22` does not precede a
/// comparator and is left alone.
fn comma_separate(req: &str) -> String {
    let mut out = String::with_capacity(req.len() + 4);
    for (index, current) in req.char_indices() {
        if current.is_whitespace() {
            let follows_comparator = req[index..].trim_start().starts_with(['<', '>', '=', '^', '~', '*']);
            let already_separated = out.trim_end().ends_with(',');
            if follows_comparator && !already_separated && !out.trim().is_empty() {
                out.push(',');
            }
        }
        out.push(current);
    }
    out
}

fn parse_requirement(req: &str) -> Result<VersionReq> {
    // node-semver's `||` is a union of intervals; this guard carries one
    // interval, and quietly reading only half of a union is how a range that
    // readmits 2.x passes for a pin.
    if req.contains("||") {
        bail!(
            "`{req}` is an OR range. Renovate reads `allowedVersions` through node-semver, which unions the \
             alternatives, while this guard evaluates a single interval against the one PINNED_SERIES \
             ({PINNED_SERIES}) names — so it would read at most one branch and could call a range that \
             readmits the next series up a pin. Express the constraint as one range, or teach this check to \
             union them."
        );
    }
    VersionReq::parse(&comma_separate(req)).with_context(|| {
        format!(
            "`{req}` is not a semver requirement range. This guard compares the range's interval against the \
             one PINNED_SERIES ({PINNED_SERIES}) names, so it cannot read a regex or glob spelling; express \
             the constraint as a semver range, or teach this check the other form."
        )
    })
}

// Cargo.lock — the resolved signal ====================================================================================

#[derive(Deserialize)]
struct Lockfile {
    #[serde(rename = "package", default)]
    packages: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// Which `schemars` [`UPSTREAM`] actually resolved against, as a
/// `(upstream version, schemars version)` pair — e.g. `("0.6.2", "0.8.22")`.
///
/// Read out of `Cargo.lock` rather than `cargo metadata`: the lockfile is a
/// tracked file, so this needs no subprocess, no registry and no network, which
/// is what lets it run in the archive lane. See the module doc for what this
/// signal is blind to and what covers that.
///
/// A lockfile dependency entry carries its version only when the name is
/// ambiguous — which it is today (three `schemars` are locked) — so a bare
/// `"schemars"` is resolved against the sole `[[package]]` entry instead.
pub fn upstream_schemars(lock: &str) -> Result<(String, String)> {
    let lockfile: Lockfile = toml::from_str(lock).context("failed to parse Cargo.lock")?;

    let upstream: Vec<&LockPackage> = lockfile.packages.iter().filter(|p| p.name == UPSTREAM).collect();
    let upstream = match upstream.as_slice() {
        [] => bail!(
            "`{UPSTREAM}` is not in Cargo.lock at all. If typify was dropped, this pin has no reason to exist \
             and both it and this module should go; if it was renamed, this check needs to follow it.\n\
             {WHEN_UPSTREAM_MOVES}"
        ),
        [one] => *one,
        many => {
            let versions: Vec<&str> = many.iter().map(|p| p.version.as_str()).collect();
            bail!(
                "`{UPSTREAM}` is locked at {} different versions ({}). This is not a schemars problem: \
                 something in the workspace now pulls a second `typify`, and one pin cannot describe both \
                 upstreams. Unify the `typify` versions — or, if the split is deliberate, teach this check \
                 which one `crates/common/build.rs` compiles against — before reading anything here as a \
                 verdict on schemars.",
                many.len(),
                versions.join(", ")
            )
        }
    };

    let entry = upstream
        .dependencies
        .iter()
        .find(|d| *d == "schemars" || d.starts_with("schemars "));
    let Some(entry) = entry else {
        bail!(
            "`{UPSTREAM}` {} no longer has `schemars` among its locked dependencies. This is the expected end \
             state, not a broken check: upstream may have landed its own IR (oxidecomputer/typify#886), or \
             demoted schemars to a dev-dependency, or made it an optional feature nothing enables. Any of \
             those means the pin is obsolete.\n\
             {WHEN_UPSTREAM_MOVES}",
            upstream.version
        )
    };

    // `name version (source)`; cargo omits the trailing fields as they become
    // unambiguous, so take the version positionally rather than by splitting once.
    let schemars_version = match entry.split_whitespace().nth(1) {
        Some(version) => version.to_string(),
        // Unqualified: cargo omits the version only when one `schemars` is in
        // the graph, so the sole package entry is the one meant.
        None => {
            let all: Vec<&LockPackage> = lockfile.packages.iter().filter(|p| p.name == "schemars").collect();
            match all.as_slice() {
                [one] => one.version.clone(),
                [] => bail!(
                    "`{UPSTREAM}` {} depends on `schemars`, but no `schemars` package is locked. Cargo does \
                     not emit that; the lockfile has been hand-edited or truncated. Regenerate it with \
                     `cargo update --workspace`.",
                    upstream.version
                ),
                other => {
                    let versions: Vec<&str> = other.iter().map(|p| p.version.as_str()).collect();
                    bail!(
                        "`{UPSTREAM}` {} names `schemars` without a version, but {} `schemars` packages are \
                         locked ({}). Cargo drops the version only when the name is unambiguous, so this \
                         lockfile is inconsistent with itself — regenerate it with `cargo update --workspace` \
                         rather than trusting either reading.",
                        upstream.version,
                        other.len(),
                        versions.join(", ")
                    )
                }
            }
        }
    };
    Ok((upstream.version.clone(), schemars_version))
}

// cargo metadata — the declared signal ================================================================================

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetaPackage>,
}

#[derive(Deserialize)]
struct MetaPackage {
    name: String,
    version: String,
    dependencies: Vec<MetaDependency>,
}

#[derive(Deserialize)]
struct MetaDependency {
    name: String,
    req: String,
    /// `None` for a normal dependency; `"dev"`/`"build"` otherwise. Only the
    /// normal one constrains what a consumer must link against.
    kind: Option<String>,
}

/// Every normal `schemars` requirement [`UPSTREAM`] declares, as an
/// `(upstream version, requirements)` pair — e.g. `("0.6.2", ["^0.8.22"])`.
///
/// A list, not one string: a crate may declare the same dependency several
/// times behind different optional features, which is precisely how a crate
/// dual-supports two incompatible series (`serde_with` 3.18.0 declares
/// `^0.8.16`, `^0.9.0` and `^1.0.2` this way). If typify ever does that, every
/// one of its requirements has to stay inside the pin — one that admits 1.x is
/// a bump waiting for a resolver nudge, and the lockfile shows nothing.
///
/// Takes the JSON rather than running cargo so the parse is testable without a
/// registry; [`cargo_metadata_json`] is the caller that produces it.
pub fn declared_schemars_requirements(metadata: &str) -> Result<(String, Vec<String>)> {
    let metadata: Metadata = serde_json::from_str(metadata).context("failed to parse `cargo metadata` output")?;

    let upstream: Vec<&MetaPackage> = metadata.packages.iter().filter(|p| p.name == UPSTREAM).collect();
    let upstream = match upstream.as_slice() {
        [] => bail!(
            "`{UPSTREAM}` does not appear in `cargo metadata`. If typify was dropped, this pin has no reason \
             to exist and both it and this module should go; if it was renamed, this check needs to follow \
             it.\n{WHEN_UPSTREAM_MOVES}"
        ),
        [one] => *one,
        many => {
            let versions: Vec<&str> = many.iter().map(|p| p.version.as_str()).collect();
            bail!(
                "`{UPSTREAM}` appears at {} different versions in `cargo metadata` ({}). This is not a \
                 schemars problem: something in the workspace now pulls a second `typify`. Unify them before \
                 reading anything here as a verdict on schemars.",
                many.len(),
                versions.join(", ")
            )
        }
    };

    let reqs: Vec<String> = upstream
        .dependencies
        .iter()
        .filter(|d| d.name == "schemars" && d.kind.is_none())
        .map(|d| d.req.clone())
        .collect();
    if reqs.is_empty() {
        bail!(
            "`{UPSTREAM}` {} declares no normal `schemars` dependency. This is the expected end state, not a \
             broken check: upstream may have landed its own IR (oxidecomputer/typify#886), or moved schemars \
             to dev/build dependencies. Either way the pin is obsolete.\n{WHEN_UPSTREAM_MOVES}",
            upstream.version
        );
    }
    Ok((upstream.version.clone(), reqs))
}

/// `cargo metadata --format-version 1` for the workspace at `repo_root`.
///
/// No `--offline`: with a warm cache and a current `Cargo.lock` cargo reaches
/// the network for nothing, and where the cache is cold the registry is the
/// only place the declared requirement exists — failing there would make this
/// check pass by not running, which is the failure mode the whole module is
/// about. `--locked` keeps it read-only: it refuses rather than rewriting a
/// lockfile that has drifted.
pub fn cargo_metadata_json(repo_root: &Path) -> Result<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(&cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `{cargo} metadata`"))?;
    if !out.status.success() {
        bail!(
            "`cargo metadata --locked` failed, so `{UPSTREAM}`'s declared schemars requirement could not be \
             read and this half of the guard did not run. It needs a resolvable workspace and, from a cold \
             `CARGO_HOME`, a registry to fetch from — on a fresh clone with no network there is nothing to \
             read and nothing to conclude. Fix what cargo reports below and re-run; the offline half reads \
             tracked files only and is unaffected. Cargo said:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8(out.stdout).context("`cargo metadata` emitted non-UTF-8 output")
}

// crates/common/Cargo.toml — the local pin ============================================================================

/// Path this pin's manifest lives at, relative to the repo root.
const LOCAL_MANIFEST: &str = "crates/common/Cargo.toml";

/// The `schemars` build-dependency requirement declared by
/// `crates/common/Cargo.toml`.
pub fn local_schemars_requirement(manifest: &str) -> Result<String> {
    let doc: toml::Value = toml::from_str(manifest).context("failed to parse crates/common/Cargo.toml")?;
    let entry = doc
        .get("build-dependencies")
        .and_then(|d| d.get("schemars"))
        .context("crates/common/Cargo.toml declares no `schemars` build-dependency")?;
    let req = match entry {
        toml::Value::String(s) => s.clone(),
        table => table
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .context("crates/common/Cargo.toml's `schemars` build-dependency has no `version`")?,
    };
    Ok(req)
}

/// Does `crates/common/Cargo.toml` pin the series this module thinks it does?
///
/// Not the same question as "does it agree with typify" — that one the compiler
/// answers with `E0603`. This one catches [`PINNED_SERIES`] and the manifest
/// drifting apart, which nothing else would notice: the guard would simply
/// start policing a series the build does not use.
pub fn check_local_pin(manifest: &str) -> Result<()> {
    let req = local_schemars_requirement(manifest)?;
    if let Some(admitted) = requirement_admits_beyond_pin(&req)? {
        bail!(
            "crates/common/Cargo.toml requires `schemars = \"{req}\"`, which admits {admitted} — outside the \
             {PINNED_SERIES} series this guard, the Renovate rule and build.rs are all written around. Either \
             the manifest or `PINNED_SERIES` in xtask/src/schemars_pin.rs was changed without the other; make \
             them agree before trusting anything else this check reports."
        );
    }
    Ok(())
}

// Entry points ========================================================================================================

/// Every check sourceable from tracked files: the resolved upstream version
/// and the local pin.
///
/// Split out from [`verify`] because this half needs no registry and therefore
/// runs in the nextest archive lane, where `cargo metadata` cannot resolve the
/// workspace at all. See the module doc.
pub fn verify_offline(repo_root: &Path) -> Result<()> {
    let lock = read(repo_root, "Cargo.lock")?;
    let (upstream_version, resolved) = upstream_schemars(&lock)?;
    if !version_tracks_pin(&resolved)? {
        bail!(
            "`{UPSTREAM}` {upstream_version} now resolves against schemars {resolved}, not {PINNED_SERIES}. \
             The pin in crates/common/Cargo.toml and the `allowedVersions` rule in .github/renovate.json \
             exist only because of that requirement, so both are now suppressing an update that may be \
             possible.\n{WHEN_UPSTREAM_MOVES}"
        );
    }

    check_local_pin(&read(repo_root, LOCAL_MANIFEST)?)?;
    Ok(())
}

/// [`verify_offline`] plus the declared-requirement signal, which needs a
/// registry. Backs `cargo xtask check-schemars-pin`.
pub fn verify(repo_root: &Path) -> Result<()> {
    verify_offline(repo_root)?;

    let (upstream_version, reqs) = declared_schemars_requirements(&cargo_metadata_json(repo_root)?)?;
    for req in &reqs {
        if let Some(admitted) = requirement_admits_beyond_pin(req)? {
            bail!(
                "`{UPSTREAM}` {upstream_version} declares `schemars = \"{req}\"`, which admits {admitted} — \
                 outside the {PINNED_SERIES} series crates/common/build.rs compiles against. Cargo.lock does \
                 not show this: a widened requirement leaves the locked 0.8 version untouched, so the pin \
                 would go on suppressing an update that has become possible.\n{WHEN_UPSTREAM_MOVES}"
            );
        }
    }
    Ok(())
}

fn read(repo_root: &Path, relative: &str) -> Result<String> {
    let path = repo_root.join(relative);
    std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))
}
