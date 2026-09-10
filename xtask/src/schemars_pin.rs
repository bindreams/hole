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
//! regardless of what the rest of the workspace wants — which is what left
//! bindreams/hole#379 permanently red.
//!
//! Cargo does not catch this. Three semver-incompatible `schemars` already
//! coexist in this tree — 0.8.22, 0.9.0 and 1.2.1, with `serde_with` 3.18.0
//! declaring all three as optional features and resolving to both 0.9.0 and
//! 1.2.1 — so 1.x is already vendored, a bump resolves cleanly, and the failure
//! only appears at compile time. Renovate therefore cannot see the constraint
//! either, which is why `.github/renovate.json` carries an `allowedVersions`
//! rule and why that rule needs an expiry.
//!
//! ## Three artefacts, one fact
//!
//! [`PINNED_SERIES`] is the fact. `.github/renovate.json`'s `allowedVersions`
//! and `crates/common/Cargo.toml`'s `schemars = "0.8"` are consequences of it,
//! and both are checked *against* it rather than compared textually: the
//! Renovate range is evaluated as an interval against the one derived from
//! `PINNED_SERIES` (see [`requirement_admits_beyond_pin`]), so a rule that has
//! drifted into permitting the next series up fails even though it still
//! "constrains schemars". Presence was never the property worth guarding —
//! bindreams/hole#379 reopens on an `allowedVersions` of `"<2"`, on a rule
//! Renovate no longer applies, and on no rule at all, identically.
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
//!   version, the Renovate rule, and the local pin.
//! - `cargo xtask check-schemars-pin` checks those *plus* the declared
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
//! manifest against [`PINNED_SERIES`], which is a different question and is not
//! compiler-covered: a constant edited out from under the guard would otherwise
//! leave it checking the wrong series.
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
use serde_json::{Map, Value};

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
enum SeriesReach {
    /// Every release from some floor upward, however high the patch number
    /// climbs.
    WholeTail,
    /// In-series releases only up to `highest`, which is itself admitted when
    /// `inclusive`.
    CappedAt { highest: Version, inclusive: bool },
    /// Nothing inside the series at all.
    Nothing,
}

impl SeriesReach {
    /// The clause naming what this range does to the series, for the finding.
    fn describe(&self) -> String {
        match self {
            SeriesReach::WholeTail => format!("admits every {PINNED_SERIES}.x release"),
            SeriesReach::Nothing => format!("admits no {PINNED_SERIES}.x release at all"),
            SeriesReach::CappedAt {
                highest,
                inclusive: false,
            } => format!("admits no {PINNED_SERIES}.x release at or above {highest}"),
            SeriesReach::CappedAt {
                highest,
                inclusive: true,
            } => format!("admits no {PINNED_SERIES}.x release above {highest}"),
        }
    }
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
        Included(highest) => SeriesReach::CappedAt {
            highest,
            inclusive: true,
        },
        Excluded(highest) => SeriesReach::CappedAt {
            highest,
            inclusive: false,
        },
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

// .github/renovate.json — the suppression rule ========================================================================

/// The dependency, manager, manifest path and manifest section a packageRule's
/// selectors are evaluated against. `schemars` reaches this repo only as a
/// `cargo` build-dependency of `crates/common/Cargo.toml`, so a rule scoped
/// away from any one of the four never applies to it.
///
/// The section is a selector subject because the `cargo` manager tags every
/// dependency with the table it was extracted from
/// (`modules/manager/cargo/schema.ts`: `dependencies`, `dev-dependencies`,
/// `build-dependencies`, `workspace.dependencies`), and `schemars` is declared
/// under `[build-dependencies]`.
const PIN_DEPENDENCY: &str = "schemars";
const PIN_MANAGER: &str = "cargo";
const PIN_MANIFEST: &str = "crates/common/Cargo.toml";
const PIN_DEP_TYPE: &str = "build-dependencies";

/// What a `match*`/`exclude*` selector is matched against.
///
/// Renovate carries roughly fifteen selector keys and each one can scope a rule
/// away from `schemars` entirely — `matchDatasources: ["npm"]`,
/// `matchBaseBranches`, `matchRepositories`, `matchJsonata`, the `exclude*`
/// family. A rule so scoped is dead, and a dead rule suppresses exactly as much
/// as no rule at all. So the ones absent from this table are *rejected*, not
/// ignored, on the principle [`comparator_bounds`] already applies to semver
/// operators: a selector this guard cannot reason about must be taught here
/// rather than assumed harmless.
fn selector_subject(key: &str) -> Option<Subject> {
    Some(match key {
        "matchDepNames" | "matchPackageNames" => Subject::Name,
        // Renovate's pre-39 spelling: bare regexes rather than glob-or-`/re/`.
        "matchDepPatterns" | "matchPackagePatterns" => Subject::NamePattern,
        "matchManagers" => Subject::Manager,
        "matchFileNames" => Subject::File,
        "matchDepTypes" => Subject::DepType,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Subject {
    Name,
    NamePattern,
    Manager,
    File,
    DepType,
}

/// Is this option one `mergeChildConfig` *joins* rather than replaces when a
/// nested rule is flattened? Renovate carries the flag on the option definition
/// itself; these are the ones whose value this guard decides. `matchFileNames`
/// is deliberately absent — it is not mergeable, so a child's list replaces the
/// parent's.
///
/// A key this table gets wrong on some *other* selector cannot change a
/// verdict: every selector [`selector_subject`] does not know makes its rule
/// [`Verdict::Unknown`] whether it was joined or replaced.
fn joins_when_flattened(key: &str) -> bool {
    matches!(
        key,
        "matchDepNames" | "matchPackageNames" | "matchManagers" | "matchDepTypes" | "ignoreDeps"
    )
}

/// A three-valued selector verdict.
///
/// `Unknown` is not a shrug: it is the answer that makes the caller fail.
/// "Renovate does not apply this rule" and "this guard cannot tell whether
/// Renovate applies this rule" are different findings and must not share a
/// message — telling a maintainer to restore a rule that is present and working
/// is the false red that gets guards deleted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Selected,
    Excluded,
    Unknown,
}

impl Verdict {
    /// Distinct selectors are ANDed. One that provably excludes the dependency
    /// settles the rule whatever the others say — which is what stops an
    /// unreadable selector on an already-excluded rule from failing the check.
    fn and(self, other: Verdict) -> Verdict {
        match (self, other) {
            (Verdict::Excluded, _) | (_, Verdict::Excluded) => Verdict::Excluded,
            (Verdict::Unknown, _) | (_, Verdict::Unknown) => Verdict::Unknown,
            _ => Verdict::Selected,
        }
    }

    /// Entries within one selector are ORed.
    fn or(self, other: Verdict) -> Verdict {
        match (self, other) {
            (Verdict::Selected, _) | (_, Verdict::Selected) => Verdict::Selected,
            (Verdict::Unknown, _) | (_, Verdict::Unknown) => Verdict::Unknown,
            _ => Verdict::Excluded,
        }
    }

    fn of(hit: bool) -> Verdict {
        if hit {
            Verdict::Selected
        } else {
            Verdict::Excluded
        }
    }

    /// What a `!` in front of this entry makes of it. `Unknown` stays unknown:
    /// negating an answer this guard does not have does not produce one.
    fn negate(self) -> Verdict {
        match self {
            Verdict::Selected => Verdict::Excluded,
            Verdict::Excluded => Verdict::Selected,
            Verdict::Unknown => Verdict::Unknown,
        }
    }
}

/// `glob`'s reading of a minimatch pattern built the way Renovate builds every
/// one of them, `{ dot: true, nocase: true }`.
///
/// `require_literal_separator` because minimatch's `*` stops at a `/` — the
/// opposite of `glob`'s default, and the difference decides the one subject
/// with separators in it, [`PIN_MANIFEST`]. Without it `crates/*` and
/// `*/Cargo.toml`, which Renovate does not apply to
/// `crates/common/Cargo.toml`, both read as selecting it.
const MINIMATCH: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: false,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// minimatch's `**` spans zero or more path segments only where the segment
/// *is* exactly `**`; written anywhere else — `tauri-plugin-**`,
/// `**Cargo.toml`, or a longer run like `crates/***` — it is a plain `*`.
/// `glob` accepts `**` in that same whole-segment position only, so rewriting
/// the other spellings the way minimatch reads them makes the two agree rather
/// than approximating one with the other.
fn expand_globstars(matcher: &str) -> String {
    let bytes = matcher.as_bytes();
    let mut out = String::with_capacity(matcher.len());
    let (mut copied, mut index) = (0, 0);
    while index < bytes.len() {
        if bytes[index] != b'*' {
            index += 1;
            continue;
        }
        let run = index;
        while index < bytes.len() && bytes[index] == b'*' {
            index += 1;
        }
        if index - run < 2 {
            continue;
        }
        // minimatch tests the segment for equality with `**`, so a longer run
        // is not a globstar either: `crates/***` matches as `crates/*`.
        let globstar =
            index - run == 2 && (run == 0 || bytes[run - 1] == b'/') && (index == bytes.len() || bytes[index] == b'/');
        out.push_str(&matcher[copied..run]);
        out.push_str(if globstar { "**" } else { "*" });
        copied = index;
    }
    out.push_str(&matcher[copied..]);
    out
}

/// Does minimatch read this pattern with syntax `glob` has no equivalent for?
///
/// Two constructs, both live in Renovate because it passes neither `noext` nor
/// any brace option:
///
/// - **Brace alternation** (`{schemars,serde}`), which `glob` does not expand.
/// - **Extglob** (`@(a|b)`, `?()`, `*()`, `+()`, `!()`) — a `(` under one of
///   `?*+@!`. This one is the reason a bare `(` is *not* enough to disqualify a
///   pattern: minimatch treats unprefixed parentheses as literal, and so does
///   the literal branch below. `@(schemars)` selects `schemars`, but reading it
///   as a literal makes it select nothing, which is a dead rule read as a live
///   one.
fn beyond_glob(matcher: &str) -> bool {
    if matcher.contains(['{', '}']) {
        return true;
    }
    matcher
        .as_bytes()
        .windows(2)
        .any(|pair| pair[1] == b'(' && matches!(pair[0], b'?' | b'*' | b'+' | b'@' | b'!'))
}

/// Does one matcher entry select `subject`?
///
/// Renovate accepts a literal, a minimatch glob, a delimited `/regex/`
/// (optionally `/i`), and any of those under a `!` negation, which the caller
/// splits off. All are honoured — `.github/renovate.json` already spells
/// `matchPackageNames` with globs. A spelling this guard cannot decide, such as
/// anything [`beyond_glob`] names, returns `Unknown` rather than a guess in
/// either direction.
///
/// The glob path is case-insensitive because every minimatch Renovate builds
/// carries `nocase: true`; the regex path is not, because `parseRegexMatch`
/// asks for the `i` flag only when the spelling ends in one.
fn matcher_selects(matcher: &str, subject: &str) -> Verdict {
    // `matchRegexOrGlob` short-circuits a bare `*` to "everything" before
    // minimatch sees it, so it reaches a subject with separators in it that a
    // `*` glob would not.
    if matcher == "*" {
        return Verdict::Selected;
    }
    // `isRegexMatch` needs *both* delimiters (`/^!?\//` and `/\/i?$/`). With
    // only the opening one this is not a regex at all: Renovate hands it to
    // minimatch as an ordinary glob, so falling through is what Renovate does
    // rather than a guess about what it meant.
    if matcher.starts_with('/') && (matcher.ends_with('/') || matcher.ends_with("/i")) {
        let body = &matcher[1..];
        let body = body
            .strip_suffix("/i")
            .or_else(|| body.strip_suffix('/'))
            .unwrap_or(body);
        // The flag is read off the whole spelling, not off what was stripped:
        // `parseRegexMatch` tests `input.endsWith('i')`.
        let flags = if matcher.ends_with('i') { "(?i)" } else { "" };
        return regex_selects(&format!("{flags}{body}"), subject);
    }
    if beyond_glob(matcher) {
        return Verdict::Unknown;
    }
    // minimatch splits on `/` and matches segment by segment, so an empty
    // segment is a segment that has to match. `glob` has no such notion:
    // `crates/**/` selects nothing in minimatch and everything under
    // `crates/` in `glob`. A leading empty segment (`/schemars`) is left
    // alone — there the two already agree.
    if matcher.contains("//") || (matcher.len() > 1 && matcher.ends_with('/')) {
        return Verdict::Unknown;
    }
    if !matcher.contains(['*', '?', '[', ']']) {
        // A literal is a glob with no metacharacters, and inherits `nocase`.
        return Verdict::of(matcher.eq_ignore_ascii_case(subject));
    }
    match glob::Pattern::new(&expand_globstars(matcher)) {
        Ok(pattern) => Verdict::of(pattern.matches_with(subject, MINIMATCH)),
        Err(_) => Verdict::Unknown,
    }
}

fn regex_selects(pattern: &str, subject: &str) -> Verdict {
    match regex::Regex::new(pattern) {
        Ok(compiled) => Verdict::of(compiled.is_match(subject)),
        // Renovate's engine is not Rust's. One it accepts and this cannot
        // compile is undecidable here, not absent.
        Err(_) => Verdict::Unknown,
    }
}

/// One entry's own predicate, the way `getRegexOrGlobPredicate` builds it.
///
/// Whether an entry is *filed* as a negation is a separate question from what
/// its predicate says: `matchRegexOrGlobList` buckets on a single leading `!`,
/// but the predicate it then calls is built from the whole spelling, and
/// minimatch's `parseNegate` consumes *every* leading `!`, toggling each time.
/// So `!!foo` is filed under the negations while its predicate is the plain
/// `foo` — a positive requirement in the negative bucket. Stripping one `!` and
/// assuming the sense flipped reads that as "everything except foo".
fn entry_predicate(matcher: &str, subject: &str, bare_regex: bool) -> Verdict {
    if bare_regex {
        return regex_selects(matcher, subject);
    }
    // A delimited regex keeps its own `!` handling: `isRegexMatch` allows one
    // optional `!` before the opening `/`, and `parseRegexMatch` strips exactly
    // that one.
    if let Some(body) = matcher.strip_prefix('!') {
        if body.starts_with('/') && (body.ends_with('/') || body.ends_with("/i")) {
            return matcher_selects(body, subject).negate();
        }
    }
    let bare = matcher.trim_start_matches('!');
    let toggles = matcher.len() - bare.len();
    let hit = matcher_selects(bare, subject);
    if toggles.is_multiple_of(2) {
        hit
    } else {
        hit.negate()
    }
}

/// Does a whole selector list select `subject`?
///
/// `matchRegexOrGlobList`, line for line: an empty list selects nothing; if
/// there are positive entries at least one must hold; if there are negative
/// entries every one of them must hold. A list of only negations therefore
/// means "everything except", because the positive test is skipped rather than
/// failed — and an *empty* list is not that case, it is the `if
/// (!patterns.length) return false` on the first line, which leaves a rule that
/// still reads exactly like the pin, still validates, and is dead.
fn list_selects(matchers: &[Value], subject: &str, bare_regex: bool) -> Verdict {
    if matchers.is_empty() {
        return Verdict::Excluded;
    }
    // `some` over the positives, `every` over the negatives.
    let (mut some_positive, mut every_negative): (Option<Verdict>, Option<Verdict>) = (None, None);
    for entry in matchers {
        let Some(matcher) = entry.as_str() else {
            return Verdict::Unknown;
        };
        let holds = entry_predicate(matcher, subject, bare_regex);
        // The bucket is chosen by one leading `!`, whatever the predicate says.
        if !bare_regex && matcher.starts_with('!') {
            every_negative = Some(every_negative.unwrap_or(Verdict::Selected).and(holds));
        } else {
            some_positive = Some(some_positive.unwrap_or(Verdict::Excluded).or(holds));
        }
    }
    some_positive
        .unwrap_or(Verdict::Selected)
        .and(every_negative.unwrap_or(Verdict::Selected))
}

/// Would Renovate apply this packageRule to `schemars`, and if not — or if that
/// cannot be decided — which selector settled it?
fn rule_applies(rule: &Value) -> (Verdict, Option<String>) {
    let Some(fields) = rule.as_object() else {
        return (Verdict::Unknown, Some("the rule is not an object".into()));
    };
    let mut verdict = Verdict::Selected;
    let (mut excluded_by, mut unreadable) = (None, None);
    for (key, value) in fields {
        if !key.starts_with("match") && !key.starts_with("exclude") {
            continue;
        }
        let axis = match (selector_subject(key), value.as_array()) {
            // Every selector this table knows takes an array. A scalar there is
            // a different option shape than the one being evaluated.
            (Some(subject), Some(list)) => match subject {
                Subject::Name => list_selects(list, PIN_DEPENDENCY, false),
                Subject::NamePattern => list_selects(list, PIN_DEPENDENCY, true),
                Subject::Manager => list_selects(list, PIN_MANAGER, false),
                Subject::File => list_selects(list, PIN_MANIFEST, false),
                Subject::DepType => list_selects(list, PIN_DEP_TYPE, false),
            },
            _ => Verdict::Unknown,
        };
        let settled = match axis {
            Verdict::Excluded => &mut excluded_by,
            Verdict::Unknown => &mut unreadable,
            Verdict::Selected => {
                verdict = verdict.and(axis);
                continue;
            }
        };
        settled.get_or_insert_with(|| key.clone());
        verdict = verdict.and(axis);
    }
    let reason = match verdict {
        Verdict::Excluded => excluded_by,
        Verdict::Unknown => unreadable,
        Verdict::Selected => None,
    };
    (verdict, reason)
}

/// Does this rule select `schemars` *by name*, rather than reaching it inside a
/// broader scope? A blanket rule does not, which is what separates "no rule
/// names it" from "the rule that names it constrains nothing".
fn names_schemars(rule: &Value) -> Verdict {
    let mut verdict = Verdict::Excluded;
    for (key, value) in rule.as_object().into_iter().flatten() {
        let Some(list) = value.as_array() else { continue };
        verdict = match selector_subject(key) {
            Some(Subject::Name) => verdict.or(list_selects(list, PIN_DEPENDENCY, false)),
            Some(Subject::NamePattern) => verdict.or(list_selects(list, PIN_DEPENDENCY, true)),
            _ => verdict,
        };
    }
    verdict
}

/// Does this `ignoreDeps` list name the pinned dependency? Renovate's check is
/// `config.ignoreDeps.includes(depName)` — plain equality, not a glob.
fn ignores_pin(value: Option<&Value>) -> bool {
    value
        .and_then(|v| v.as_array())
        .is_some_and(|list| list.iter().any(|entry| entry.as_str() == Some(PIN_DEPENDENCY)))
}

/// Renovate does not *descend* into a nested `packageRules`. Migration
/// **flattens** it (`config/migration.ts`), replacing the parent with one
/// lifted copy per child, each folded through `mergeChildConfig`: the child's
/// fields win, except that a mergeable array option set on both sides is
/// concatenated.
///
/// Concatenation is a union, not an intersection, which is why a nested rule
/// cannot be dismissed by reading its parent: a parent scoped to `npm` does not
/// confine a `cargo` child, it widens the pair to both managers. Flattening
/// here rather than bailing also keeps an unrelated nested rule — one whose
/// flattened form cannot reach `schemars` — from reddening this guard.
fn flatten(rule: &Value) -> Vec<Value> {
    let Some(fields) = rule.as_object() else {
        return vec![rule.clone()];
    };
    let Some(children) = fields.get("packageRules").and_then(|nested| nested.as_array()) else {
        return vec![rule.clone()];
    };
    let mut parent = fields.clone();
    parent.remove("packageRules");
    children
        .iter()
        .flat_map(|child| flatten(&fold(&parent, child)))
        .collect()
}

/// One `mergeChildConfig` of a nested child onto its parent.
fn fold(parent: &Map<String, Value>, child: &Value) -> Value {
    let Some(child) = child.as_object() else {
        // Not an object, so not something `rule_applies` can read either; hand
        // it on unchanged and let it get the same answer it would at the top
        // level.
        return child.clone();
    };
    let mut merged = parent.clone();
    for (key, value) in child {
        let folded = match (joins_when_flattened(key), merged.get(key), value) {
            (true, Some(Value::Array(inherited)), Value::Array(own)) => {
                Value::Array(inherited.iter().chain(own).cloned().collect())
            }
            _ => value.clone(),
        };
        merged.insert(key.clone(), folded);
    }
    Value::Object(merged)
}

/// What Renovate resolves for `schemars` once every applying rule is merged.
struct Resolved {
    /// The last applying rule's `allowedVersions`, with its position.
    allowed: Option<(usize, String)>,
    /// The position of the last applying rule to leave it `enabled: false`.
    disabled: Option<usize>,
    /// The position of the first applying rule to list `schemars` in
    /// `ignoreDeps`. First, not last: `ignoreDeps` is a mergeable array, so a
    /// later rule adds to it and none can take a name back out.
    ignored: Option<usize>,
    /// Did any applying rule select `schemars` by name?
    named: bool,
    /// Rules that set `allowedVersions`/`enabled`/`ignoreDeps` but do not
    /// apply, as `#position (selector)` — the difference between a rule that is
    /// missing and one that is merely out of reach.
    sidelined: Vec<String>,
}

/// Merge every packageRule that applies to `schemars`, in order.
///
/// Renovate is last-wins across *all* matching rules, not "the first rule that
/// names it, then whatever follows": `[<2, <0.9]` resolves to `<0.9`, and a
/// grouping rule above the pin does not displace it.
fn resolve_schemars(rules: &[Value]) -> Result<Resolved> {
    let mut resolved = Resolved {
        allowed: None,
        disabled: None,
        ignored: None,
        named: false,
        sidelined: Vec::new(),
    };
    // A flattened child reports its parent's index: that is where a reader
    // finds it in the file, and the array is identity-flattened when nothing
    // nests.
    let flattened: Vec<(usize, Value)> = rules
        .iter()
        .enumerate()
        .flat_map(|(position, rule)| flatten(rule).into_iter().map(move |rule| (position, rule)))
        .collect();
    for (position, rule) in flattened {
        let rule = &rule;
        let allowed = match rule.get("allowedVersions") {
            None => None,
            Some(Value::String(range)) => Some(range.clone()),
            Some(other) => bail!(
                ".github/renovate.json's packageRule #{position} sets `allowedVersions` to {other}, which is \
                 not a string. `allowedVersions` is a string option: a one-element array is migrated to one \
                 (`config/migration.ts`) and anything else is rejected, and either way \
                 `renovate-config-validator --strict` fails the config before this guard sees it. Spell it as \
                 a bare range."
            ),
        };
        let enabled = rule.get("enabled").and_then(|v| v.as_bool());
        let ignored = ignores_pin(rule.get("ignoreDeps"));
        let (verdict, reason) = rule_applies(rule);
        if verdict == Verdict::Selected {
            resolved.named |= names_schemars(rule) == Verdict::Selected;
            if let Some(range) = allowed {
                resolved.allowed = Some((position, range));
            }
            if ignored {
                resolved.ignored.get_or_insert(position);
            }
            match enabled {
                Some(false) => resolved.disabled = Some(position),
                Some(true) => resolved.disabled = None,
                None => {}
            }
        } else if allowed.is_some() || enabled.is_some() || ignored {
            let selector = reason.unwrap_or_else(|| "an unnamed selector".into());
            if verdict == Verdict::Unknown {
                bail!(
                    ".github/renovate.json's packageRule #{position} sets \
                     `allowedVersions`/`enabled`/`ignoreDeps`, and this guard cannot determine whether \
                     Renovate applies it to `{PIN_DEPENDENCY}`: `{selector}` settled it, either because \
                     `selector_subject` does not know that key or because one of its entries is a spelling \
                     this guard cannot decide (a brace alternation, an extglob, or a regex Rust will not \
                     compile). A rule Renovate does not apply suppresses nothing while looking exactly like \
                     one that does, so an unreadable selector must be taught here rather than assumed \
                     harmless.\nRule: {rule}"
                );
            }
            resolved.sidelined.push(format!("#{position} (`{selector}`)"));
        }
        // A rule setting neither field cannot change what Renovate resolves
        // here, so whether it applies never has to be decided.
    }
    Ok(resolved)
}

/// Does `.github/renovate.json` still *effectively* stop Renovate proposing a
/// `schemars` bump past [`PINNED_SERIES`]?
///
/// Effectively, not merely present. The config is resolved the way Renovate
/// resolves it — every rule that applies to `schemars` under `cargo`, merged
/// last-wins — and the result must satisfy all of:
///
/// - some rule has to apply at all. Every `match*`/`exclude*` selector narrows
///   the set a rule reaches, and one this guard cannot evaluate is rejected
///   rather than ignored (see [`selector_subject`]);
/// - it must not resolve to `enabled: false`, nor to an `ignoreDeps` naming
///   `schemars` — Renovate's two spellings for the same skip, both of which
///   also block 0.8.x patches, the reason the rule is a range in the first
///   place;
/// - the resolved `allowedVersions` must exclude the next series up, evaluated
///   as an interval against the one [`PINNED_SERIES`] names, while still
///   admitting the whole patch tail inside it.
pub fn check_renovate_rule(config: &str) -> Result<()> {
    let doc: Value = serde_json::from_str(config).context("failed to parse .github/renovate.json")?;
    let empty = Vec::new();
    let rules = doc.get("packageRules").and_then(|r| r.as_array()).unwrap_or(&empty);
    let resolved = resolve_schemars(rules)?;

    // `fetch.js` reads the ignore first, two lines above the `enabled === false`
    // branch and after the same packageRules merge, so this check goes first
    // too.
    let ignore_site = match (ignores_pin(doc.get("ignoreDeps")), resolved.ignored) {
        (true, _) => Some("the top-level `ignoreDeps`".to_string()),
        (false, Some(position)) => Some(format!("`ignoreDeps` on packageRule #{position}")),
        (false, None) => None,
    };
    if let Some(site) = ignore_site {
        bail!(
            ".github/renovate.json lists `{PIN_DEPENDENCY}` in {site}. `fetch.js` sets \
             `skipReason: \"ignored\"` two lines above the `enabled === false` branch and both run after the \
             packageRules merge, so an ignore is `enabled: false` under a second name: it suppresses the \
             impossible bump but also every {PINNED_SERIES}.x patch, including a security one — which is \
             exactly why the pin is written as an `allowedVersions` range instead. Nothing takes a name back \
             out of `ignoreDeps`; drop it and leave the range to do the suppressing."
        );
    }

    if let Some(position) = resolved.disabled {
        bail!(
            ".github/renovate.json resolves `{PIN_DEPENDENCY}` to `enabled: false` (packageRule #{position}). \
             That suppresses the impossible bump but also every {PINNED_SERIES}.x patch, including a security \
             one — which is exactly why the pin is written as an `allowedVersions` range instead. Renovate \
             merges every applying rule last-wins, so a later blanket disable counts for as much as the pin \
             rule's own fields. Restore the range."
        );
    }

    let Some((position, allowed)) = resolved.allowed else {
        if resolved.named {
            bail!(
                ".github/renovate.json's `{PIN_DEPENDENCY}` rule declares no `allowedVersions`. Naming the \
                 dependency constrains nothing on its own; the range is what suppresses the bump past \
                 {PINNED_SERIES}."
            );
        }
        let sidelined = match resolved.sidelined.as_slice() {
            [] => String::new(),
            out_of_reach => format!(
                " packageRule {} sets `allowedVersions`/`enabled`/`ignoreDeps`, but that selector keeps it off \
                 `{PIN_DEPENDENCY}` as a `{PIN_MANAGER}` dependency of {PIN_MANIFEST}, so Renovate never \
                 applies it.",
                out_of_reach.join(", ")
            ),
        };
        bail!(
            ".github/renovate.json has no packageRule naming `{PIN_DEPENDENCY}` that Renovate would apply to \
             it.{sidelined} Without one Renovate re-proposes the bump past {PINNED_SERIES} that `{UPSTREAM}` \
             cannot compile against — bindreams/hole#379, permanently red. Restore the rule, or, if upstream \
             has moved, delete this module too."
        )
    };

    if let Some(admitted) = requirement_admits_beyond_pin(&allowed)? {
        bail!(
            ".github/renovate.json resolves `{PIN_DEPENDENCY}` to `allowedVersions` `{allowed}` (packageRule \
             #{position}), which admits {admitted} — outside the {PINNED_SERIES} series `{UPSTREAM}` \
             requires. The rule is present but no longer suppresses anything: Renovate will propose the bump \
             that fails crates/common/build.rs with E0603 (bindreams/hole#379). Renovate merges every \
             applying rule last-wins, so this is the range that applies. Narrow it back to the \
             {PINNED_SERIES} series."
        );
    }

    let reach = series_reach(&parse_requirement(&allowed)?)?;
    if !matches!(reach, SeriesReach::WholeTail) {
        bail!(
            ".github/renovate.json resolves `{PIN_DEPENDENCY}` to `allowedVersions` `{allowed}` (packageRule \
             #{position}), which {}, so no such patch can ever land — a security one included. The rule is a \
             range rather than `enabled: false` precisely to keep {PINNED_SERIES}.x patches flowing, and the \
             number the next one will carry is not knowable in advance; widen it back to the whole \
             {PINNED_SERIES} series.",
            reach.describe()
        );
    }
    Ok(())
}

// Entry points ========================================================================================================

/// Every check sourceable from tracked files: the resolved upstream version,
/// the Renovate rule, and the local pin.
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

    check_renovate_rule(&read(repo_root, ".github/renovate.json")?)?;
    check_local_pin(&read(repo_root, PIN_MANIFEST)?)?;
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
