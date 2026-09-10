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
//! drifted into
//! permitting the next series up fails even though it still "constrains
//! schemars". Presence was never the property worth guarding — bindreams/hole#379
//! reopens on an `allowedVersions` of `"<2"` exactly as it does on no rule at
//! all.
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
//! **The residue:** the two signals cannot run in the same place. `cargo
//! metadata` needs a registry to resolve the graph, and `Test tooling` runs
//! from a nextest archive with no populated `CARGO_HOME` — there
//! `cargo metadata --offline` fails outright (on `cosca`, the first workspace
//! dep it cannot find). So the split is by lane, not by strength:
//!
//! - `schemars_pin_still_tracks_typify` (this crate's tests, and therefore the
//!   archive lane) checks everything readable from tracked files: the resolved
//!   version, the Renovate rule, and the local pin.
//! - `cargo xtask check-schemars-pin` checks those *plus* the declared
//!   requirement, and runs where a registry exists — the `check-schemars-pin`
//!   prek hook, i.e. every commit and the `Lint` CI job.
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

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use cargo_metadata::semver::{Version, VersionReq};
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

/// The half-open interval `[lower, upper)` a single comparator admits, with
/// `None` for "unbounded above".
///
/// Deliberately an interval computation and not a set of probe versions: a
/// probe set is only ever a sample, and `^1.0.2` — a perfectly ordinary way for
/// an upstream to move — admits nothing at `1.0.0`, `2.0.0` or any other round
/// number one would think to try. Sampling a range that is *defined* by its
/// endpoints is how a guard ends up green on the change it exists to catch.
fn comparator_bounds(c: &cargo_metadata::semver::Comparator) -> Result<(Version, Option<Version>)> {
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
    let floor = at(minor.unwrap_or(0), patch.unwrap_or(0));

    Ok(match c.op {
        Op::Exact | Op::Wildcard => (floor, Some(prefix_end())),
        Op::Greater => (prefix_end(), None),
        Op::GreaterEq => (floor, None),
        Op::Less => (Version::new(0, 0, 0), Some(floor)),
        Op::LessEq => (Version::new(0, 0, 0), Some(prefix_end())),
        Op::Tilde => (
            floor,
            Some(match minor {
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
            (floor, Some(end))
        }
        other => bail!(
            "this guard does not understand the semver operator in `{c}` ({other:?}). It compares a \
             requirement's interval against PINNED_SERIES ({PINNED_SERIES}), so an operator it cannot bound \
             must be taught here rather than assumed harmless."
        ),
    })
}

/// The interval a whole requirement admits: comparators are ANDed, so the
/// lower bounds combine by max and the upper bounds by min. No comparators
/// (`*`, or an empty requirement) means unbounded in both directions.
fn requirement_bounds(req: &VersionReq) -> Result<(Version, Option<Version>)> {
    let mut lower = Version::new(0, 0, 0);
    let mut upper: Option<Version> = None;
    for comparator in &req.comparators {
        let (comparator_lower, comparator_upper) = comparator_bounds(comparator)?;
        if comparator_lower > lower {
            lower = comparator_lower;
        }
        upper = match (upper, comparator_upper) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };
    }
    Ok((lower, upper))
}

/// A version inside the pin, above any patch upstream has released or will
/// plausibly release — the probe for "does this range still let 0.8.x patches
/// through".
fn in_series_probe() -> Version {
    let (floor, _) = pinned_bounds();
    Version::new(floor.major, floor.minor, 9999)
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
    // `upper <= lower` is a self-contradictory range: it admits nothing at all,
    // and so admits nothing beyond the pin either. That it also blocks every
    // in-series patch is [`requirement_admits_series_patches`]'s finding to
    // report, with the message that fits.
    if upper.is_some_and(|upper| upper <= next || upper <= lower) {
        return Ok(None);
    }
    // Report a version the caller can act on rather than the bound itself. The
    // interval is contiguous, so the first admitted version at or past the pin
    // is either the next series' first release or the range's own floor.
    let mut witness = lower.max(next.clone());
    if !parsed.matches(&witness) {
        witness.patch += 1;
    }
    Ok(Some(if parsed.matches(&witness) { witness } else { next }))
}

/// Does `req` still let patch releases inside [`PINNED_SERIES`] through?
///
/// The Renovate rule is deliberately a range and not `enabled: false` so a
/// 0.8.x security patch still reaches us; a range that has tightened onto one
/// exact version has quietly become the `enabled: false` it was written to
/// avoid.
pub fn requirement_admits_series_patches(req: &str) -> Result<bool> {
    let parsed = parse_requirement(req)?;
    Ok(parsed.matches(&in_series_probe()))
}

fn parse_requirement(req: &str) -> Result<VersionReq> {
    VersionReq::parse(req).with_context(|| {
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
             read. This check needs a resolvable workspace and a registry; run it where `cargo` can resolve \
             (the `check-schemars-pin` prek hook and the `Lint` CI job both can). Cargo said:\n{}",
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

/// Does `.github/renovate.json` still carry a rule that *effectively* stops
/// Renovate proposing a `schemars` bump past [`PINNED_SERIES`]?
///
/// Effectively, not merely present. Every clause below is load-bearing, and a
/// rule failing any one of them suppresses nothing while looking exactly like a
/// rule that does:
///
/// - it must name `schemars`;
/// - it must not be `enabled: false` (which would also block 0.8.x patches —
///   the reason the rule is a range in the first place);
/// - it must reach the `cargo` manager;
/// - its `allowedVersions` must exclude the next series up, evaluated as a
///   semver range against probes derived from [`PINNED_SERIES`], while still
///   admitting patches inside it;
/// - no *later* rule may re-widen it. Renovate is last-wins, which is why this
///   file's own comments insist the compiler rules stay last.
pub fn check_renovate_rule(config: &str) -> Result<()> {
    let doc: serde_json::Value = serde_json::from_str(config).context("failed to parse .github/renovate.json")?;
    let empty = Vec::new();
    let rules = doc.get("packageRules").and_then(|r| r.as_array()).unwrap_or(&empty);

    let Some(index) = rules.iter().position(names_schemars) else {
        bail!(
            ".github/renovate.json has no packageRule naming `schemars`. Without one Renovate re-proposes the \
             bump past {PINNED_SERIES} that `{UPSTREAM}` cannot compile against — bindreams/hole#379, \
             permanently red. Restore the rule, or, if upstream has moved, delete this module too."
        )
    };
    let rule = &rules[index];

    if rule.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        bail!(
            ".github/renovate.json's `schemars` rule is `enabled: false`. That suppresses the impossible bump \
             but also every 0.8.x patch, including a security one — which is exactly why this rule is written \
             as an `allowedVersions` range instead. Restore the range."
        );
    }

    if let Some(managers) = rule.get("matchManagers").and_then(|m| m.as_array()) {
        if !managers.iter().any(|m| m.as_str() == Some("cargo")) {
            let listed: Vec<&str> = managers.iter().filter_map(|m| m.as_str()).collect();
            bail!(
                ".github/renovate.json's `schemars` rule is scoped to matchManagers [{}], which does not \
                 include `cargo`. `schemars` is a Rust dependency, so the rule never applies and \
                 bindreams/hole#379 is re-proposed on the next run.",
                listed.join(", ")
            );
        }
    }

    let Some(allowed) = rule.get("allowedVersions").and_then(|v| v.as_str()) else {
        bail!(
            ".github/renovate.json's `schemars` rule declares no `allowedVersions`. Naming the dependency \
             constrains nothing on its own; the range is what suppresses the bump past {PINNED_SERIES}."
        )
    };

    if let Some(admitted) = requirement_admits_beyond_pin(allowed)? {
        bail!(
            ".github/renovate.json's `schemars` rule allows `{allowed}`, which admits {admitted} — outside \
             the {PINNED_SERIES} series `{UPSTREAM}` requires. The rule is present but no longer suppresses \
             anything: Renovate will propose the bump that fails crates/common/build.rs with E0603 \
             (bindreams/hole#379). Narrow the range back to the {PINNED_SERIES} series."
        );
    }

    if !requirement_admits_series_patches(allowed)? {
        bail!(
            ".github/renovate.json's `schemars` rule allows `{allowed}`, which excludes {} — so no {PINNED_SERIES}.x \
             patch can ever land, including a security one. The rule is a range rather than `enabled: false` \
             precisely to keep those flowing; widen it back to the whole {PINNED_SERIES} series.",
            in_series_probe()
        );
    }

    for (position, later) in rules.iter().enumerate().skip(index + 1) {
        if could_override_schemars(later) {
            bail!(
                ".github/renovate.json's packageRule #{position} can also match `schemars` under `cargo` and \
                 sets `allowedVersions`/`enabled` after the pin rule (#{index}). Renovate is last-wins, so it \
                 silently replaces the pin. Move the pin rule after it, or scope this one away from \
                 `schemars`.\nOffending rule: {later}"
            );
        }
    }
    Ok(())
}

/// Does this rule name `schemars` in either of Renovate's dependency-name
/// selectors?
fn names_schemars(rule: &serde_json::Value) -> bool {
    ["matchDepNames", "matchPackageNames"].iter().any(|key| {
        rule.get(key)
            .and_then(|n| n.as_array())
            .is_some_and(|n| n.iter().any(|v| v.as_str() == Some("schemars")))
    })
}

/// Could this rule neutralise the pin if Renovate evaluated it afterwards?
///
/// Conservative on the matching side and precise on the effect side: a rule
/// that sets neither `allowedVersions` nor `enabled: false` cannot override
/// anything the pin asserts, and is ignored no matter what it matches. One that
/// does is cleared only by a selector that provably excludes `schemars` or the
/// `cargo` manager — a glob counts as "might match", because it might.
fn could_override_schemars(rule: &serde_json::Value) -> bool {
    let overrides =
        rule.get("allowedVersions").is_some() || rule.get("enabled").and_then(|v| v.as_bool()) == Some(false);
    if !overrides {
        return false;
    }
    if let Some(managers) = rule.get("matchManagers").and_then(|m| m.as_array()) {
        if !managers.iter().any(|m| m.as_str() == Some("cargo")) {
            return false;
        }
    }
    for key in ["matchDepNames", "matchPackageNames"] {
        if let Some(names) = rule.get(key).and_then(|n| n.as_array()) {
            let reaches_schemars = names
                .iter()
                .filter_map(|v| v.as_str())
                .any(|name| name == "schemars" || name.contains('*'));
            if !reaches_schemars {
                return false;
            }
        }
    }
    true
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
    check_local_pin(&read(repo_root, "crates/common/Cargo.toml")?)?;
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
