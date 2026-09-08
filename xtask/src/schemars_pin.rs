//! Is `typify` still the reason `schemars` is held at 0.8?
//!
//! Backs the `schemars_pin_still_tracks_typify` conformance test.
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
//! Cargo does not catch this. Two semver-incompatible `schemars` already
//! coexist in this tree (`serde_with` pulls 0.9 beside typify's 0.8), so a
//! bump resolves cleanly and only fails at compile time. Renovate therefore
//! cannot see the constraint either, which is why `.github/renovate.json`
//! carries an `allowedVersions` rule and why that rule needs an expiry.
//!
//! ## What this checks, and what the compiler already checks
//!
//! It does NOT check that `crates/common/Cargo.toml` agrees with typify. It
//! cannot: a mismatch fails `crates/common/build.rs` to compile with the very
//! `E0603` above, so any run of this test already proves that agreement. An
//! assertion that can only execute when it is already true detects nothing —
//! the shape bindreams/hole#894 exists to stop.
//!
//! What the compiler cannot see is the other two: that upstream still requires
//! 0.8, and that the Renovate rule which suppresses the impossible bump is
//! still there. Those are what this guards.
//!
//! ## Why this is a test and not a comment
//!
//! The pin is correct only while the upstream fact holds. Left as prose it
//! would outlive that fact silently: the `allowedVersions` rule would keep
//! suppressing a bump that had become possible, and nobody would notice,
//! because a suppressed update produces no signal at all. This test reads
//! which `schemars` typify actually resolved against out of `Cargo.lock` and
//! fails the moment it stops being 0.8 — turning "upstream moved" from something
//! someone has to remember to check into a red build with instructions.
//!
//! Note the eventual fix is not expected to be a `schemars` bump. Typify's
//! maintainer has said the schemars schema structures "have been removed. We
//! will roll our own IR" (oxidecomputer/typify#886), so when this test fires,
//! read that issue before assuming the answer is `schemars = "1"`.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The crate whose choice decides ours. `typify-impl` rather than the `typify`
/// facade: the facade's own `schemars` entry is a dev-dependency (its
/// doctests), while `typify-impl` is what holds the schema types in its public
/// API.
pub const UPSTREAM: &str = "typify-impl";

/// The major.minor series `crates/common/build.rs` compiles against.
pub const PINNED_SERIES: &str = "0.8";

// Cargo.lock ==========================================================================================================

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
/// Read out of `Cargo.lock` rather than `cargo metadata`. The lockfile is a
/// tracked file, so this needs no subprocess, no registry and no network —
/// which matters, because `Test tooling` runs from a nextest archive where
/// `cargo metadata --offline` cannot resolve the workspace at all (it fails on
/// `cosca`). The resolved version answers the question just as well as the
/// declared requirement: if upstream ever admits schemars 1.x, that is what
/// resolution will pick, and this fires.
///
/// A lockfile dependency entry carries its version only when the name is
/// ambiguous — which it is today (`serde_with` pulls schemars 0.9 beside
/// typify's 0.8) — so a bare `"schemars"` is resolved against the sole
/// `[[package]]` entry instead.
pub fn upstream_schemars(lock: &str) -> Result<(String, String)> {
    let lockfile: Lockfile = toml::from_str(lock).context("failed to parse Cargo.lock")?;

    let upstream: Vec<&LockPackage> = lockfile.packages.iter().filter(|p| p.name == UPSTREAM).collect();
    let upstream = match upstream.as_slice() {
        [] => bail!(
            "`{UPSTREAM}` is not in Cargo.lock. If typify was dropped, this pin has no reason to              exist and both it and this module should go; if it was renamed, this check needs to              follow it."
        ),
        [one] => *one,
        many => bail!(
            "`{UPSTREAM}` resolves to {} versions in Cargo.lock; one pin cannot describe them all",
            many.len()
        ),
    };

    let entry = upstream
        .dependencies
        .iter()
        .find(|d| d == &"schemars" || d.starts_with("schemars "))
        .with_context(|| {
            format!(
                "`{UPSTREAM}` {} no longer depends on schemars at all. Upstream may have landed its                  own IR (oxidecomputer/typify#886), which means this pin is obsolete rather than                  this check being broken.",
                upstream.version
            )
        })?;

    let schemars_version = match entry.split_once(' ') {
        Some((_, version)) => version.to_string(),
        // Unqualified: only one `schemars` in the graph, so the sole package
        // entry is the one meant.
        None => {
            let all: Vec<&LockPackage> = lockfile.packages.iter().filter(|p| p.name == "schemars").collect();
            match all.as_slice() {
                [one] => one.version.clone(),
                other => bail!(
                    "`{UPSTREAM}` names schemars without a version, but {} schemars packages are                      locked; cannot tell which it resolved against",
                    other.len()
                ),
            }
        }
    };
    Ok((upstream.version.clone(), schemars_version))
}

/// Is `version` inside the [`PINNED_SERIES`]?
///
/// A series test, not a full semver comparison: the question is only "which
/// 0.x line is this", and for a 0.x crate the minor IS the breaking axis. The
/// leading-operator strip lets the same predicate read a requirement string
/// (`^0.8.22`, `~0.8`) as well as a resolved version, so a caller that has one
/// rather than the other needs no second function.
pub fn requirement_tracks_pin(version: &str) -> bool {
    let bare = version.trim_start_matches(['^', '~', '=', '>', '<', ' ']);
    bare == PINNED_SERIES || bare.starts_with(&format!("{PINNED_SERIES}."))
}

// Renovate ============================================================================================================

/// Does `.github/renovate.json` still carry the rule that stops Renovate
/// proposing a `schemars` bump past [`PINNED_SERIES`]?
///
/// Checked alongside the upstream fact so the two cannot drift apart: a rule
/// left behind after upstream moves silently suppresses a now-valid update,
/// and a rule removed while upstream still blocks reopens the permanently-red
/// PR this whole mechanism exists to close.
pub fn renovate_rule_present(config: &str) -> Result<bool> {
    let doc: serde_json::Value = serde_json::from_str(config).context("failed to parse .github/renovate.json")?;
    let Some(rules) = doc.get("packageRules").and_then(|r| r.as_array()) else {
        return Ok(false);
    };
    Ok(rules.iter().any(|rule| {
        let names = rule.get("matchDepNames").and_then(|n| n.as_array());
        let matches_schemars = names.is_some_and(|n| n.iter().any(|v| v.as_str() == Some("schemars")));
        let constrains = rule.get("allowedVersions").and_then(|v| v.as_str()).is_some();
        matches_schemars && constrains
    }))
}
