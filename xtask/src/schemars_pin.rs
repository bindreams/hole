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
//! typify's own declared requirement out of `cargo metadata` and fails the
//! moment it stops being 0.8 — turning "upstream moved" from something
//! someone has to remember to check into a red build with instructions.
//!
//! Note the eventual fix is not expected to be a `schemars` bump. Typify's
//! maintainer has said the schemars schema structures "have been removed. We
//! will roll our own IR" (oxidecomputer/typify#886), so when this test fires,
//! read that issue before assuming the answer is `schemars = "1"`.

use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The crate whose requirement decides ours. `typify-impl` rather than the
/// `typify` facade: the facade's own `schemars` entry is a dev-dependency
/// (its doctests), while `typify-impl` is what actually holds the schema
/// types in its public API.
pub const UPSTREAM: &str = "typify-impl";

/// The major.minor series `crates/common/build.rs` compiles against. Bare
/// `0.8` rather than a full requirement string: what matters is the series,
/// and the patch floor is typify's to raise.
pub const PINNED_SERIES: &str = "0.8";

// cargo metadata ======================================================================================================

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
    req: String,
    /// `None` for a normal dependency; `"dev"`/`"build"` otherwise. Only the
    /// normal one constrains what a consumer must link against.
    kind: Option<String>,
}

/// `typify-impl`'s declared `schemars` requirement, as a `(version, req)`
/// pair — e.g. `("0.7.0", "^0.8.22")`.
///
/// `--offline` so this never reaches the network: the metadata comes from the
/// already-vendored registry entry that the build itself resolved against, so
/// the answer is the same one the compiler will get.
pub fn upstream_requirement(manifest_dir: &str) -> Result<(String, String)> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--offline"])
        .current_dir(manifest_dir)
        .output()
        .context("failed to run `cargo metadata`")?;
    if !out.status.success() {
        bail!(
            "`cargo metadata --offline` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let metadata: Metadata = serde_json::from_slice(&out.stdout).context("failed to parse `cargo metadata` output")?;

    let mut found = Vec::new();
    for package in &metadata.packages {
        if package.name != UPSTREAM {
            continue;
        }
        for dep in &package.dependencies {
            if dep.name == "schemars" && dep.kind.is_none() {
                found.push((package.version.clone(), dep.req.clone()));
            }
        }
    }
    match found.len() {
        0 => bail!(
            "no normal `schemars` dependency found on `{UPSTREAM}` in `cargo metadata`. Either the \
             dependency is gone (upstream may have landed its own IR — see oxidecomputer/typify#886) \
             or the crate was renamed. Both mean this pin needs revisiting, not that the check is broken."
        ),
        1 => Ok(found.pop().expect("length checked")),
        _ => bail!(
            "`{UPSTREAM}` resolves to more than one version in this workspace ({found:?}); \
             the pin below cannot describe both"
        ),
    }
}

/// Does `req` constrain to the [`PINNED_SERIES`]?
///
/// Deliberately a prefix test on the series, not a semver-range evaluation:
/// the question is "which 0.x series does upstream speak", and any of
/// `^0.8.22`, `0.8.22`, `=0.8.22`, `~0.8` answers it the same way. A range
/// that admitted anything outside the series would not start with it.
pub fn requirement_tracks_pin(req: &str) -> bool {
    let bare = req.trim_start_matches(['^', '~', '=', '>', '<', ' ']);
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
