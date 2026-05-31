//! Version reader for the `ex-ray` release group.
//!
//! ex-ray is a first-party Go crate (`crates/ex-ray/`) with no Cargo.toml,
//! so its version cannot come from the workspace-member scan that serves
//! the hole/garter/galoshes groups. Instead it lives in
//! `crates/ex-ray/version.toml` as a top-level `version = "X.Y.Z"` key.
//!
//! Unlike the retired `v2ray-plugin` group — which vendored an upstream
//! project and used a lineage-aware `X.Y.Z-hole.N` pre-release scheme —
//! ex-ray is first-party and uses plain strict semver. There is no
//! lineage or pre-release form. Validation against `releases/ex-ray/v...`
//! tags goes through the generic [`crate::version::validate_against_tag`]
//! path (the `is_valid_next` one-bump-ahead rule), identical to the
//! Cargo.toml-based groups.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use semver::Version;

/// Read `crates/ex-ray/version.toml` and parse its `version` key as strict
/// `MAJOR.MINOR.PATCH` semver. Pre-release and build metadata are rejected,
/// matching the workspace-member groups' `parse_strict_version`.
pub fn read_version(repo_root: &Path) -> Result<Version> {
    let version_path = repo_root.join("crates").join("ex-ray").join("version.toml");
    let text =
        std::fs::read_to_string(&version_path).with_context(|| format!("failed to read {}", version_path.display()))?;
    let doc: toml::Table =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", version_path.display()))?;
    let v_str = doc
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no `version` key in {}", version_path.display()))?;
    let v = Version::parse(v_str)
        .with_context(|| format!("{} version '{v_str}' is not valid semver", version_path.display()))?;
    if !v.pre.is_empty() || !v.build.is_empty() {
        bail!(
            "{} version must be strict MAJOR.MINOR.PATCH (no pre-release/build): {v}",
            version_path.display()
        );
    }
    Ok(v)
}
