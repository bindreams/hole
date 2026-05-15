//! Lineage-aware version validator for the `v2ray-plugin` release group.
//!
//! Unlike the workspace-member groups (hole/garter/galoshes) which use
//! strict-semver Cargo.toml versions locked within a group, v2ray-plugin
//! vendors an upstream project (shadowsocks/v2ray-plugin) via git-subrepo
//! and tracks its version separately in `external/v2ray-plugin/version.toml`.
//!
//! The version string captures Hole's relationship to upstream's release
//! lineage:
//!
//! - **`X.Y.Z`** (bare semver) — we vendor upstream's `vX.Y.Z` release
//!   commit exactly.
//! - **`X.Y.Z-hole.N`** (pre-release) — we vendor upstream-master between
//!   upstream's last tag and an unknown future `vX.Y.Z`, with `N` Hole
//!   release iterations cut against this base. Per semver precedence,
//!   `X.Y.Z-hole.N` orders strictly above all prior `X.Y.Z` and strictly
//!   below upstream's eventual `vX.Y.Z` (or any later tag), so the
//!   pre-release semantics align with what we mean by "between upstream's
//!   last release and their next."
//!
//! Validator enforces two rules:
//!
//! 1. **Shape** — pre-release, when present, must be exactly `hole.N` for
//!    a positive integer N. Build metadata is rejected.
//! 2. **Sequence-no-gap** — for `X.Y.Z-hole.N`, N must equal
//!    `max_existing(same_base) + 1` where `max_existing` is 0 when no
//!    same-base `hole.K` tags exist. This catches both "started above 1"
//!    (bootstrap reject) and "skipped a number" (mid-sequence reject).
//!
//! What this validator does NOT enforce:
//!
//! - Whether `X.Y.Z` matches a real upstream release tag, or is one
//!   patch past upstream's last tag. We don't have upstream's git data
//!   locally; the maintainer is trusted to pick the right base when
//!   bumping `version.toml`.
//! - `is_valid_next`-style "one bump ahead" transitions between bases.
//!   Upstream itself can major/minor/patch-bump arbitrarily, so we don't
//!   impose constraints on the base portion.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use semver::Version;

use crate::version::{ancestor_tags, nearest_tag_version, Group};

/// Validate a v2ray-plugin version string's shape.
///
/// Accepts `X.Y.Z` or `X.Y.Z-hole.N` where N is a positive integer.
/// Rejects build metadata in all cases. Rejects any pre-release form
/// other than `hole.N`.
pub fn parse_version_string(s: &str) -> Result<Version> {
    let v = Version::parse(s).with_context(|| format!("v2ray-plugin version '{s}' is not valid semver"))?;
    if !v.build.is_empty() {
        bail!("v2ray-plugin version must not have build metadata: '{s}'");
    }
    if !v.pre.is_empty() {
        let pre = v.pre.as_str();
        let Some(n_str) = pre.strip_prefix("hole.") else {
            bail!(
                "v2ray-plugin pre-release identifier must be exactly `hole.N` for a positive integer N; \
                 got '{pre}' in '{s}'"
            );
        };
        let n: u64 = n_str
            .parse()
            .map_err(|_| anyhow!("v2ray-plugin hole.N suffix must be a positive integer; got '{pre}' in '{s}'"))?;
        if n < 1 {
            bail!("v2ray-plugin hole.N suffix N must be >= 1; got '{pre}' in '{s}'");
        }
    }
    Ok(v)
}

/// Read and shape-validate `external/v2ray-plugin/version.toml`.
pub fn read_version(repo_root: &Path) -> Result<Version> {
    let version_path = repo_root.join("external").join("v2ray-plugin").join("version.toml");
    let text =
        std::fs::read_to_string(&version_path).with_context(|| format!("failed to read {}", version_path.display()))?;
    let doc: toml::Table =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", version_path.display()))?;
    let v_str = doc
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no `version` key in {}", version_path.display()))?;
    parse_version_string(v_str).with_context(|| format!("in {}", version_path.display()))
}

/// Extract the hole iteration number `N` from a `Version` whose
/// pre-release is `hole.N`, otherwise `None`.
pub(crate) fn hole_iteration(v: &Version) -> Option<u64> {
    if v.pre.is_empty() {
        return None;
    }
    let n_str = v.pre.as_str().strip_prefix("hole.")?;
    let n: u64 = n_str.parse().ok()?;
    if n < 1 {
        return None;
    }
    Some(n)
}

/// V2rayPlugin-specific version validator. See module-level docs for the rules.
///
/// `exact = true` (used by CI's release workflow): version.toml must equal
/// the nearest ancestor `releases/v2ray-plugin/v...` tag exactly. A missing
/// tag is itself an error.
///
/// `exact = false` (used by prek's local check): version.toml's shape is
/// already validated by `read_version`. If the version is `X.Y.Z-hole.N`,
/// apply the sequence-no-gap rule against ancestor tags. If bare `X.Y.Z`,
/// no sequence constraint.
pub fn validate_against_tag(repo_root: &Path, exact: bool) -> Result<Version> {
    let current = read_version(repo_root)?;

    if exact {
        let Some(tag_ver) = nearest_tag_version(repo_root, Group::V2rayPlugin)? else {
            bail!(
                "group 'v2ray-plugin' has no `releases/v2ray-plugin/v...` tag yet but `--exact` was requested; \
                 the release workflow must run on a commit with the matching tag"
            );
        };
        if current != tag_ver {
            bail!("group 'v2ray-plugin' version.toml ({current}) != tag version ({tag_ver})");
        }
        return Ok(current);
    }

    // Non-exact: shape is already validated. If bare X.Y.Z, no sequence
    // constraint applies (the maintainer is signalling "we vendor an
    // upstream tag exactly," and the validator trusts that claim).
    let Some(n) = hole_iteration(&current) else {
        return Ok(current);
    };

    // Sequence-no-gap rule. Find the highest existing hole.K tag that
    // shares the same X.Y.Z base. `max_existing` defaults to 0 when no
    // same-base hole.K tags exist (bootstrap pivot). The current
    // version is accepted when it equals `max_existing` (after-release
    // stable state — same as the most recent tag, hasn't been bumped
    // yet) or `max_existing + 1` (preparing the next release). Any
    // other value is a gap (`N > max_existing + 1`) or a regression
    // (`N < max_existing`).
    //
    // Do NOT simplify to "no tags → no constraint" — that breaks the
    // bootstrap-reject path. In bootstrap state (max_existing = 0),
    // current N == 0 is impossible (hole_iteration requires N >= 1), so
    // the only accepted N is 1. Same single equality, same correct
    // semantics for both bootstrap and mid-sequence states.
    let all_tags = ancestor_tags(repo_root, Group::V2rayPlugin)?;
    let max_existing = all_tags
        .iter()
        .filter(|(v, _)| v.major == current.major && v.minor == current.minor && v.patch == current.patch)
        .filter_map(|(v, _)| hole_iteration(v))
        .max()
        .unwrap_or(0);

    if n != max_existing && n != max_existing + 1 {
        bail!(
            "v2ray-plugin sequence violation: version.toml is `{current}` (hole.{n}), \
             but valid hole iterations for base {}.{}.{} are hole.{max_existing} \
             (current latest) or hole.{} (next). Tags must increment by 1 with no gaps.",
            current.major,
            current.minor,
            current.patch,
            max_existing + 1
        );
    }

    Ok(current)
}
