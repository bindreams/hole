//! Version computation for the `hole` workspace.
//!
//! Three concepts to keep distinct:
//!
//! - **Cargo.toml version**: the strict `vMAJOR.MINOR.PATCH` declared in
//!   each workspace member's `Cargo.toml`. Asserted to match the nearest
//!   git tag (or be one bump ahead) by `validate_against_tag`. This is
//!   what the MSI installer stamps into Windows install metadata.
//!
//! - **Display version**: a human-readable string suitable for the `hole
//!   version` CLI output and the `HOLE_VERSION` env var the GUI bakes in.
//!   For tagged commits this is the same as the Cargo.toml version. For
//!   untagged commits it includes a `-snapshot+git.<hash>` suffix and a
//!   `.dirty` suffix when the worktree has uncommitted changes.
//!
//! - **Tag version**: the nearest ancestor tag matching `v[0-9]+.[0-9]+.[0-9]+`,
//!   parsed back into a strict semver. Only used by `validate_against_tag`.
//!
//! All git invocations use `--match v[0-9]*.[0-9]*.[0-9]*` so that any
//! non-version tags (e.g. `latest`) are ignored.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use semver::Version;

/// Read the workspace member Cargo.tomls and assert they all declare the
/// same strict semver version. Returns that version.
///
/// Members with `publish = false` are **excluded** from the consistency
/// check — they are internal tooling (xtask, xtask-lib) and don't share the
/// release cadence of the user-facing crates. Without this exclusion, every
/// release version bump would have to touch all 5 Cargo.tomls instead of 3,
/// and a release-time mistake would silently produce mismatched binaries.
pub fn cargo_toml_version(repo_root: &Path) -> Result<Version> {
    let root_toml = repo_root.join("Cargo.toml");
    let root_text =
        std::fs::read_to_string(&root_toml).with_context(|| format!("failed to read {}", root_toml.display()))?;

    let members = parse_workspace_members(&root_text)
        .ok_or_else(|| anyhow!("no [workspace] members found in {}", root_toml.display()))?;

    if members
        .iter()
        .any(|m| m.contains('*') || m.contains('?') || m.contains('['))
    {
        return Err(anyhow!("glob patterns in workspace members are not supported"));
    }

    let mut versions: Vec<(String, Version)> = Vec::new();
    for member in &members {
        let cargo_path = repo_root.join(member).join("Cargo.toml");
        let text =
            std::fs::read_to_string(&cargo_path).with_context(|| format!("failed to read {}", cargo_path.display()))?;

        // Skip publish = false members (internal tooling).
        if parse_package_publish_false(&text) {
            continue;
        }

        let v_str =
            parse_package_version(&text).ok_or_else(|| anyhow!("no [package] version in {}", cargo_path.display()))?;
        let v = Version::parse(&v_str)
            .with_context(|| format!("{} version '{v_str}' is not valid semver", cargo_path.display()))?;
        if !v.pre.is_empty() || !v.build.is_empty() {
            return Err(anyhow!(
                "{} version must be strict MAJOR.MINOR.PATCH (no pre-release/build): {v}",
                cargo_path.display()
            ));
        }
        versions.push((cargo_path.display().to_string(), v));
    }

    if versions.is_empty() {
        return Err(anyhow!(
            "no publishable workspace members found (all have publish = false?)"
        ));
    }

    let unique: std::collections::BTreeSet<_> = versions.iter().map(|(_, v)| v.clone()).collect();
    if unique.len() != 1 {
        let mut msg = String::from("workspace members have inconsistent versions:\n");
        for (path, v) in &versions {
            msg.push_str(&format!("  {path}: {v}\n"));
        }
        return Err(anyhow!(msg.trim_end().to_string()));
    }

    Ok(unique.into_iter().next().unwrap())
}

/// Compute a display version string suitable for the `hole version` CLI and
/// the `HOLE_VERSION` env var baked into the GUI binary.
///
/// Returns the Cargo.toml version when it matches the nearest tag exactly
/// and the worktree is clean. Otherwise appends a `-snapshot+git.<hash>`
/// suffix and a `.dirty` suffix as appropriate.
///
/// Falls back to `0.0.0-unknown` if git is unavailable (no panic).
pub fn display_version(repo_root: &Path) -> String {
    match display_version_inner(repo_root) {
        Ok(v) => v,
        Err(_) => "0.0.0-unknown".to_string(),
    }
}

fn display_version_inner(repo_root: &Path) -> Result<String> {
    // git describe --tags --match "v[0-9]*.[0-9]*.[0-9]*" --long
    // Output: <tag>-<distance>-g<short-hash>
    let desc = run_git(
        repo_root,
        &["describe", "--tags", "--match", "v[0-9]*.[0-9]*.[0-9]*", "--long"],
    )?;
    let desc = desc.trim();

    let parts: Vec<&str> = desc.rsplitn(3, '-').collect();
    if parts.len() != 3 {
        return Err(anyhow!("unexpected git describe output: {desc}"));
    }
    let tag = parts[2];
    let distance: u64 = parts[1].parse().with_context(|| format!("bad distance in '{desc}'"))?;

    let semver_str = tag
        .strip_prefix('v')
        .ok_or_else(|| anyhow!("tag '{tag}' missing 'v' prefix"))?;
    let parsed = Version::parse(semver_str).with_context(|| format!("tag '{tag}' is not valid semver"))?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(anyhow!(
            "tag '{tag}' must be strict vMAJOR.MINOR.PATCH (no pre-release/build)"
        ));
    }

    let mut version = semver_str.to_string();

    if distance > 0 {
        let full_hash = run_git(repo_root, &["rev-parse", "HEAD"])?;
        version = format!("{version}-snapshot+git.{}", full_hash.trim());
    }

    // Worktree dirtiness on tracked files only — matches `git describe --dirty`
    let dirty = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(repo_root)
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    if dirty {
        version.push_str(".dirty");
    }

    Ok(version)
}

/// Validate that all workspace member Cargo.toml versions agree, that they
/// match the nearest git tag (or are exactly one bump ahead unless `exact`),
/// and return the cargo version on success.
///
/// This is the function called by the prek `check-version` hook (replacing
/// `scripts/check-version.py`) and by the release CI workflow.
pub fn validate_against_tag(repo_root: &Path, exact: bool) -> Result<Version> {
    let cargo_ver = cargo_toml_version(repo_root)?;
    let tag_ver = nearest_tag_version(repo_root)?;

    if exact {
        if cargo_ver != tag_ver {
            return Err(anyhow!("Cargo.toml version ({cargo_ver}) != tag version ({tag_ver})"));
        }
    } else if !is_valid_next(&tag_ver, &cargo_ver) {
        return Err(anyhow!(
            "Cargo.toml version ({cargo_ver}) is not a valid successor of tag version ({tag_ver})\n\
             allowed: {tag_ver}, or one patch/minor/major bump"
        ));
    }

    Ok(cargo_ver)
}

/// Return the nearest ancestor tag matching `v[0-9]+.[0-9]+.[0-9]+`, parsed
/// to strict semver.
pub fn nearest_tag_version(repo_root: &Path) -> Result<Version> {
    let tag = run_git(
        repo_root,
        &["describe", "--tags", "--match", "v[0-9]*.[0-9]*.[0-9]*", "--abbrev=0"],
    )?;
    let tag = tag.trim();
    let semver_str = tag
        .strip_prefix('v')
        .ok_or_else(|| anyhow!("nearest tag '{tag}' missing 'v' prefix"))?;
    let parsed = Version::parse(semver_str).with_context(|| format!("tag '{tag}' is not valid semver"))?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(anyhow!("nearest tag '{tag}' must be strict vMAJOR.MINOR.PATCH"));
    }
    Ok(parsed)
}

/// Returns true if `cargo_ver` is equal to `tag_ver` or exactly one bump
/// (patch, minor, or major) ahead. Mirrors `scripts/check-version.py`'s
/// `is_valid_next`.
pub fn is_valid_next(tag_ver: &Version, cargo_ver: &Version) -> bool {
    if cargo_ver == tag_ver {
        return true;
    }
    // Patch bump: same major + minor, patch + 1
    if cargo_ver.major == tag_ver.major && cargo_ver.minor == tag_ver.minor && cargo_ver.patch == tag_ver.patch + 1 {
        return true;
    }
    // Minor bump: same major, minor + 1, patch reset to 0
    if cargo_ver.major == tag_ver.major && cargo_ver.minor == tag_ver.minor + 1 && cargo_ver.patch == 0 {
        return true;
    }
    // Major bump: major + 1, minor and patch reset to 0
    if cargo_ver.major == tag_ver.major + 1 && cargo_ver.minor == 0 && cargo_ver.patch == 0 {
        return true;
    }
    false
}

// Helpers =============================================================================================================

fn run_git(repo_root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to spawn `git {}`", args.join(" ")))?;
    if !output.status.success() {
        return Err(anyhow!(
            "git {} exited {}: {}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).with_context(|| format!("git {} output not utf-8", args.join(" ")))
}

/// Naive parser for `[workspace] members = [...]`. Returns the literal member
/// path strings. Not a full TOML parser — we only support the format the hole
/// workspace currently uses (literal paths, no globs, single-line array).
fn parse_workspace_members(toml: &str) -> Option<Vec<String>> {
    // Find `[workspace]` then the next `members` line.
    let ws_start = toml.find("[workspace]")?;
    let ws_section = &toml[ws_start..];
    let line_start = ws_section.find("members")?;
    let line = &ws_section[line_start..];
    let bracket_open = line.find('[')?;
    let bracket_close = line[bracket_open..].find(']')?;
    let inner = &line[bracket_open + 1..bracket_open + bracket_close];

    let mut members = Vec::new();
    for raw in inner.split(',') {
        let s = raw.trim().trim_matches('"').trim_matches('\'').trim();
        if !s.is_empty() {
            members.push(s.to_string());
        }
    }
    Some(members)
}

/// Naive parser for the first `version = "..."` inside `[package]`.
fn parse_package_version(toml: &str) -> Option<String> {
    let pkg = extract_package_section(toml)?;
    for line in pkg.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                return Some(rest.trim_matches('"').trim_matches('\'').to_string());
            }
        }
    }
    None
}

/// Returns true if `[package]` declares `publish = false`.
fn parse_package_publish_false(toml: &str) -> bool {
    let Some(pkg) = extract_package_section(toml) else {
        return false;
    };
    for line in pkg.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("publish") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                if rest.trim() == "false" {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract the `[package]` section text (everything until the next `[section]`).
fn extract_package_section(toml: &str) -> Option<&str> {
    let pkg_start = toml.find("[package]")?;
    let pkg_section = &toml[pkg_start..];
    let next_section = pkg_section[1..].find("\n[").map(|i| i + 1).unwrap_or(pkg_section.len());
    Some(&pkg_section[..next_section])
}
