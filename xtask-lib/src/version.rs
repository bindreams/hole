//! Group-aware version computation for the `hole` workspace.
//!
//! Three concepts to keep distinct:
//!
//! - **Cargo.toml version**: the strict `vMAJOR.MINOR.PATCH` declared in
//!   each workspace member's `Cargo.toml`. Members are grouped by
//!   `[package.metadata.hole-release].group` declaration. Within a group,
//!   all members must declare the same version.
//!
//! - **Display version**: a human-readable string suitable for `<binary>
//!   version` CLI output and the `*_VERSION` env vars baked into binaries.
//!   For tagged commits this matches the Cargo.toml version. For untagged
//!   commits it includes `-snapshot+git.<hash>` plus `.dirty` when the
//!   worktree has uncommitted changes.
//!
//! - **Tag version**: the nearest ancestor tag matching the group's tag
//!   glob (`releases/<group>/v<X.Y.Z>`), parsed back into strict semver.
//!
//! The non-Rust `v2ray-plugin` group reads its version from
//! `external/v2ray-plugin/version.toml`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use semver::Version;

// Group ===============================================================================================================

/// One of the four product release groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    Hole,
    Garter,
    Galoshes,
    V2rayPlugin,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hole => "hole",
            Self::Garter => "garter",
            Self::Galoshes => "galoshes",
            Self::V2rayPlugin => "v2ray-plugin",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "hole" => Ok(Self::Hole),
            "garter" => Ok(Self::Garter),
            "galoshes" => Ok(Self::Galoshes),
            "v2ray-plugin" => Ok(Self::V2rayPlugin),
            _ => bail!("unknown release group '{s}' (expected: hole, garter, galoshes, v2ray-plugin)"),
        }
    }

    pub fn all() -> &'static [Group] {
        &[Self::Hole, Self::Garter, Self::Galoshes, Self::V2rayPlugin]
    }

    /// `git describe --match <this>` glob for nearest-tag lookups for this
    /// group's releases. Excludes the legacy `v0.1.0` tag (which has no
    /// `releases/<group>/` prefix).
    pub fn tag_glob(self) -> String {
        format!("releases/{}/v[0-9]*.[0-9]*.[0-9]*", self.as_str())
    }

    pub fn tag_prefix(self) -> String {
        format!("releases/{}/v", self.as_str())
    }
}

impl std::fmt::Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// Workspace reading ===================================================================================================

/// Resolved version per release group.
#[derive(Debug, Clone)]
pub struct WorkspaceVersions {
    pub by_group: HashMap<Group, Version>,
}

/// Read every workspace member, parse their group metadata, enforce
/// drift-prevention (publishable-but-ungrouped crates are rejected) and
/// within-group version equality. Also reads
/// `external/v2ray-plugin/version.toml` for the v2ray-plugin group.
pub fn read_workspace_versions(repo_root: &Path) -> Result<WorkspaceVersions> {
    let root_toml = repo_root.join("Cargo.toml");
    let root_text =
        std::fs::read_to_string(&root_toml).with_context(|| format!("failed to read {}", root_toml.display()))?;
    let root_doc: toml::Table =
        toml::from_str(&root_text).with_context(|| format!("failed to parse {}", root_toml.display()))?;

    let members = workspace_members(&root_doc, &root_toml)?;

    // group -> Vec<(crate_path, version)>
    let mut accumulator: HashMap<Group, Vec<(PathBuf, Version)>> = HashMap::new();

    for member in &members {
        let cargo_path = repo_root.join(member).join("Cargo.toml");
        let text =
            std::fs::read_to_string(&cargo_path).with_context(|| format!("failed to read {}", cargo_path.display()))?;
        let doc: toml::Table =
            toml::from_str(&text).with_context(|| format!("failed to parse {}", cargo_path.display()))?;

        let package = doc
            .get("package")
            .and_then(|p| p.as_table())
            .ok_or_else(|| anyhow!("no [package] section in {}", cargo_path.display()))?;

        let publish_false = matches!(package.get("publish"), Some(toml::Value::Boolean(false)));

        // [package.metadata.hole-release].group
        let group_str = package
            .get("metadata")
            .and_then(|m| m.as_table())
            .and_then(|m| m.get("hole-release"))
            .and_then(|h| h.as_table())
            .and_then(|h| h.get("group"))
            .and_then(|g| g.as_str());

        match group_str {
            Some(name) => {
                let group = Group::parse(name).with_context(|| format!("invalid group in {}", cargo_path.display()))?;
                let version = parse_strict_version(package, &cargo_path)?;
                accumulator.entry(group).or_default().push((cargo_path, version));
            }
            None => {
                if !publish_false {
                    bail!(
                        "{} is publishable (no `publish = false`) but has no \
                         [package.metadata.hole-release].group declaration. \
                         Add a group, or mark `publish = false` if it is internal tooling.",
                        cargo_path.display()
                    );
                }
                // publish = false + no group: internal tooling (xtask, xtask-lib, mock-plugin). OK.
            }
        }
    }

    // Within-group equality.
    let mut by_group = HashMap::new();
    for (group, entries) in accumulator {
        let unique: BTreeSet<&Version> = entries.iter().map(|(_, v)| v).collect();
        if unique.len() != 1 {
            let mut msg = format!("workspace members in group '{group}' have inconsistent versions:\n");
            for (path, v) in &entries {
                msg.push_str(&format!("  {}: {v}\n", path.display()));
            }
            bail!(msg.trim_end().to_string());
        }
        by_group.insert(group, entries.into_iter().next().unwrap().1);
    }

    // v2ray-plugin: read external/v2ray-plugin/version.toml if it exists.
    let v2ray_path = repo_root.join("external").join("v2ray-plugin").join("version.toml");
    if v2ray_path.exists() {
        by_group.insert(Group::V2rayPlugin, read_v2ray_version(&v2ray_path)?);
    }

    Ok(WorkspaceVersions { by_group })
}

fn read_v2ray_version(version_path: &Path) -> Result<Version> {
    let text =
        std::fs::read_to_string(version_path).with_context(|| format!("failed to read {}", version_path.display()))?;
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

fn workspace_members(root_doc: &toml::Table, root_toml: &Path) -> Result<Vec<String>> {
    let ws = root_doc
        .get("workspace")
        .and_then(|w| w.as_table())
        .ok_or_else(|| anyhow!("no [workspace] section in {}", root_toml.display()))?;
    let members = ws
        .get("members")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow!("no `members` in [workspace] in {}", root_toml.display()))?;
    let mut out = Vec::with_capacity(members.len());
    for m in members {
        let s = m
            .as_str()
            .ok_or_else(|| anyhow!("non-string member in [workspace.members]: {m:?}"))?;
        if s.contains('*') || s.contains('?') || s.contains('[') {
            bail!("glob patterns in workspace members are not supported");
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_strict_version(package: &toml::Table, cargo_path: &Path) -> Result<Version> {
    let v_str = package
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no [package] version in {}", cargo_path.display()))?;
    let v = Version::parse(v_str)
        .with_context(|| format!("{} version '{v_str}' is not valid semver", cargo_path.display()))?;
    if !v.pre.is_empty() || !v.build.is_empty() {
        bail!(
            "{} version must be strict MAJOR.MINOR.PATCH (no pre-release/build): {v}",
            cargo_path.display()
        );
    }
    Ok(v)
}

/// Convenience: read all groups and return the version for `group`.
pub fn cargo_toml_version_for_group(repo_root: &Path, group: Group) -> Result<Version> {
    let ws = read_workspace_versions(repo_root)?;
    ws.by_group
        .get(&group)
        .cloned()
        .ok_or_else(|| anyhow!("no workspace member declared group '{group}'"))
}

// Tag computation =====================================================================================================

/// Return the nearest ancestor tag matching `group`'s tag glob, parsed
/// to strict semver.
///
/// Returns `Ok(None)` when no matching tag exists in the repo (bootstrap
/// state, before the group's first release). Returns `Err` for any other
/// failure (git not installed, parse error on a malformed tag, etc.).
pub fn nearest_tag_version(repo_root: &Path, group: Group) -> Result<Option<Version>> {
    let glob = group.tag_glob();
    let output = Command::new("git")
        .args(["describe", "--tags", "--match", &glob, "--abbrev=0"])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to spawn git describe for group '{group}'"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `git describe` exits non-zero with these stderrs when no tag matches the glob.
        if stderr.contains("No names found")
            || stderr.contains("No tags can describe")
            || stderr.contains("cannot describe")
        {
            return Ok(None);
        }
        bail!(
            "git describe for group '{group}' failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }
    let tag = String::from_utf8(output.stdout)
        .with_context(|| format!("git describe output not utf-8 for group '{group}'"))?;
    let tag = tag.trim();
    Ok(Some(parse_tag_to_version(tag, group)?))
}

fn parse_tag_to_version(tag: &str, group: Group) -> Result<Version> {
    let prefix = group.tag_prefix();
    let semver_str = tag
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow!("tag '{tag}' does not start with '{prefix}'"))?;
    let parsed = Version::parse(semver_str).with_context(|| format!("tag '{tag}' is not valid semver after prefix"))?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        bail!("tag '{tag}' must be strict releases/<group>/vMAJOR.MINOR.PATCH");
    }
    Ok(parsed)
}

/// Validate the group's Cargo.toml version against its nearest tag.
///
/// When `exact`, requires the Cargo.toml version to match the tag exactly.
/// Otherwise, accepts equality or a single patch/minor/major bump ahead.
///
/// When no tag exists yet for the group (bootstrap state), accepts the
/// Cargo.toml version unconditionally. The first release establishes the
/// baseline. With `exact`, a missing tag is still an error — CI/release
/// workflows always have a tag to match against.
pub fn validate_against_tag(repo_root: &Path, group: Group, exact: bool) -> Result<Version> {
    let cargo_ver = cargo_toml_version_for_group(repo_root, group)?;
    let Some(tag_ver) = nearest_tag_version(repo_root, group)? else {
        if exact {
            bail!(
                "group '{group}' has no `releases/{group}/v...` tag yet but `--exact` was requested; \
                 the release workflow must run on a commit with the matching tag"
            );
        }
        return Ok(cargo_ver);
    };

    if exact {
        if cargo_ver != tag_ver {
            bail!("group '{group}' Cargo.toml version ({cargo_ver}) != tag version ({tag_ver})");
        }
    } else if !is_valid_next(&tag_ver, &cargo_ver) {
        bail!(
            "group '{group}' Cargo.toml version ({cargo_ver}) is not a valid successor of tag version ({tag_ver})\n\
             allowed: {tag_ver}, or one patch/minor/major bump"
        );
    }

    Ok(cargo_ver)
}

// Display version =====================================================================================================

/// Compute a display version string for `group` suitable for `<binary>
/// version` CLI output and the `*_VERSION` env vars baked into binaries.
///
/// Returns the Cargo.toml version when it matches the nearest tag exactly
/// and the worktree is clean. Otherwise appends `-snapshot+git.<hash>`
/// and `.dirty` suffixes as appropriate.
///
/// Falls back to `0.0.0-unknown` if anything fails (so build.rs never panics).
pub fn display_version(repo_root: &Path, group: Group) -> String {
    display_version_inner(repo_root, group).unwrap_or_else(|_| "0.0.0-unknown".to_string())
}

fn display_version_inner(repo_root: &Path, group: Group) -> Result<String> {
    let glob = group.tag_glob();
    let desc = run_git(repo_root, &["describe", "--tags", "--match", &glob, "--long"])?;
    let desc = desc.trim();

    // Output shape: <tag>-<distance>-g<short-hash>
    let parts: Vec<&str> = desc.rsplitn(3, '-').collect();
    if parts.len() != 3 {
        bail!("unexpected git describe output: {desc}");
    }
    let tag = parts[2];
    let distance: u64 = parts[1].parse().with_context(|| format!("bad distance in '{desc}'"))?;

    let parsed = parse_tag_to_version(tag, group)?;
    let mut version = parsed.to_string();

    if distance > 0 {
        let full_hash = run_git(repo_root, &["rev-parse", "HEAD"])?;
        version = format!("{version}-snapshot+git.{}", full_hash.trim());
    }

    // Worktree dirtiness on tracked files only — matches `git describe --dirty`.
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

// is_valid_next =======================================================================================================

/// Returns true if `cargo_ver` is equal to `tag_ver` or exactly one bump
/// (patch, minor, or major) ahead.
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
        bail!(
            "git {} exited {}: {}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("git {} output not utf-8", args.join(" ")))
}
