// GitHub release update checking.
//
// Uses a two-step tag-then-release approach:
// 1. Fetch all tags (lightweight), filter to valid semver, sort descending.
// 2. For each candidate tag, fetch the specific release. First qualifying one wins.

use hole_common::version::ReleaseVersion;
use serde::Deserialize;

use super::error::UpdateError;

// GitHub API types ====================================================================================================

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubTag {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubRelease {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub body: Option<String>,
    pub html_url: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

// Platform asset suffix ===============================================================================================

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const ASSET_SUFFIX: &str = "windows-amd64.msi";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const ASSET_SUFFIX: &str = "darwin-arm64.dmg";

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const ASSET_SUFFIX: &str = "darwin-amd64.dmg";

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
)))]
compile_error!("unsupported platform for auto-update asset matching");

// Public API ==========================================================================================================

/// Information about an available update.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub version: ReleaseVersion,
    pub asset_url: String,
    pub asset_name: String,
    pub sha256sums_url: String,
    pub sha256sums_minisig_url: String,
    pub release_notes: Option<String>,
    pub html_url: String,
}

const REPO: &str = "bindreams/hole";

/// Tag-name prefix for hole's release track. Per the four-track release
/// model (#291), other products (`galoshes`, `garter`, `v2ray-plugin`)
/// use their own `releases/<product>/v...` prefixes and must be ignored
/// by the hole auto-updater.
const HOLE_TAG_PREFIX: &str = "releases/hole/v";

/// Parse a hole release tag name. Returns `None` for tags that do not
/// belong to hole's release track (other products' tags, or any
/// non-release tag).
fn parse_hole_tag(tag: &str) -> Option<ReleaseVersion> {
    let stripped = tag.strip_prefix(HOLE_TAG_PREFIX)?;
    ReleaseVersion::parse(stripped).ok()
}

/// Check GitHub for an available update.
///
/// This is a blocking function — call from `spawn_blocking`.
pub fn check_for_update() -> Result<Option<UpdateInfo>, UpdateError> {
    let (current, is_snapshot) = ReleaseVersion::from_build_version(crate::version::VERSION)
        .map_err(|e| UpdateError::Io(std::io::Error::other(format!("failed to parse current version: {e}"))))?;

    // Step 1: Fetch all tags, filter to candidates.
    let all_tags = fetch_all_tags()?;
    let candidates = candidate_tags(&all_tags, &current, is_snapshot);

    if candidates.is_empty() {
        return Ok(None);
    }

    // Step 2: For each candidate (highest first), try to fetch a qualifying release.
    for (_, tag_name) in &candidates {
        match fetch_release_for_tag(tag_name)? {
            Some(release) => {
                if let Some(info) = release_qualifies(&release) {
                    return Ok(Some(info));
                }
            }
            None => continue,
        }
    }

    Ok(None)
}

// Internal helpers ====================================================================================================

/// Fetch all tags from GitHub, transparently paginating.
fn fetch_all_tags() -> Result<Vec<GitHubTag>, UpdateError> {
    let mut tags = Vec::new();
    let mut url = format!("https://api.github.com/repos/{REPO}/tags?per_page=100");

    loop {
        let mut response = ureq::get(&url).header("Accept", "application/vnd.github+json").call()?;

        let next_url = response
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_next_link);

        let page: Vec<GitHubTag> = response.body_mut().read_json()?;
        tags.extend(page);

        match next_url {
            Some(next) => url = next,
            None => break,
        }
    }

    Ok(tags)
}

/// Fetch the release associated with a specific tag. Returns `None` if no release exists (404).
fn fetch_release_for_tag(tag_name: &str) -> Result<Option<GitHubRelease>, UpdateError> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/tags/{tag_name}");

    match ureq::get(&url).header("Accept", "application/vnd.github+json").call() {
        Ok(mut response) => {
            let release: GitHubRelease = response.body_mut().read_json()?;
            Ok(Some(release))
        }
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Filter and sort tags into candidate versions, highest first.
///
/// A tag is a candidate if:
/// - It parses as a valid strict semver (`vMAJOR.MINOR.PATCH`).
/// - Its version is greater than `current`, or equal to `current` when `is_snapshot` is true.
pub(crate) fn candidate_tags(
    tags: &[GitHubTag],
    current: &ReleaseVersion,
    is_snapshot: bool,
) -> Vec<(ReleaseVersion, String)> {
    let mut candidates: Vec<(ReleaseVersion, String)> = tags
        .iter()
        .filter_map(|t| {
            // Filter to hole's track only (`releases/hole/v...`). Other product
            // tracks live alongside in the same repo and must not trigger hole
            // auto-updates.
            let ver = parse_hole_tag(&t.name)?;
            let dominated = if is_snapshot { ver >= *current } else { ver > *current };
            dominated.then(|| (ver, t.name.clone()))
        })
        .collect();

    // Sort descending by version (highest first).
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates
}

/// Check if a release qualifies as an update: not draft, not prerelease, has a matching platform
/// asset with both `SHA256SUMS` and `SHA256SUMS.minisig` manifest files.
pub(crate) fn release_qualifies(release: &GitHubRelease) -> Option<UpdateInfo> {
    if release.draft || release.prerelease {
        return None;
    }

    let asset = release.assets.iter().find(|a| a.name.ends_with(ASSET_SUFFIX))?;

    // Both manifest files must be present for the release to qualify.
    let sha256sums = release.assets.iter().find(|a| a.name == "SHA256SUMS")?;
    let sha256sums_minisig = release.assets.iter().find(|a| a.name == "SHA256SUMS.minisig")?;

    let version = parse_hole_tag(&release.tag_name)?;

    Some(UpdateInfo {
        version,
        asset_url: asset.browser_download_url.clone(),
        asset_name: asset.name.clone(),
        sha256sums_url: sha256sums.browser_download_url.clone(),
        sha256sums_minisig_url: sha256sums_minisig.browser_download_url.clone(),
        release_notes: release.body.clone(),
        html_url: release.html_url.clone(),
    })
}

/// Parse the `Link` response header to extract the URL for the next page.
///
/// GitHub uses the standard format: `<URL>; rel="next", <URL>; rel="last"`.
pub(crate) fn parse_next_link(header: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        if part.ends_with("rel=\"next\"") {
            // Extract URL between < and >
            let start = part.find('<')? + 1;
            let end = part.find('>')?;
            return Some(part[start..end].to_string());
        }
    }
    None
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod check_tests;
