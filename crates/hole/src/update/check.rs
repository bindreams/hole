// GitHub release update checking.
//
// Uses a two-step tag-then-release approach:
// 1. Fetch all tags (lightweight), filter to valid semver, sort descending.
// 2. For each candidate tag, fetch the specific release. First qualifying one wins.
//
// The withdrawal list (`withdrawals.rs`) is read first: a withdrawn tag is not a candidate, and the
// running version's own withdrawal is reported beside the offer.

use hole_common::version::ReleaseVersion;
use hole_common::withdrawals::is_https_url;
use serde::Deserialize;
use tracing::{info, warn};

use super::error::UpdateError;
use super::http::{self, Bounds};
use super::withdrawals::{fetch_withdrawals, Withdrawal, Withdrawals};

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
    pub html_url: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

// Platform ============================================================================================================

/// Defines `PLATFORM_ID` and `ASSET_EXTENSION` for this build.
macro_rules! platform {
    ($id:expr, $extension:literal) => {
        /// This build's release platform id: the name the withdrawal list and the release assets use.
        pub const PLATFORM_ID: &str = $id;
        const ASSET_EXTENSION: &str = $extension;
    };
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
platform!(hole_common::withdrawals::WINDOWS_AMD64, "zip");

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
platform!(hole_common::withdrawals::DARWIN_ARM64, "tar.gz");

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
platform!(hole_common::withdrawals::DARWIN_AMD64, "tar.gz");

/// The suffix of this build's update archive's name: `<platform id>.<extension>`.
fn asset_suffix() -> String {
    format!("{PLATFORM_ID}.{ASSET_EXTENSION}")
}

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
)))]
compile_error!("unsupported platform for auto-update asset matching");

// Public API ==========================================================================================================

/// Information about an available update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    pub version: ReleaseVersion,
    pub asset_url: String,
    pub asset_name: String,
    pub sha256sums_url: String,
    pub sha256sums_minisig_url: String,
    /// The release page, which shows its notes: `Some` only for an `https` URL with a host, the only kind
    /// the app hands to the system's opener. A release with another kind of link is still offered.
    pub html_url: Option<String>,
}

/// What one check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateCheck {
    /// The newest release that qualifies and is not withdrawn, if there is one.
    pub offer: Option<UpdateInfo>,
    /// The withdrawal of the running version on this platform, if the list has one.
    pub running_withdrawn: Option<Withdrawal>,
}

const REPO: &str = "bindreams/hole";

/// Tag-name prefix for hole's release track. Hole shares the repo with
/// other release tracks (`galoshes`, `garter`, `ex-ray`) whose
/// `releases/<product>/v...` tags must be ignored by the hole
/// auto-updater.
const HOLE_TAG_PREFIX: &str = "releases/hole/v";

/// Parse a hole release tag name. Returns `None` for tags that do not
/// belong to hole's release track (other products' tags, or any
/// non-release tag).
fn parse_hole_tag(tag: &str) -> Option<ReleaseVersion> {
    let stripped = tag.strip_prefix(HOLE_TAG_PREFIX)?;
    ReleaseVersion::parse(stripped).ok()
}

/// Check GitHub for an available update, and the withdrawal list for the running version.
///
/// A list that cannot be fetched or verified fails the check: nothing is offered and nothing is
/// warned about.
///
/// This is a blocking function — call from `spawn_blocking`.
pub fn check_for_update() -> Result<UpdateCheck, UpdateError> {
    check_with(fetch_withdrawals, fetch_all_tags)
}

/// [`check_for_update`] with its two fetches as parameters, so a test decides what each returns. A list
/// fetch that fails ends the check before `fetch_tags` runs.
fn check_with(
    fetch_list: impl FnOnce() -> Result<Withdrawals, UpdateError>,
    fetch_tags: impl FnOnce() -> Result<Vec<GitHubTag>, UpdateError>,
) -> Result<UpdateCheck, UpdateError> {
    let (current, is_snapshot) = ReleaseVersion::from_build_version(crate::version::VERSION)
        .map_err(|e| UpdateError::Io(std::io::Error::other(format!("failed to parse current version: {e}"))))?;

    let withdrawals = fetch_list()?;
    let running_withdrawn = running_withdrawn(&current, is_snapshot, &withdrawals).cloned();
    if let Some(withdrawal) = &running_withdrawn {
        warn!(
            version = %withdrawal.version,
            reason = %withdrawal.reason,
            url = %withdrawal.url,
            "the running version was withdrawn"
        );
    }

    // Step 1: Fetch all tags, filter to candidates.
    let all_tags = fetch_tags()?;
    let candidates = candidate_tags(&all_tags, &current, is_snapshot, &withdrawals);

    // Step 2: For each candidate (highest first), try to fetch a qualifying release.
    for (_, tag_name) in &candidates {
        let Some(release) = fetch_release_for_tag(tag_name)? else {
            continue;
        };
        if let Some(offer) = release_qualifies(&release) {
            return Ok(UpdateCheck {
                offer: Some(offer),
                running_withdrawn,
            });
        }
    }

    Ok(UpdateCheck {
        offer: None,
        running_withdrawn,
    })
}

// Internal helpers ====================================================================================================

/// Fetch all tags from GitHub, transparently paginating.
fn fetch_all_tags() -> Result<Vec<GitHubTag>, UpdateError> {
    let mut tags = Vec::new();
    let mut url = format!("https://api.github.com/repos/{REPO}/tags?per_page=100");

    loop {
        let mut response = http::get(&url, Bounds::SMALL)
            .header("Accept", "application/vnd.github+json")
            .call()?;

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

    match http::get(&url, Bounds::SMALL)
        .header("Accept", "application/vnd.github+json")
        .call()
    {
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
/// - It is a hole-track tag (`releases/hole/v<MAJOR.MINOR.PATCH>`), parsed via `parse_hole_tag`.
/// - Its version is greater than `current`, or equal to `current` when `is_snapshot` is true.
/// - It is not withdrawn on this platform.
pub(crate) fn candidate_tags(
    tags: &[GitHubTag],
    current: &ReleaseVersion,
    is_snapshot: bool,
    withdrawals: &Withdrawals,
) -> Vec<(ReleaseVersion, String)> {
    let mut candidates: Vec<(ReleaseVersion, String)> = tags
        .iter()
        .filter_map(|t| {
            // Filter to hole's track only (`releases/hole/v...`). Other product
            // tracks live alongside in the same repo and must not trigger hole
            // auto-updates.
            let ver = parse_hole_tag(&t.name)?;
            let dominated = if is_snapshot { ver >= *current } else { ver > *current };
            if !dominated {
                return None;
            }
            if let Some(withdrawal) = withdrawals.for_version(&ver, PLATFORM_ID) {
                info!(version = %ver, url = %withdrawal.url, "skipping a withdrawn release");
                return None;
            }
            Some((ver, t.name.clone()))
        })
        .collect();

    // Sort descending by version (highest first).
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates
}

/// The withdrawal of the running version on this platform, if the list has one. A snapshot build is a
/// development build after the version it carries, not that release, so it has none.
pub(crate) fn running_withdrawn<'a>(
    current: &ReleaseVersion,
    is_snapshot: bool,
    withdrawals: &'a Withdrawals,
) -> Option<&'a Withdrawal> {
    if is_snapshot {
        return None;
    }
    withdrawals.for_version(current, PLATFORM_ID)
}

/// Check if a release qualifies as an update: not draft, not prerelease, has a matching platform asset with
/// both `SHA256SUMS` and `SHA256SUMS.minisig` manifest files.
pub(crate) fn release_qualifies(release: &GitHubRelease) -> Option<UpdateInfo> {
    if release.draft || release.prerelease {
        return None;
    }

    let suffix = asset_suffix();
    let asset = release.assets.iter().find(|a| a.name.ends_with(&suffix))?;

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
        html_url: is_https_url(&release.html_url).then(|| release.html_url.clone()),
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
