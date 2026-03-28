use super::*;
use hole_common::version::ReleaseVersion;

/// Asset name that matches the current platform's ASSET_SUFFIX.
fn platform_asset_name(version: &str) -> String {
    format!("hole-{version}-{ASSET_SUFFIX}")
}

fn tag(name: &str) -> GitHubTag {
    GitHubTag { name: name.to_string() }
}

fn asset(name: &str, url: &str) -> GitHubAsset {
    GitHubAsset {
        name: name.to_string(),
        browser_download_url: url.to_string(),
    }
}

fn release(tag: &str, draft: bool, prerelease: bool, assets: Vec<GitHubAsset>) -> GitHubRelease {
    GitHubRelease {
        tag_name: tag.to_string(),
        draft,
        prerelease,
        body: Some("Release notes".to_string()),
        html_url: format!("https://github.com/test/repo/releases/tag/{tag}"),
        assets,
    }
}

// candidate_tags ======================================================================================================

#[skuld::test]
fn candidate_tags_filters_non_semver() {
    let tags = vec![tag("v1.0.0"), tag("nightly"), tag("v2.0.0"), tag("bad")];
    let current = ReleaseVersion::parse("0.9.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_sorts_descending() {
    let tags = vec![tag("v1.0.0"), tag("v3.0.0"), tag("v2.0.0")];
    let current = ReleaseVersion::parse("0.1.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[2].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_excludes_older_and_equal() {
    let tags = vec![tag("v1.0.0"), tag("v2.0.0"), tag("v3.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_includes_equal_when_snapshot() {
    let tags = vec![tag("v1.0.0"), tag("v2.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, true);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_empty_when_no_newer() {
    let tags = vec![tag("v1.0.0"), tag("v0.5.0")];
    let current = ReleaseVersion::parse("1.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert!(result.is_empty());
}

// release_qualifies ===================================================================================================

#[skuld::test]
fn release_qualifies_valid() {
    let name = platform_asset_name("1.0.0");
    let r = release(
        "v1.0.0",
        false,
        false,
        vec![asset(&name, "https://example.com/hole-asset")],
    );
    let info = release_qualifies(&r).unwrap();
    assert_eq!(info.version, ReleaseVersion::parse("1.0.0").unwrap());
    assert_eq!(info.asset_url, "https://example.com/hole-asset");
    assert_eq!(info.asset_name, name);
}

#[skuld::test]
fn release_qualifies_draft_returns_none() {
    let name = platform_asset_name("1.0.0");
    let r = release("v1.0.0", true, false, vec![asset(&name, "https://example.com/hole")]);
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_prerelease_returns_none() {
    let name = platform_asset_name("1.0.0");
    let r = release("v1.0.0", false, true, vec![asset(&name, "https://example.com/hole")]);
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_no_matching_asset_returns_none() {
    // Use an asset name that will never match any platform's ASSET_SUFFIX.
    let r = release(
        "v1.0.0",
        false,
        false,
        vec![asset(
            "hole-1.0.0-linux-amd64.tar.gz",
            "https://example.com/hole.tar.gz",
        )],
    );
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_no_assets_returns_none() {
    let r = release("v1.0.0", false, false, vec![]);
    assert!(release_qualifies(&r).is_none());
}

// parse_next_link =====================================================================================================

#[skuld::test]
fn parse_next_link_standard() {
    let header = r#"<https://api.github.com/repos/test/tags?page=2>; rel="next", <https://api.github.com/repos/test/tags?page=5>; rel="last""#;
    let next = parse_next_link(header).unwrap();
    assert_eq!(next, "https://api.github.com/repos/test/tags?page=2");
}

#[skuld::test]
fn parse_next_link_only_prev() {
    let header = r#"<https://api.github.com/repos/test/tags?page=1>; rel="prev""#;
    assert!(parse_next_link(header).is_none());
}

#[skuld::test]
fn parse_next_link_empty() {
    assert!(parse_next_link("").is_none());
}
