use super::*;
use hole_common::version::ReleaseVersion;

/// Asset name that matches the current platform's ASSET_SUFFIX.
fn platform_asset_name(version: &str) -> String {
    format!("hole-{version}-{ASSET_SUFFIX}")
}

fn tag(name: &str) -> GitHubTag {
    GitHubTag { name: name.to_string() }
}

/// Build a tag in the hole release track (`releases/hole/v<X.Y.Z>`).
fn hole_tag(version: &str) -> GitHubTag {
    tag(&format!("releases/hole/v{version}"))
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

/// Build the standard set of release assets (main + SHA256SUMS + SHA256SUMS.minisig) for the given version.
fn full_asset_set(version: &str) -> Vec<GitHubAsset> {
    let name = platform_asset_name(version);
    vec![
        asset(&name, &format!("https://example.com/{name}")),
        asset("SHA256SUMS", "https://example.com/SHA256SUMS"),
        asset("SHA256SUMS.minisig", "https://example.com/SHA256SUMS.minisig"),
    ]
}

// candidate_tags ======================================================================================================

#[skuld::test]
fn candidate_tags_filters_non_semver() {
    let tags = vec![hole_tag("1.0.0"), tag("nightly"), hole_tag("2.0.0"), tag("bad")];
    let current = ReleaseVersion::parse("0.9.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_sorts_descending() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("3.0.0"), hole_tag("2.0.0")];
    let current = ReleaseVersion::parse("0.1.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[2].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_excludes_older_and_equal() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("2.0.0"), hole_tag("3.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_includes_equal_when_snapshot() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("2.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, true);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_empty_when_no_newer() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("0.5.0")];
    let current = ReleaseVersion::parse("1.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert!(result.is_empty());
}

#[skuld::test]
fn candidate_tags_filters_other_product_tracks() {
    // Other release-track tags (galoshes, garter, v2ray-plugin) must not
    // trigger hole auto-updates even when they are higher-versioned.
    let tags = vec![
        hole_tag("1.0.0"),
        tag("releases/galoshes/v9.9.9"),
        tag("releases/garter/v9.9.9"),
        tag("releases/v2ray-plugin/v9.9.9"),
        // Legacy `v0.1.0` tag predating the new scheme — must be ignored.
        tag("v0.1.0"),
    ];
    let current = ReleaseVersion::parse("0.9.0").unwrap();
    let result = candidate_tags(&tags, &current, false);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("1.0.0").unwrap());
    assert_eq!(result[0].1, "releases/hole/v1.0.0");
}

// release_qualifies ===================================================================================================

#[skuld::test]
fn release_qualifies_valid() {
    let name = platform_asset_name("1.0.0");
    let r = release("releases/hole/v1.0.0", false, false, full_asset_set("1.0.0"));
    let info = release_qualifies(&r).unwrap();
    assert_eq!(info.version, ReleaseVersion::parse("1.0.0").unwrap());
    assert_eq!(info.asset_url, format!("https://example.com/{name}"));
    assert_eq!(info.asset_name, name);
    assert_eq!(info.sha256sums_url, "https://example.com/SHA256SUMS");
    assert_eq!(info.sha256sums_minisig_url, "https://example.com/SHA256SUMS.minisig");
}

#[skuld::test]
fn release_qualifies_draft_returns_none() {
    let r = release("releases/hole/v1.0.0", true, false, full_asset_set("1.0.0"));
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_prerelease_returns_none() {
    let r = release("releases/hole/v1.0.0", false, true, full_asset_set("1.0.0"));
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_no_matching_asset_returns_none() {
    let r = release(
        "releases/hole/v1.0.0",
        false,
        false,
        vec![
            asset("hole-1.0.0-linux-amd64.tar.gz", "https://example.com/hole.tar.gz"),
            asset("SHA256SUMS", "https://example.com/SHA256SUMS"),
            asset("SHA256SUMS.minisig", "https://example.com/SHA256SUMS.minisig"),
        ],
    );
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_no_assets_returns_none() {
    let r = release("releases/hole/v1.0.0", false, false, vec![]);
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_missing_sha256sums_returns_none() {
    let name = platform_asset_name("1.0.0");
    let r = release(
        "releases/hole/v1.0.0",
        false,
        false,
        vec![
            asset(&name, "https://example.com/hole-asset"),
            asset("SHA256SUMS.minisig", "https://example.com/SHA256SUMS.minisig"),
        ],
    );
    assert!(release_qualifies(&r).is_none());
}

#[skuld::test]
fn release_qualifies_missing_sha256sums_minisig_returns_none() {
    let name = platform_asset_name("1.0.0");
    let r = release(
        "releases/hole/v1.0.0",
        false,
        false,
        vec![
            asset(&name, "https://example.com/hole-asset"),
            asset("SHA256SUMS", "https://example.com/SHA256SUMS"),
        ],
    );
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
