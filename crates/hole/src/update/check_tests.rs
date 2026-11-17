use super::*;
use hole_common::version::ReleaseVersion;

use crate::update::Withdrawal;

fn platform_asset_name(version: &str) -> String {
    format!("hole-{version}-{}", asset_suffix())
}

fn tag(name: &str) -> GitHubTag {
    GitHubTag { name: name.to_string() }
}

/// Build a tag in the hole release track (`releases/hole/v<X.Y.Z>`).
fn hole_tag(version: &str) -> GitHubTag {
    tag(&format!("releases/hole/v{version}"))
}

/// A list withdrawing `version` on `platforms` (every platform when `None`).
fn withdrawals(version: &str, platforms: Option<&[&str]>) -> Withdrawals {
    Withdrawals::new(vec![Withdrawal {
        version: ReleaseVersion::parse(version).unwrap(),
        platforms: platforms.map(|ids| ids.iter().map(|id| id.to_string()).collect()),
        reason: "a reason".to_string(),
        url: "https://example.com/why".to_string(),
    }])
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

// asset_suffix ========================================================================================================

#[skuld::test]
fn asset_suffix_matches_the_shared_release_source() {
    assert_eq!(asset_suffix(), xtask_lib::asset::host_update_asset_suffix());
}

#[skuld::test]
fn the_asset_suffix_starts_with_the_platform_id() {
    let suffix = asset_suffix();
    assert!(suffix.starts_with(PLATFORM_ID), "{suffix} / {PLATFORM_ID}");
    assert!(suffix.len() > PLATFORM_ID.len());
}

#[skuld::test]
fn the_platform_id_is_one_of_the_release_platform_ids() {
    assert!(
        hole_common::withdrawals::PLATFORM_IDS.contains(&PLATFORM_ID),
        "{PLATFORM_ID}"
    );
}

// candidate_tags ======================================================================================================

#[skuld::test]
fn candidate_tags_filters_non_semver() {
    let tags = vec![hole_tag("1.0.0"), tag("nightly"), hole_tag("2.0.0"), tag("bad")];
    let current = ReleaseVersion::parse("0.9.0").unwrap();
    let result = candidate_tags(&tags, &current, false, &Withdrawals::default());
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_sorts_descending() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("3.0.0"), hole_tag("2.0.0")];
    let current = ReleaseVersion::parse("0.1.0").unwrap();
    let result = candidate_tags(&tags, &current, false, &Withdrawals::default());
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
    assert_eq!(result[1].0, ReleaseVersion::parse("2.0.0").unwrap());
    assert_eq!(result[2].0, ReleaseVersion::parse("1.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_excludes_older_and_equal() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("2.0.0"), hole_tag("3.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false, &Withdrawals::default());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("3.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_includes_equal_when_snapshot() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("2.0.0")];
    let current = ReleaseVersion::parse("2.0.0").unwrap();
    let result = candidate_tags(&tags, &current, true, &Withdrawals::default());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("2.0.0").unwrap());
}

#[skuld::test]
fn candidate_tags_empty_when_no_newer() {
    let tags = vec![hole_tag("1.0.0"), hole_tag("0.5.0")];
    let current = ReleaseVersion::parse("1.0.0").unwrap();
    let result = candidate_tags(&tags, &current, false, &Withdrawals::default());
    assert!(result.is_empty());
}

#[skuld::test]
fn candidate_tags_filters_other_product_tracks() {
    // Other release-track tags (galoshes, garter, ex-ray) must not
    // trigger hole auto-updates even when they are higher-versioned.
    let tags = vec![
        hole_tag("1.0.0"),
        tag("releases/galoshes/v9.9.9"),
        tag("releases/garter/v9.9.9"),
        tag("releases/ex-ray/v9.9.9"),
        // Bare-semver tag (no `releases/<track>/` prefix) — must be ignored.
        tag("v0.1.0"),
    ];
    let current = ReleaseVersion::parse("0.9.0").unwrap();
    let result = candidate_tags(&tags, &current, false, &Withdrawals::default());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, ReleaseVersion::parse("1.0.0").unwrap());
    assert_eq!(result[0].1, "releases/hole/v1.0.0");
}

#[skuld::test]
fn a_withdrawn_tag_is_not_a_candidate() {
    let tags = vec![hole_tag("0.8.0"), hole_tag("0.7.1")];
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.8.0", Some(&[PLATFORM_ID]));

    let result = candidate_tags(&tags, &current, false, &list);

    assert_eq!(
        result,
        vec![(
            ReleaseVersion::parse("0.7.1").unwrap(),
            "releases/hole/v0.7.1".to_string()
        )]
    );
}

#[skuld::test]
fn a_tag_withdrawn_on_another_platform_stays_a_candidate() {
    let tags = vec![hole_tag("0.8.0"), hole_tag("0.7.1")];
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.8.0", Some(&["plan9-mips"]));

    let result = candidate_tags(&tags, &current, false, &list);

    assert_eq!(result[0].0, ReleaseVersion::parse("0.8.0").unwrap());
    assert_eq!(result.len(), 2);
}

#[skuld::test]
fn a_tag_withdrawn_on_every_platform_is_not_a_candidate() {
    let tags = vec![hole_tag("0.8.0")];
    let current = ReleaseVersion::parse("0.7.0").unwrap();

    let result = candidate_tags(&tags, &current, false, &withdrawals("0.8.0", None));

    assert!(result.is_empty());
}

#[skuld::test]
fn a_snapshot_skips_its_own_withdrawn_version() {
    let tags = vec![hole_tag("0.7.0")];
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.7.0", Some(&[PLATFORM_ID]));

    assert!(candidate_tags(&tags, &current, true, &list).is_empty());
    assert_eq!(candidate_tags(&tags, &current, true, &Withdrawals::default()).len(), 1);
}

// running_withdrawn ===================================================================================================

#[skuld::test]
fn the_running_version_is_reported_when_listed() {
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.7.0", Some(&[PLATFORM_ID]));

    let found = running_withdrawn(&current, false, &list).unwrap();

    assert_eq!(found.url, "https://example.com/why");
}

#[skuld::test]
fn a_snapshot_of_a_withdrawn_version_is_not_reported() {
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.7.0", Some(&[PLATFORM_ID]));

    assert!(running_withdrawn(&current, true, &list).is_none());
    assert!(running_withdrawn(&current, false, &list).is_some());
}

#[skuld::test]
fn the_running_version_is_not_reported_when_listed_for_another_platform() {
    let current = ReleaseVersion::parse("0.7.0").unwrap();
    let list = withdrawals("0.7.0", Some(&["plan9-mips"]));

    assert!(running_withdrawn(&current, false, &list).is_none());
}

#[skuld::test]
fn another_version_listed_is_not_the_running_one() {
    let current = ReleaseVersion::parse("0.7.0").unwrap();

    assert!(running_withdrawn(&current, false, &withdrawals("0.7.1", None)).is_none());
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

/// A release page that is not an `https` URL with a host is dropped; the release is still offered.
#[skuld::test]
fn a_release_whose_page_is_not_https_is_offered_without_a_notes_link() {
    for page in [
        "http://github.com/bindreams/hole/releases/tag/v1.0.0",
        "file:///c:/windows/system32/calc.exe",
        "github.com/bindreams/hole",
        "https://",
        "",
    ] {
        let mut r = release("releases/hole/v1.0.0", false, false, full_asset_set("1.0.0"));
        r.html_url = page.to_string();

        let info = release_qualifies(&r).unwrap_or_else(|| panic!("{page:?} hid a valid release"));
        assert_eq!(info.html_url, None, "{page:?}");
        assert_eq!(info.version, ReleaseVersion::parse("1.0.0").unwrap(), "{page:?}");
    }
}

#[skuld::test]
fn an_https_release_page_is_carried_as_the_notes_link() {
    let r = release("releases/hole/v1.0.0", false, false, full_asset_set("1.0.0"));

    let info = release_qualifies(&r).unwrap();

    assert_eq!(
        info.html_url.as_deref(),
        Some("https://github.com/test/repo/releases/tag/releases/hole/v1.0.0")
    );
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

// check_with ==========================================================================================================

/// One failure of each kind a list fetch can end in: the three ways a fetched list is unreadable, and a
/// transport error.
fn list_failures() -> [(&'static str, UpdateError); 4] {
    fn unreadable<T>(result: Result<T, hole_common::withdrawals::WithdrawalListError>) -> UpdateError {
        match result {
            Ok(_) => panic!("the fixture must be unreadable"),
            Err(e) => UpdateError::from(e),
        }
    }
    [
        (
            "not an envelope",
            unreadable(hole_common::withdrawals::parse_envelope("[")),
        ),
        (
            "no signature verifies",
            unreadable(hole_common::withdrawals::parse_signed(
                "payload: |\n  withdrawn: []\nsignatures: []\n",
            )),
        ),
        (
            "not a payload",
            unreadable(hole_common::withdrawals::parse_payload("withdrawn: 1")),
        ),
        (
            "transport",
            UpdateError::Io(std::io::Error::other("connection refused")),
        ),
    ]
}

#[skuld::test]
fn an_unreadable_list_fails_the_check_before_any_tag_is_fetched() {
    for (name, failure) in list_failures() {
        let expected = failure.to_string();
        let tags_fetched = std::cell::Cell::new(false);

        let result = check_with(
            || Err(failure),
            || {
                tags_fetched.set(true);
                Ok(vec![])
            },
        );

        assert_eq!(result.unwrap_err().to_string(), expected, "{name}: the check's error");
        assert!(!tags_fetched.get(), "{name}: no tag is fetched without a readable list");
    }
}

#[skuld::test]
fn a_readable_list_lets_the_tag_walk_run() {
    let tags_fetched = std::cell::Cell::new(0);

    let result = check_with(
        || Ok(withdrawals("0.0.1", None)),
        || {
            tags_fetched.set(tags_fetched.get() + 1);
            Ok(vec![])
        },
    );

    assert_eq!(tags_fetched.get(), 1);
    assert_eq!(result.unwrap().offer, None, "no tag, no offer");
}
