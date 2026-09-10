//! `schemars_pin_still_tracks_typify` conformance test, plus unit coverage of
//! the readers it composes.
//!
//! The Renovate and declared-requirement cases below are mutation proofs: each
//! one is the real artefact with a single field changed to the shape that would
//! silently reopen bindreams/hole#379, asserting that the guard notices.

use crate::schemars_pin::{
    check_local_pin, check_renovate_rule, declared_schemars_requirements, requirement_admits_beyond_pin,
    requirement_admits_series_patches, upstream_schemars, verify_offline, version_tracks_pin, PINNED_SERIES, UPSTREAM,
};

// Series arithmetic ===================================================================================================

#[skuld::test]
fn a_resolved_version_inside_the_series_tracks_the_pin() {
    assert!(version_tracks_pin("0.8.0").unwrap());
    assert!(version_tracks_pin("0.8.22").unwrap());
    assert!(version_tracks_pin("0.8.9999").unwrap());
}

#[skuld::test]
fn a_resolved_version_outside_the_series_does_not_track_the_pin() {
    // The two that actually break `crates/common/build.rs` — `schema` went
    // private in both — plus the shapes a future upstream move could take.
    assert!(!version_tracks_pin("0.9.0").unwrap());
    assert!(!version_tracks_pin("1.2.1").unwrap());
    assert!(!version_tracks_pin("0.7.6").unwrap());
}

/// `0.8` must not match `0.81`: a prefix test on the bare string would, and
/// semver treats them as unrelated series.
#[skuld::test]
fn a_neighbouring_series_is_not_mistaken_for_the_pin() {
    assert!(!version_tracks_pin("0.80.0").unwrap());
    assert!(!version_tracks_pin("0.81.3").unwrap());
}

/// Every operator spelling that still confines to 0.8, across all of semver's
/// bounded forms.
#[skuld::test]
fn a_requirement_confined_to_the_series_admits_nothing_beyond_it() {
    for req in [
        "<0.9",
        "<0.9.0",
        "<=0.8.22",
        "=0.8.22",
        "=0.8",
        "^0.8.22",
        "^0.8",
        "0.8",
        "~0.8",
        "~0.8.22",
        "0.8.*",
        ">=0.8.16, <0.9",
        ">0.8.0, <0.9",
        // A pre-release endpoint is the endpoint: 0.9.0-alpha sorts below
        // 0.9.0, so `version_tracks_pin` puts it inside the series and this
        // range never leaves it.
        "<=0.9.0-alpha",
        "=0.9.0-alpha",
    ] {
        assert_eq!(requirement_admits_beyond_pin(req).unwrap(), None, "req: {req}");
    }
}

/// The mutation at the heart of bindreams/hole#379: a range that still names a
/// bound, still parses, still reads like a pin — and readmits schemars 1.x.
///
/// `^1.0.2` and `>=1.4, <1.5` are here because they are the reason this asks
/// for the range's interval instead of sampling it: neither admits `1.0.0`,
/// `2.0.0` or any other version a probe list would think to try.
#[skuld::test]
fn a_widened_requirement_is_reported_with_the_version_it_readmits() {
    for req in [
        "<2",
        "*",
        ">=0.8",
        ">0.8",
        "<1.3",
        "^0.9",
        "^1.0.2",
        ">=1.4, <1.5",
        "1.*",
        "~1.2.3",
        "<=0.9",
        // Pre-release endpoints past the pin. Both drove the fabricating tail
        // this test's second assertion exists to catch.
        "<=1.0.0-alpha",
        ">=0.9.0-alpha",
    ] {
        let admitted = requirement_admits_beyond_pin(req)
            .unwrap()
            .unwrap_or_else(|| panic!("`{req}` should have been reported as admitting beyond the pin"));
        assert!(
            !version_tracks_pin(&admitted.to_string()).unwrap(),
            "req {req} -> {admitted}"
        );
        assert!(
            cargo_metadata::semver::VersionReq::parse(req)
                .unwrap()
                .matches(&admitted),
            "the reported version must be one `{req}` actually admits, got {admitted}"
        );
    }
    assert_eq!(
        requirement_admits_beyond_pin("<2").unwrap().map(|v| v.to_string()),
        Some("0.9.0".to_string()),
        "the next series up is the first version that matters"
    );
    assert_eq!(
        requirement_admits_beyond_pin("^1.0.2").unwrap().map(|v| v.to_string()),
        Some("1.0.2".to_string()),
        "a range that starts past the pin reports its own floor"
    );
}

/// Whatever version comes back is one the requirement really admits.
///
/// The reported version *is* the finding — it is what a maintainer reads and
/// acts on — so a range that cannot be shown to reach past the pin must not be
/// decorated with a version it does not accept. `<=0.9.0-alpha` is the input
/// that broke this: its interval was computed with the pre-release dropped, no
/// candidate in it matched, and the fallback reported the series boundary
/// regardless.
#[skuld::test]
fn a_reported_version_is_never_fabricated() {
    for req in [
        "<0.9",
        "<=0.8.22",
        "^0.8.22",
        "0.8.*",
        ">=0.8.16, <0.9",
        "<2",
        "*",
        ">=0.8",
        ">0.8",
        "<1.3",
        "^0.9",
        "^1.0.2",
        ">=1.4, <1.5",
        "1.*",
        "~1.2.3",
        "<=0.9",
        "<=0.9.0-alpha",
        "=0.9.0-alpha",
        "<=1.0.0-alpha",
        ">=0.9.0-alpha",
        ">0.9.0-alpha",
        "^0.9.0-alpha",
    ] {
        let Some(admitted) = requirement_admits_beyond_pin(req).unwrap() else {
            continue;
        };
        assert!(
            cargo_metadata::semver::VersionReq::parse(req)
                .unwrap()
                .matches(&admitted),
            "`{req}` was reported as admitting {admitted}, which it does not accept"
        );
        assert!(
            !version_tracks_pin(&admitted.to_string()).unwrap(),
            "`{req}` was reported as admitting {admitted}, which is inside the pin"
        );
    }
}

/// A range that has tightened onto one release has become the `enabled: false`
/// the rule is written to avoid.
#[skuld::test]
fn a_requirement_pinned_to_one_release_no_longer_admits_patches() {
    assert!(requirement_admits_series_patches("<0.9").unwrap());
    assert!(requirement_admits_series_patches("^0.8.22").unwrap());
    assert!(!requirement_admits_series_patches("=0.8.22").unwrap());
}

/// A range whose bounds cross admits nothing, so it admits nothing *beyond the
/// pin* either. It is still broken — it blocks every 0.8.x patch — and that is
/// the finding that fits it.
#[skuld::test]
fn a_self_contradictory_range_is_not_reported_as_widening() {
    assert_eq!(requirement_admits_beyond_pin(">=2.0, <1.0").unwrap(), None);
    assert!(!requirement_admits_series_patches(">=2.0, <1.0").unwrap());
}

#[skuld::test]
fn a_requirement_that_is_not_a_semver_range_is_reported_as_unreadable() {
    let err = requirement_admits_beyond_pin("/^0\\.8\\./").unwrap_err();
    assert!(
        err.to_string().contains("not a semver requirement range"),
        "unexpected error: {err}"
    );
}

// check_renovate_rule =================================================================================================

/// The rule as `.github/renovate.json` actually spells it. Every mutation case
/// below is this string with one field changed.
fn renovate_config(rule: &str) -> String {
    format!(r#"{{ "packageRules": [ {rule} ] }}"#)
}

const REAL_RULE: &str = r#"{
  "description": "schemars is typify's choice, not ours.",
  "matchManagers": ["cargo"],
  "matchDepNames": ["schemars"],
  "allowedVersions": "<0.9"
}"#;

#[skuld::test]
fn the_real_rule_shape_is_accepted() {
    check_renovate_rule(&renovate_config(REAL_RULE)).unwrap();
}

/// MUTATION: `<0.9` → `<2`. Still a constraint, still names schemars, still
/// cargo-scoped — and readmits the 1.x that fails build.rs with E0603.
#[skuld::test]
fn a_rule_widened_past_the_pinned_series_is_rejected() {
    let err = check_renovate_rule(&renovate_config(&REAL_RULE.replace("<0.9", "<2")))
        .expect_err("a rule allowing <2 suppresses nothing");
    let message = err.to_string();
    assert!(message.contains("admits 0.9.0"), "unexpected error: {message}");
    assert!(
        message.contains("379"),
        "the error must name the issue it reopens: {message}"
    );
}

/// MUTATION: `<0.9` → `*`, the do-nothing range.
#[skuld::test]
fn a_rule_allowing_everything_is_rejected() {
    let err = check_renovate_rule(&renovate_config(&REAL_RULE.replace("<0.9", "*")))
        .expect_err("a rule allowing * suppresses nothing");
    assert!(err.to_string().contains("admits 0.9.0"), "unexpected error: {err}");
}

/// MUTATION: `<0.9` → `=0.8.22`. Suppresses the impossible bump and every 0.8.x
/// patch with it — the outcome the rule is a range to avoid.
#[skuld::test]
fn a_rule_that_freezes_the_series_is_rejected() {
    let err = check_renovate_rule(&renovate_config(&REAL_RULE.replace("<0.9", "=0.8.22")))
        .expect_err("a rule allowing exactly one release blocks security patches");
    assert!(
        err.to_string().contains("patch can ever land"),
        "unexpected error: {err}"
    );
}

/// MUTATION: `cargo` → `npm`. schemars is a Rust dependency; the rule never
/// fires.
#[skuld::test]
fn a_rule_scoped_to_the_wrong_manager_is_rejected() {
    let err = check_renovate_rule(&renovate_config(&REAL_RULE.replace(r#"["cargo"]"#, r#"["npm"]"#)))
        .expect_err("a rule scoped to npm never reaches a cargo dependency");
    let message = err.to_string();
    assert!(
        message.contains("`matchManagers`"),
        "the error must name the selector that sidelined the rule: {message}"
    );
    assert!(
        message.contains("`cargo` dependency"),
        "the error must say what the rule failed to reach: {message}"
    );
}

/// MUTATION: add a selector that makes Renovate not apply the rule.
///
/// Each of these is schema-valid — renovate-config-validator --strict accepts
/// them all — and each leaves a rule that reads exactly like the pin and
/// suppresses nothing. `matchManagers` is one of about fifteen such keys, so
/// the guard enumerates the ones it can evaluate and rejects the rest rather
/// than the other way round.
#[skuld::test]
fn a_rule_scoped_by_a_selector_the_guard_cannot_evaluate_is_rejected() {
    for selector in [
        r#""matchDatasources": ["npm"]"#,
        r#""matchCategories": ["js"]"#,
        r#""matchRepositories": ["someone/else"]"#,
        r#""matchBaseBranches": ["nonexistent"]"#,
        r#""matchDepTypes": ["dependencies"]"#,
        r#""matchCurrentVersion": ">=1.0.0""#,
        r#""matchUpdateTypes": ["major"]"#,
        r#""matchJsonata": ["false"]"#,
        r#""excludeDepNames": ["schemars"]"#,
        r#""excludePackageNames": ["schemars"]"#,
    ] {
        let rule = REAL_RULE.replace(r#""matchManagers""#, &format!("{selector},\n  \"matchManagers\""));
        let err = check_renovate_rule(&renovate_config(&rule))
            .err()
            .unwrap_or_else(|| panic!("a rule scoped by {selector} may never apply, and must not pass"));
        let message = err.to_string();
        assert!(
            message.contains("cannot determine"),
            "an unreadable selector is not an absent rule: {message}"
        );
        assert!(
            message.contains("must be taught"),
            "the error must say what to do about it: {message}"
        );
    }
}

/// MUTATION: `matchFileNames` pointed at a manifest `schemars` is not in.
/// Decidable, unlike the selectors above, and so it gets the finding that fits:
/// the rule exists and Renovate does not apply it.
#[skuld::test]
fn a_rule_scoped_to_another_manifest_is_rejected() {
    let rule = REAL_RULE.replace(
        r#""matchManagers""#,
        r#""matchFileNames": ["package.json"],
  "matchManagers""#,
    );
    let err = check_renovate_rule(&renovate_config(&rule)).expect_err("schemars is not declared in package.json");
    let message = err.to_string();
    assert!(message.contains("`matchFileNames`"), "unexpected error: {message}");
    assert!(
        message.contains("crates/common/Cargo.toml"),
        "the error must name the manifest the rule failed to reach: {message}"
    );
}

/// MUTATION: a negation that cancels the rule's own name match. Renovate vetoes
/// on `!schemars` and the rule matches nothing.
#[skuld::test]
fn a_rule_whose_negation_cancels_its_name_match_is_rejected() {
    let rule = REAL_RULE.replace(r#"["schemars"]"#, r#"["schemars", "!schemars"]"#);
    let err = check_renovate_rule(&renovate_config(&rule)).expect_err("a vetoed rule matches nothing");
    assert!(err.to_string().contains("`matchDepNames`"), "unexpected error: {err}");
}

/// The dep-name spellings Renovate honours, which the guard must read as the
/// pin rather than as no rule at all. The glob form is not hypothetical:
/// `.github/renovate.json`'s own Tauri rule is spelled that way.
#[skuld::test]
fn the_dep_name_spellings_renovate_honours_are_accepted() {
    for selector in [
        r#""matchDepNames": ["schemars"]"#,
        r#""matchPackageNames": ["schemars"]"#,
        r#""matchPackageNames": ["schemars*"]"#,
        r#""matchPackageNames": ["sch*mars"]"#,
        r#""matchPackageNames": ["/^schemars$/"]"#,
        r#""matchPackageNames": ["/^SCHEMARS$/i"]"#,
        r#""matchPackageNames": ["schemars", "serde"]"#,
        r#""matchPackageNames": ["!serde"]"#,
        r#""matchPackagePatterns": ["^schemars$"]"#,
        r#""matchDepPatterns": ["^schemars$"]"#,
    ] {
        let rule = REAL_RULE.replace(r#""matchDepNames": ["schemars"]"#, selector);
        check_renovate_rule(&renovate_config(&rule))
            .unwrap_or_else(|e| panic!("Renovate applies {selector}; the guard must too\n{e}"));
    }
}

/// A spelling the guard cannot decide is reported as undecided. "No rule names
/// schemars" would send a maintainer to restore a rule that is right there.
#[skuld::test]
fn an_undecidable_name_spelling_is_reported_as_undecidable_not_absent() {
    for selector in [
        // `glob` does not expand brace alternation.
        r#""matchPackageNames": ["{schemars,serde}"]"#,
        // A regex Rust's engine will not compile. Renovate's might.
        r#""matchPackageNames": ["/^(?=schemars)/"]"#,
        // An opening delimiter with no closing one is not a spelling Renovate
        // defines, so neither reading of it is safe.
        r#""matchPackageNames": ["/schemars"]"#,
    ] {
        let rule = REAL_RULE.replace(r#""matchDepNames": ["schemars"]"#, selector);
        let err = check_renovate_rule(&renovate_config(&rule))
            .err()
            .unwrap_or_else(|| panic!("{selector} is not decidable here, and must not pass"));
        let message = err.to_string();
        assert!(message.contains("cannot determine"), "unexpected error: {message}");
        assert!(
            !message.contains("no packageRule naming"),
            "undecidable is not absent, and the two must not share a message: {message}"
        );
    }
}

/// An absent `matchManagers` matches every manager, `cargo` among them. Not a
/// mutation to reject — rejecting it would fail a config that works.
#[skuld::test]
fn a_rule_with_no_manager_scope_is_accepted() {
    let rule = REAL_RULE.replace("\"matchManagers\": [\"cargo\"],\n  ", "");
    assert!(!rule.contains("matchManagers"));
    check_renovate_rule(&renovate_config(&rule)).unwrap();
}

/// MUTATION: add `"enabled": false`. Renovate skips the dependency entirely, so
/// 0.8.x patches stop too.
#[skuld::test]
fn a_disabled_rule_is_rejected() {
    let rule = REAL_RULE.replace(
        r#""allowedVersions": "<0.9""#,
        r#""allowedVersions": "<0.9", "enabled": false"#,
    );
    let err = check_renovate_rule(&renovate_config(&rule)).expect_err("a disabled rule blocks security patches");
    assert!(err.to_string().contains("enabled: false"), "unexpected error: {err}");
}

/// A rule that names `schemars` but constrains nothing does not count — it is
/// the `allowedVersions` that suppresses the bump.
#[skuld::test]
fn a_schemars_rule_without_a_version_constraint_is_rejected() {
    let rule = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "groupName": "whatever" }"#;
    let err = check_renovate_rule(&renovate_config(rule)).expect_err("naming a dependency constrains nothing");
    assert!(
        err.to_string().contains("no `allowedVersions`"),
        "unexpected error: {err}"
    );
}

/// Renovate lets a packageRule carry its own `packageRules`, so a nested
/// `allowedVersions` is reachable from a rule this merge only reads the surface
/// of. Same class as an unreadable selector, same answer.
#[skuld::test]
fn a_rule_nesting_its_own_package_rules_is_rejected() {
    let nested = format!(r#"{{ "matchManagers": ["cargo"], "packageRules": [ {REAL_RULE} ] }}"#);
    let err = check_renovate_rule(&renovate_config(&nested)).expect_err("this guard reads the top-level array");
    let message = err.to_string();
    assert!(message.contains("cannot determine"), "unexpected error: {message}");
    assert!(message.contains("nests its own"), "unexpected error: {message}");
}

#[skuld::test]
fn a_config_with_no_schemars_rule_is_rejected() {
    let unrelated = r#"{ "matchDepNames": ["serde"], "allowedVersions": "<2" }"#;
    for config in [
        renovate_config(unrelated),
        r#"{ "extends": ["config:recommended"] }"#.to_string(),
        r#"{ "packageRules": [] }"#.to_string(),
    ] {
        let err = check_renovate_rule(&config).expect_err("no rule names schemars");
        assert!(
            err.to_string().contains("no packageRule naming"),
            "unexpected error: {err}"
        );
    }
}

/// Renovate is last-wins, so a rule after the pin that can also reach
/// `schemars` under `cargo` replaces it. `.github/renovate.json`'s own comments
/// depend on this ordering ("these compiler rules must stay LAST").
#[skuld::test]
fn a_later_rule_that_rewidens_the_pin_is_rejected() {
    let later = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "<2" }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later} ] }}"#))
        .expect_err("a later rule overrides the pin");
    assert!(err.to_string().contains("last-wins"), "unexpected error: {err}");

    let later_disable = r#"{ "matchPackageNames": ["*"], "enabled": false }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later_disable} ] }}"#))
        .expect_err("a later blanket disable overrides the pin");
    assert!(err.to_string().contains("last-wins"), "unexpected error: {err}");
}

/// The rules that really do follow the pin in `.github/renovate.json` — scoped
/// to other managers, or setting neither `allowedVersions` nor `enabled` — must
/// not trip the last-wins check.
#[skuld::test]
fn later_rules_that_cannot_reach_schemars_are_accepted() {
    let others = [
        r#"{ "matchManagers": ["gomod"], "matchDepNames": ["go"], "enabled": false }"#,
        r#"{ "matchManagers": ["rust-toolchain"], "matchDepNames": ["rust"], "automerge": false }"#,
        r#"{ "matchPackageNames": ["@tauri-apps/**", "tauri"], "groupName": "Tauri" }"#,
        r#"{ "matchManagers": ["cargo"], "matchDepNames": ["serde"], "allowedVersions": "<2" }"#,
        // This repo's own first rule: a blanket `enabled: false` narrowed to a
        // path `schemars` is not declared in.
        r#"{ "matchFileNames": ["external/*/.circleci/**"], "enabled": false }"#,
        // A selector the guard cannot read, on a rule another selector has
        // already excluded. Excluded settles it; unreadable does not get a vote.
        r#"{ "matchManagers": ["gomod"], "matchJsonata": ["true"], "enabled": false }"#,
    ];
    for other in others {
        check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {other} ] }}"#))
            .unwrap_or_else(|e| panic!("rule should not have tripped last-wins: {other}\n{e}"));
    }
}

/// Renovate merges *every* applying rule, so last-wins runs forwards as well as
/// backwards: an earlier widened rule is overridden by the pin that follows it,
/// and the resolved range is safe. Taking the first rule that names `schemars`
/// and scanning only later ones reports the `<2` that never applies.
#[skuld::test]
fn an_earlier_widened_rule_is_overridden_by_the_pin_that_follows_it() {
    let earlier = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "<2" }"#;
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {earlier}, {REAL_RULE} ] }}"#))
        .expect("Renovate resolves the later `<0.9`, which holds the pin");

    let disabled = r#"{ "matchPackageNames": ["*"], "enabled": false }"#;
    let reenabled = REAL_RULE.replace(r#""allowedVersions""#, r#""enabled": true, "allowedVersions""#);
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {disabled}, {reenabled} ] }}"#))
        .expect("the pin rule re-enables what the blanket disable turned off");
}

/// A grouping rule above the pin is the realistic version of the same mistake:
/// it names `schemars`, sets no `allowedVersions`, and Renovate merges the pin
/// on top of it. Reading only the first naming rule reports "no
/// `allowedVersions`" about a config that has one.
#[skuld::test]
fn an_earlier_grouping_rule_does_not_displace_the_pin() {
    let grouping = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "groupName": "Rust crates" }"#;
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {grouping}, {REAL_RULE} ] }}"#))
        .expect("a rule that sets no allowedVersions cannot displace one that does");
}

// upstream_schemars (Cargo.lock) ======================================================================================

/// A lockfile shaped like this repo's: several `schemars` in the graph, so the
/// dependency entry carries its version.
const QUALIFIED_LOCK: &str = r#"
[[package]]
name = "typify-impl"
version = "0.6.2"
dependencies = ["regress", "schemars 0.8.22", "serde"]

[[package]]
name = "schemars"
version = "0.8.22"

[[package]]
name = "schemars"
version = "0.9.0"

[[package]]
name = "schemars"
version = "1.2.1"
"#;

#[skuld::test]
fn a_qualified_dependency_entry_yields_the_resolved_pair() {
    let (upstream, schemars) = upstream_schemars(QUALIFIED_LOCK).unwrap();
    assert_eq!((upstream.as_str(), schemars.as_str()), ("0.6.2", "0.8.22"));
}

/// Older lockfile formats append the source to the dependency entry; the
/// version is the second field either way.
#[skuld::test]
fn a_dependency_entry_carrying_its_source_still_yields_the_version() {
    let lock = QUALIFIED_LOCK.replace(
        r#""schemars 0.8.22""#,
        r#""schemars 0.8.22 (registry+https://github.com/rust-lang/crates.io-index)""#,
    );
    let (_, schemars) = upstream_schemars(&lock).unwrap();
    assert_eq!(schemars, "0.8.22");
}

/// With a single `schemars` in the graph Cargo omits the version from the
/// dependency entry, so it has to be resolved against the package list.
#[skuld::test]
fn an_unqualified_dependency_entry_resolves_against_the_sole_package() {
    let lock = r#"
[[package]]
name = "typify-impl"
version = "0.7.0"
dependencies = ["schemars"]

[[package]]
name = "schemars"
version = "0.8.22"
"#;
    let (upstream, schemars) = upstream_schemars(lock).unwrap();
    assert_eq!((upstream.as_str(), schemars.as_str()), ("0.7.0", "0.8.22"));
}

/// Cargo drops the version only when the name is unambiguous, so an unqualified
/// entry beside several `schemars` packages means the lockfile disagrees with
/// itself. Report that, rather than guessing which one was meant.
#[skuld::test]
fn an_ambiguous_unqualified_dependency_entry_is_reported_as_an_inconsistent_lockfile() {
    let lock = QUALIFIED_LOCK.replace(r#""schemars 0.8.22""#, r#""schemars""#);
    let err = upstream_schemars(&lock).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("without a version"), "unexpected error: {message}");
    assert!(
        message.contains("0.8.22, 0.9.0, 1.2.1"),
        "the error must list the candidates: {message}"
    );
    assert!(
        message.contains("cargo update"),
        "the error must say how to fix it: {message}"
    );
}

#[skuld::test]
fn an_unqualified_entry_with_no_schemars_package_is_reported() {
    let lock = r#"
[[package]]
name = "typify-impl"
version = "0.7.0"
dependencies = ["schemars"]
"#;
    let err = upstream_schemars(lock).unwrap_err();
    assert!(
        err.to_string().contains("no `schemars` package is locked"),
        "unexpected error: {err}"
    );
}

/// Upstream landing its own IR is the expected end state, and it must read as
/// "the pin is obsolete", not as a broken check.
#[skuld::test]
fn upstream_dropping_schemars_is_reported_as_an_obsolete_pin() {
    let lock = r#"
[[package]]
name = "typify-impl"
version = "0.8.0"
dependencies = ["regress", "serde"]
"#;
    let err = upstream_schemars(lock).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("no longer has `schemars`"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("expected end state"),
        "the error must say this is not a breakage: {message}"
    );
    assert!(
        message.contains("typify#886"),
        "the error must point at the upstream issue: {message}"
    );
    assert!(!message.contains("  "), "wrapped-string-literal space runs: {message}");
}

#[skuld::test]
fn a_missing_upstream_is_reported() {
    let err = upstream_schemars("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n").unwrap_err();
    let message = err.to_string();
    assert!(message.contains("not in Cargo.lock"), "unexpected error: {message}");
    assert!(!message.contains("  "), "wrapped-string-literal space runs: {message}");
}

/// A second `typify` in the graph turns this lane red; the message must send
/// the reader to the real cause rather than to the schemars pin.
#[skuld::test]
fn two_locked_upstreams_are_reported_as_a_typify_split_not_a_schemars_problem() {
    let lock = format!(
        "{QUALIFIED_LOCK}\n[[package]]\nname = \"{UPSTREAM}\"\nversion = \"0.7.0\"\ndependencies = [\"schemars 0.8.22\"]\n"
    );
    let err = upstream_schemars(&lock).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("not a schemars problem"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("0.6.2, 0.7.0"),
        "the error must list the versions: {message}"
    );
    assert!(!message.contains("  "), "wrapped-string-literal space runs: {message}");
}

/// The one that fires when upstream is forced off the series.
#[skuld::test]
fn a_resolved_schemars_outside_the_pin_does_not_track_it() {
    let lock = QUALIFIED_LOCK.replace("schemars 0.8.22", "schemars 1.2.2");
    let (_, schemars) = upstream_schemars(&lock).unwrap();
    assert!(!version_tracks_pin(&schemars).unwrap());
}

// declared_schemars_requirements (cargo metadata) =====================================================================

/// `cargo metadata --format-version 1`, reduced to the fields this reads.
/// `req` is what the lockfile cannot show.
fn metadata(deps: &str) -> String {
    format!(
        r#"{{ "packages": [
             {{ "name": "{UPSTREAM}", "version": "0.6.2", "dependencies": [ {deps} ] }},
             {{ "name": "serde", "version": "1.0.0", "dependencies": [] }}
           ] }}"#
    )
}

const NORMAL_PIN: &str = r#"{ "name": "schemars", "req": "^0.8.22", "kind": null }"#;

#[skuld::test]
fn a_declared_requirement_inside_the_series_is_read_back() {
    let (version, reqs) = declared_schemars_requirements(&metadata(NORMAL_PIN)).unwrap();
    assert_eq!(
        (version.as_str(), reqs.as_slice()),
        ("0.6.2", ["^0.8.22".to_string()].as_slice())
    );
    assert_eq!(requirement_admits_beyond_pin(&reqs[0]).unwrap(), None);
}

/// THE blind spot in the lockfile signal, and the reason this reader exists:
/// upstream widens, `Cargo.lock` keeps the satisfying 0.8 entry, and only the
/// declared requirement shows the change.
#[skuld::test]
fn a_widened_declared_requirement_is_caught_while_the_lockfile_stays_green() {
    let widened = r#"{ "name": "schemars", "req": ">=0.8, <2", "kind": null }"#;
    let (_, reqs) = declared_schemars_requirements(&metadata(widened)).unwrap();
    let admitted = requirement_admits_beyond_pin(&reqs[0])
        .unwrap()
        .expect("a requirement admitting 1.x must be reported");
    assert_eq!(admitted.to_string(), "0.9.0");

    // The lockfile that goes with it is untouched, and still passes.
    let (_, resolved) = upstream_schemars(QUALIFIED_LOCK).unwrap();
    assert!(
        version_tracks_pin(&resolved).unwrap(),
        "the resolved signal is blind to this"
    );
}

/// Dual support — several optional declarations of the same dependency, the
/// shape `serde_with` already has — must be caught on the widest of them, not
/// the first.
#[skuld::test]
fn every_declared_requirement_is_returned_so_dual_support_cannot_hide() {
    let dual = format!(r#"{NORMAL_PIN}, {{ "name": "schemars", "req": "^1.0.2", "kind": null }}"#);
    let (_, reqs) = declared_schemars_requirements(&metadata(&dual)).unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(reqs.iter().any(|r| requirement_admits_beyond_pin(r).unwrap().is_some()));
}

/// Only a normal dependency constrains what a consumer links against; a
/// dev-dependency on schemars 1.x says nothing about typify's public API.
#[skuld::test]
fn dev_and_build_declarations_are_not_read_as_the_constraint() {
    let mixed = format!(
        r#"{NORMAL_PIN}, {{ "name": "schemars", "req": "^1.0.2", "kind": "dev" }}, {{ "name": "schemars", "req": "^1.0.2", "kind": "build" }}"#
    );
    let (_, reqs) = declared_schemars_requirements(&metadata(&mixed)).unwrap();
    assert_eq!(reqs, vec!["^0.8.22".to_string()]);
}

#[skuld::test]
fn upstream_declaring_no_normal_schemars_dependency_is_reported_as_an_obsolete_pin() {
    let only_dev = r#"{ "name": "schemars", "req": "^0.8.22", "kind": "dev" }"#;
    let err = declared_schemars_requirements(&metadata(only_dev)).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("no normal `schemars` dependency"),
        "unexpected error: {message}"
    );
    assert!(message.contains("expected end state"), "unexpected error: {message}");
}

#[skuld::test]
fn a_missing_upstream_in_metadata_is_reported() {
    let err = declared_schemars_requirements(r#"{ "packages": [] }"#).unwrap_err();
    assert!(
        err.to_string().contains("does not appear in `cargo metadata`"),
        "unexpected error: {err}"
    );
}

#[skuld::test]
fn two_upstreams_in_metadata_are_reported_as_a_typify_split() {
    let two = format!(
        r#"{{ "packages": [
             {{ "name": "{UPSTREAM}", "version": "0.6.2", "dependencies": [ {NORMAL_PIN} ] }},
             {{ "name": "{UPSTREAM}", "version": "0.7.0", "dependencies": [ {NORMAL_PIN} ] }}
           ] }}"#
    );
    let err = declared_schemars_requirements(&two).unwrap_err();
    assert!(
        err.to_string().contains("not a schemars problem"),
        "unexpected error: {err}"
    );
}

// check_local_pin (crates/common/Cargo.toml) ==========================================================================

#[skuld::test]
fn a_local_pin_on_the_series_is_accepted() {
    check_local_pin("[build-dependencies]\nschemars = \"0.8\"\n").unwrap();
    check_local_pin("[build-dependencies]\nschemars = { version = \"0.8.22\" }\n").unwrap();
}

/// MUTATION: the manifest and `PINNED_SERIES` drift apart. Nothing else notices
/// — the guard would go on policing a series the build no longer uses.
#[skuld::test]
fn a_local_pin_off_the_series_is_rejected() {
    let err = check_local_pin("[build-dependencies]\nschemars = \"1\"\n")
        .expect_err("a manifest off PINNED_SERIES leaves the guard checking the wrong thing");
    let message = err.to_string();
    assert!(message.contains("admits"), "unexpected error: {message}");
    assert!(
        message.contains("PINNED_SERIES"),
        "the error must name both copies: {message}"
    );
}

#[skuld::test]
fn a_manifest_without_the_build_dependency_is_reported() {
    let err = check_local_pin("[dependencies]\nserde = \"1\"\n").unwrap_err();
    assert!(
        err.to_string().contains("no `schemars` build-dependency"),
        "unexpected error: {err}"
    );
}

// The conformance test ================================================================================================

/// `schemars` is held at 0.8 because `typify` is, and for no other reason.
///
/// Three things have to hold, and this fails loud when any stops:
///
/// 1. `typify-impl` still resolves a 0.8 `schemars`.
/// 2. `.github/renovate.json` still *effectively* suppresses a bump past it —
///    the range is evaluated, not merely found.
/// 3. `crates/common/Cargo.toml` still names the series `PINNED_SERIES` does.
///
/// A fourth, `typify-impl`'s declared requirement, needs a registry and so does
/// not run here; `cargo xtask check-schemars-pin` covers it in the `Lint` job
/// and in the `check-schemars-pin` prek hook, which `prek.toml` gates to
/// commits touching the files this pin lives in. See the module doc for why the
/// split is by lane rather than by strength.
///
/// `repo_root()` rather than `env!("CARGO_MANIFEST_DIR")`: this binary runs
/// from a nextest archive under `--workspace-remap`, where the build-time path
/// does not exist.
#[skuld::test]
fn schemars_pin_still_tracks_typify() {
    let root = crate::repo_root().expect("repo root");
    if let Err(e) = verify_offline(&root) {
        panic!("the schemars {PINNED_SERIES} pin no longer holds:\n\n{e:#}");
    }
}
