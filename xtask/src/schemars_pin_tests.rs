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

/// A range that stops short of the series' top has become the `enabled: false`
/// the rule is written to avoid. The whole tail is the property, not "more than
/// one release": the number the next security patch carries is not knowable in
/// advance, so any ceiling below the next series can block it.
///
/// Answered from the range's own endpoints, like every other question in this
/// module. A probe at one high in-series version cannot tell `>=0.8, <0.8.30`,
/// which admits 0.8.23 through 0.8.29, from a range that admits nothing at all.
#[skuld::test]
fn a_requirement_that_stops_short_of_the_series_top_no_longer_admits_patches() {
    for whole_tail in [
        "<0.9",
        "^0.8.22",
        "0.8",
        "*",
        ">=0.8.16, <0.9",
        // The endpoint is 0.9.0-alpha, which sorts above every 0.8.x release.
        "<=0.9.0-alpha",
    ] {
        assert!(
            requirement_admits_series_patches(whole_tail).unwrap(),
            "req: {whole_tail}"
        );
    }
    for capped in [
        "=0.8.22",
        ">=0.8, <0.8.30",
        "<=0.8.30",
        // The input that separates the interval from a probe: a ceiling above
        // every patch anyone would sample, and still a ceiling.
        "<0.8.99999",
        // Nothing inside the series at all, from either side.
        ">=0.9",
        ">=2.0, <1.0",
        // Pre-release-only ranges. Each sits inside `[0.8.0, 0.9.0)` by semver
        // ordering while admitting no release at all — the tightest freeze
        // there is, and the one a bounds check that ignores pre-releases calls
        // healthy.
        "=0.9.0-alpha",
        "=0.9.0-0",
        ">=0.9.0-alpha, <0.9.0",
        "=0.8.22-rc.1",
    ] {
        assert!(!requirement_admits_series_patches(capped).unwrap(), "req: {capped}");
    }
}

/// Renovate reads `allowedVersions` through node-semver, which separates ANDed
/// comparators with whitespace. Refusing that spelling reds a pin that works.
#[skuld::test]
fn an_npm_spaced_range_is_read_rather_than_refused() {
    assert!(requirement_admits_series_patches(">=0.8.22 <0.9").unwrap());
    assert_eq!(requirement_admits_beyond_pin(">=0.8.22 <0.9").unwrap(), None);
    assert_eq!(
        requirement_admits_beyond_pin(">=0.8 <2")
            .unwrap()
            .map(|v| v.to_string()),
        Some("0.9.0".to_string())
    );
    check_renovate_rule(&renovate_config(&REAL_RULE.replace("<0.9", ">=0.8.22 <0.9"))).unwrap();
}

/// An OR range is a union of intervals and this guard carries one. Reading a
/// single branch of `<0.9 || >=2` would call a range that readmits 2.x a pin,
/// so it is refused — and the refusal has to say that, not that Renovate cannot
/// read it.
#[skuld::test]
fn an_or_range_is_refused_as_a_union_this_guard_does_not_evaluate() {
    let err = requirement_admits_beyond_pin("<0.9 || >=2").unwrap_err();
    let message = err.to_string();
    assert!(message.contains("OR range"), "unexpected error: {message}");
    assert!(
        !message.contains("is not a semver requirement range"),
        "Renovate reads this range; the finding must not claim otherwise: {message}"
    );
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

/// [`REAL_RULE`] with one more selector spliced in ahead of `matchManagers`.
fn rule_with(selector: &str) -> String {
    REAL_RULE.replace(r#""matchManagers""#, &format!("{selector},\n  \"matchManagers\""))
}

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
    let message = err.to_string();
    assert!(message.contains("can ever land"), "unexpected error: {message}");
    assert!(
        message.contains("at or above 0.8.23"),
        "the error must name the ceiling this range sets: {message}"
    );
}

/// MUTATION: `<0.9` → `>=0.8, <0.8.30`. 0.8.23 through 0.8.29 still land, so
/// "no 0.8.x patch can ever land" would be a false sentence a maintainer would
/// act on. The rule is still broken — the next security patch's number is not
/// knowable in advance — and the finding has to be the ceiling the range itself
/// sets.
#[skuld::test]
fn a_rule_that_caps_the_series_short_names_the_ceiling_it_sets() {
    let err = check_renovate_rule(&renovate_config(&REAL_RULE.replace("<0.9", ">=0.8, <0.8.30")))
        .expect_err("a range that stops at 0.8.30 cannot carry an arbitrary future patch");
    let message = err.to_string();
    assert!(
        message.contains("at or above 0.8.30"),
        "the error must name the ceiling the range itself sets: {message}"
    );
    assert!(
        !message.contains("9999"),
        "the ceiling is read off the range's endpoints, not from a probe version: {message}"
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
/// Each leaves a rule that reads exactly like the pin and suppresses nothing.
/// `matchManagers` is one of about fifteen such keys, so the guard enumerates
/// the ones it can evaluate and rejects the rest rather than the other way
/// round.
///
/// Five of these pass `--strict`; the other four do not, which is the design
/// working rather than a gap. `matchUpdateTypes` is a hard error beside a range
/// ("packageRules cannot combine both matchUpdateTypes and allowedVersions")
/// and `matchBaseBranches` is one without a `baseBranchPatterns` to reference;
/// `excludeDepNames`/`excludePackageNames` are schema-valid but require
/// migration (into `matchDepNames: ["schemars", "!schemars"]`), which `--strict`
/// fails on. So several of the scopings that would silently kill this rule
/// cannot land here at all, and the guard covers the rest — including, as the
/// entries below assert, the unmigrated spellings themselves.
#[skuld::test]
fn a_rule_scoped_by_a_selector_the_guard_cannot_evaluate_is_rejected() {
    for selector in [
        r#""matchDatasources": ["npm"]"#,
        r#""matchCategories": ["js"]"#,
        r#""matchRepositories": ["someone/else"]"#,
        r#""matchBaseBranches": ["nonexistent"]"#,
        r#""matchCurrentVersion": ">=1.0.0""#,
        r#""matchUpdateTypes": ["major"]"#,
        r#""matchJsonata": ["false"]"#,
        r#""excludeDepNames": ["schemars"]"#,
        r#""excludePackageNames": ["schemars"]"#,
    ] {
        let err = check_renovate_rule(&renovate_config(&rule_with(selector)))
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

/// MUTATION: a selector list emptied out. `matchRegexOrGlobList` opens with
/// `if (!patterns.length) return false`, and every matcher forwards to it once
/// the key is present — so an empty array selects *nothing*. The rule reads
/// exactly like the pin, validates, and Renovate never applies it.
#[skuld::test]
fn a_rule_with_an_emptied_selector_list_is_rejected() {
    for emptied in [
        r#""matchManagers": ["cargo"], "matchDepNames": [], "allowedVersions": "<0.9""#,
        r#""matchManagers": [], "matchDepNames": ["schemars"], "allowedVersions": "<0.9""#,
        r#""matchManagers": ["cargo"], "matchPackageNames": [], "allowedVersions": "<0.9""#,
        r#""matchManagers": ["cargo"], "matchDepNames": ["schemars"], "matchFileNames": [], "allowedVersions": "<0.9""#,
    ] {
        let err = check_renovate_rule(&renovate_config(&format!("{{ {emptied} }}")))
            .err()
            .unwrap_or_else(|| panic!("an empty list selects nothing, and must not pass: {emptied}"));
        assert!(
            err.to_string().contains("no packageRule naming"),
            "unexpected error: {err}"
        );
    }
}

/// A list of only negations is not an empty list. Renovate skips the
/// positive-entry check when there are no positive entries, leaving "everything
/// except these" — which reaches `schemars`.
#[skuld::test]
fn a_list_of_only_negations_still_reaches_schemars() {
    check_renovate_rule(&renovate_config(&REAL_RULE.replace(r#"["schemars"]"#, r#"["!serde"]"#))).unwrap();
}

/// `matchFileNames` is the one subject carrying path separators, and
/// minimatch's `*` stops at one. Only a pattern that spells the separator — or
/// `**` as a whole segment, the one place minimatch does cross — reaches
/// `crates/common/Cargo.toml`.
#[skuld::test]
fn a_file_name_glob_does_not_cross_a_path_separator() {
    for dead in [
        "*/Cargo.toml",
        "crates/*",
        "**Cargo.toml",
        "*.toml",
        // minimatch tests the segment against `**` exactly, so a longer run is
        // not a globstar and does not cross `/` either. A bare `***` is *not*
        // here: it reaches `Cargo.lock`, which has no separator to cross.
        "crates/***",
    ] {
        let selector = format!(r#""matchFileNames": ["{dead}"]"#);
        let err = check_renovate_rule(&renovate_config(&rule_with(&selector)))
            .err()
            .unwrap_or_else(|| panic!("minimatch's `*` does not cross `/`, so {dead} is dead"));
        let message = err.to_string();
        assert!(message.contains("`matchFileNames`"), "unexpected error: {message}");
        // The `Unknown` bail names the selector too, so naming it is not enough
        // to show the pattern was *decided* dead.
        assert!(
            !message.contains("cannot determine"),
            "these are decidable exclusions, not unknowns: {message}"
        );
    }
    // A trailing `/` is an empty final segment minimatch keeps, and no subject
    // here ends in a separator. Decidably dead, not undecidable.
    for trailing in ["crates/**/", "**/", "crates/common/Cargo.toml/"] {
        let selector = format!(r#""matchFileNames": ["{trailing}"]"#);
        let err = check_renovate_rule(&renovate_config(&rule_with(&selector)))
            .err()
            .unwrap_or_else(|| panic!("{trailing} requires a trailing separator the subjects do not have"));
        assert!(
            !err.to_string().contains("cannot determine"),
            "a trailing separator is decided, not undecidable: {err}"
        );
    }
    for live in [
        "crates/**",
        "**/Cargo.toml",
        "crates/*/Cargo.toml",
        "**/*.toml",
        "crates/common/Cargo.toml",
        // minimatch drops the empty segments a `//` run leaves behind, so these
        // are the same pattern as the one above.
        "crates//common/Cargo.toml",
        "crates///common/Cargo.toml",
        "crates//**",
        // Renovate short-circuits a bare `*` to "everything" before minimatch
        // ever sees it.
        "*",
        // `***` is a plain `*`, which does not cross the manifest's separators
        // — but `Cargo.lock` has none, and it is the second subject.
        "***",
    ] {
        let selector = format!(r#""matchFileNames": ["{live}"]"#);
        check_renovate_rule(&renovate_config(&rule_with(&selector)))
            .unwrap_or_else(|e| panic!("Renovate applies {live}; the guard must too\n{e}"));
    }
}

/// MUTATION: `ignoreDeps`. `fetch.js` sets `skipReason: "ignored"` two lines
/// above the `enabled === false` branch and both run after `applyPackageRules`,
/// so this is `enabled: false` under a second name — and it takes the 0.8.x
/// patches with it just the same. Renovate reads it at the top level and on any
/// applying packageRule.
#[skuld::test]
fn an_ignored_dependency_is_rejected_like_a_disabled_one() {
    let top_level = format!(r#"{{ "ignoreDeps": ["schemars"], "packageRules": [ {REAL_RULE} ] }}"#);
    let in_rule = renovate_config(&REAL_RULE.replace(
        r#""allowedVersions": "<0.9""#,
        r#""allowedVersions": "<0.9", "ignoreDeps": ["schemars"]"#,
    ));
    for config in [top_level, in_rule] {
        let err = check_renovate_rule(&config).expect_err("an ignored dependency gets no updates at all");
        let message = err.to_string();
        assert!(message.contains("ignoreDeps"), "unexpected error: {message}");
        assert!(
            message.contains("patch"),
            "the error must say what the ignore costs: {message}"
        );
    }
}

/// An ignore naming something else, or riding a rule Renovate does not apply,
/// leaves the pin alone.
#[skuld::test]
fn an_ignore_that_does_not_reach_schemars_is_accepted() {
    check_renovate_rule(&format!(
        r#"{{ "ignoreDeps": ["serde"], "packageRules": [ {REAL_RULE} ] }}"#
    ))
    .unwrap();

    let out_of_reach = r#"{ "matchManagers": ["npm"], "ignoreDeps": ["schemars"] }"#;
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {out_of_reach} ] }}"#)).unwrap();
}

/// The cargo manager tags each dependency with the manifest section it came
/// from (`modules/manager/cargo/schema.ts`), and `schemars` is declared under
/// `[build-dependencies]` — so scoping the pin that way is correct, valid, and
/// works. Rejecting it reds a working config.
#[skuld::test]
fn a_rule_scoped_to_the_build_dependencies_dep_type_is_accepted() {
    for selector in [
        r#""matchDepTypes": ["build-dependencies"]"#,
        r#""matchDepTypes": ["dependencies", "build-dependencies"]"#,
        r#""matchDepTypes": ["build-*"]"#,
        r#""matchDepTypes": ["!dev-dependencies"]"#,
    ] {
        check_renovate_rule(&renovate_config(&rule_with(selector)))
            .unwrap_or_else(|e| panic!("Renovate applies {selector}; the guard must too\n{e}"));
    }
}

/// The other sections `cargo` emits are decidable exclusions, not unknowns:
/// `schemars` is declared under none of them.
#[skuld::test]
fn a_rule_scoped_to_another_dep_type_is_rejected() {
    for selector in [
        r#""matchDepTypes": ["dependencies"]"#,
        r#""matchDepTypes": ["dev-dependencies"]"#,
        r#""matchDepTypes": ["workspace.dependencies"]"#,
    ] {
        let err = check_renovate_rule(&renovate_config(&rule_with(selector)))
            .err()
            .unwrap_or_else(|| panic!("schemars is not declared under {selector}"));
        let message = err.to_string();
        assert!(message.contains("`matchDepTypes`"), "unexpected error: {message}");
        assert!(
            !message.contains("cannot determine"),
            "a dep type this guard knows is decided, not undecidable: {message}"
        );
    }
}

/// Renovate builds every glob with `nocase: true`, so a selector differing only
/// in case is the same selector. Reading it as absent sends a maintainer to
/// restore a rule that is right there and working.
#[skuld::test]
fn selector_matching_is_case_insensitive() {
    for selector in [
        r#""matchDepNames": ["Schemars"]"#,
        r#""matchPackageNames": ["SCHEMARS"]"#,
        r#""matchPackageNames": ["SCHE*"]"#,
    ] {
        let rule = REAL_RULE.replace(r#""matchDepNames": ["schemars"]"#, selector);
        check_renovate_rule(&renovate_config(&rule))
            .unwrap_or_else(|e| panic!("Renovate applies {selector}; the guard must too\n{e}"));
    }
    check_renovate_rule(&renovate_config(&REAL_RULE.replace(r#"["cargo"]"#, r#"["Cargo"]"#))).unwrap();
    check_renovate_rule(&renovate_config(&rule_with(
        r#""matchFileNames": ["CRATES/**/CARGO.TOML"]"#,
    )))
    .unwrap();
}

/// A delimited regex is `new RegExp(body)` — case-sensitive unless the `/i`
/// suffix asks otherwise. `nocase` belongs to the glob path and must not leak
/// here.
#[skuld::test]
fn a_delimited_regex_stays_case_sensitive_without_the_i_flag() {
    let rule = REAL_RULE.replace(
        r#""matchDepNames": ["schemars"]"#,
        r#""matchPackageNames": ["/^SCHEMARS$/"]"#,
    );
    let err = check_renovate_rule(&renovate_config(&rule)).expect_err("/^SCHEMARS$/ does not match schemars");
    assert!(
        err.to_string().contains("no packageRule naming"),
        "unexpected error: {err}"
    );
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

/// An unclosed delimiter is not undecidable. `isRegexMatch` needs both
/// `/^!?\//` and `/\/i?$/`, so `"/schemars"` is not a regex at all: Renovate
/// hands it to minimatch, where it is a literal that cannot match `schemars`.
/// Decidably dead, and the finding that fits a dead rule is the one a dead rule
/// gets.
#[skuld::test]
fn an_unclosed_regex_delimiter_is_a_dead_literal_glob() {
    let rule = REAL_RULE.replace(
        r#""matchDepNames": ["schemars"]"#,
        r#""matchPackageNames": ["/schemars"]"#,
    );
    let err = check_renovate_rule(&renovate_config(&rule)).expect_err("`/schemars` is a literal, not a regex");
    let message = err.to_string();
    assert!(message.contains("no packageRule naming"), "unexpected error: {message}");
    assert!(
        !message.contains("cannot determine"),
        "a spelling Renovate resolves is decided here too: {message}"
    );
}

/// Renovate passes minimatch neither `noext` nor a brace option, so extglob
/// (`@()`, `?()`, `+()`, `*()`) and brace alternation are live syntax. Reading
/// `@(schemars)` as a literal makes it select nothing — which turns a rule
/// Renovate *does* apply into one the guard thinks is dead, the exact shape
/// that lets a later widening rule through unnoticed.
#[skuld::test]
fn an_extglob_is_undecidable_rather_than_read_as_a_literal() {
    for spelling in [
        "@(schemars)",
        "?(schemars)",
        "+(schemars)",
        "*(schemars)",
        "schemar+(s)",
    ] {
        // As a later rule's selector: it reaches `schemars`, so its `<2` is
        // what resolves, and the guard must not pass the config.
        let later = format!(
            r#"{{ "matchManagers": ["cargo"], "matchPackageNames": ["{spelling}"], "allowedVersions": "<2" }}"#
        );
        let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later} ] }}"#))
            .err()
            .unwrap_or_else(|| panic!("Renovate applies {spelling} to schemars; the guard must not pass it"));
        assert!(err.to_string().contains("cannot determine"), "unexpected error: {err}");
    }
    // An extglob reached through an interior `!` is still one.
    let interior = r#"{ "matchManagers": ["cargo"], "matchPackageNames": ["sch!(emars)"], "allowedVersions": "<2" }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {interior} ] }}"#))
        .expect_err("`sch!(emars)` is an extglob, not a literal");
    assert!(err.to_string().contains("cannot determine"), "unexpected error: {err}");

    // A *leading* `!(` is minimatch's negation winning over extglob, which is
    // what the guard does too — so that one stays decided.
    let leading = REAL_RULE.replace(r#"["schemars"]"#, r#"["!(serde)"]"#);
    check_renovate_rule(&renovate_config(&leading)).expect("`!(serde)` negates the literal `(serde)`");

    // Unprefixed parentheses are literal in minimatch, and stay literal here.
    let parens = REAL_RULE.replace(
        r#""matchDepNames": ["schemars"]"#,
        r#""matchPackageNames": ["(schemars)"]"#,
    );
    let err = check_renovate_rule(&renovate_config(&parens)).expect_err("`(schemars)` is a literal, not a group");
    assert!(
        err.to_string().contains("no packageRule naming"),
        "a bare paren is decided, not undecidable: {err}"
    );
}

/// `matchRegexOrGlobList` buckets an entry as a negation on *one* leading `!`,
/// but the predicate it then calls is minimatch's, and `parseNegate` consumes
/// every `!` and toggles each time. So `!!foo` is filed under the negations
/// while requiring a plain `foo` — and since it does not match, Renovate
/// applies the rule to nothing. Stripping one `!` reads it as "everything
/// except foo" and passes a dead pin.
#[skuld::test]
fn a_doubled_negation_is_not_read_as_a_single_one() {
    let rule = REAL_RULE.replace(r#"["schemars"]"#, r#"["!!foo"]"#);
    let err = check_renovate_rule(&renovate_config(&rule))
        .expect_err("`!!foo` requires the dep to be `foo`, so the rule never reaches schemars");
    assert!(
        err.to_string().contains("no packageRule naming"),
        "unexpected error: {err}"
    );

    // Doubled back onto the name itself, it selects, exactly as one `!` would not.
    let live = REAL_RULE.replace(r#"["schemars"]"#, r#"["!!schemars"]"#);
    check_renovate_rule(&renovate_config(&live)).expect("`!!schemars` is `schemars` with the sense toggled twice");

    // The case the `!`-counting exists for. `isRegexMatch` is `/^!?\//` — one
    // `!` at most — so a second one takes the entry away from the regex path
    // for good: minimatch gets the glob `/schemars/`, three path segments that
    // match no dependency name. Stripping both `!`s and *then* asking whether
    // what is left looks like a regex compiles it as one and selects.
    let dead = REAL_RULE.replace(r#"["schemars"]"#, r#"["!!/schemars/"]"#);
    let err = check_renovate_rule(&renovate_config(&dead))
        .expect_err("`!!/schemars/` is the glob `/schemars/`, which matches no dependency name");
    assert!(
        err.to_string().contains("no packageRule naming"),
        "unexpected error: {err}"
    );
    // A third `!` toggles the sense back, and the glob still matches nothing —
    // so the negation holds and the rule applies. Same reading, opposite
    // outcome: counting is what makes both come out right.
    let live = REAL_RULE.replace(r#"["schemars"]"#, r#"["!!!/schemars/"]"#);
    check_renovate_rule(&renovate_config(&live)).expect("three `!` leave a negation that nothing trips");
    // One `!` still is the regex negation Renovate defines.
    let negated = REAL_RULE.replace(
        r#""matchDepNames": ["schemars"]"#,
        r#""matchPackageNames": ["!/serde/"]"#,
    );
    check_renovate_rule(&renovate_config(&negated)).expect("`!/serde/` excludes serde and keeps schemars");
}

/// minimatch reads `\` as an escape, so `s\chemars` is the literal `schemars`
/// and `sc\*hemars` is not the glob it looks like. `glob` has no such rule, so
/// both readings would be wrong in opposite directions — decide neither.
#[skuld::test]
fn a_backslash_escape_is_undecidable_rather_than_compared_literally() {
    let later = r#"{ "matchManagers": ["cargo"], "matchPackageNames": ["!s\\chemars"], "allowedVersions": "<2" }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later} ] }}"#))
        .expect_err("`!s\\chemars` vetoes schemars in minimatch, so that rule reaches nothing");
    assert!(err.to_string().contains("cannot determine"), "unexpected error: {err}");
}

/// `util/package-rules/files.ts` tries the `packageFile` and then every entry
/// of `lockFiles`, and the cargo manager sets `lockFiles = ["Cargo.lock"]`. A
/// rule naming only the lockfile still reaches `schemars`, so a later one that
/// does it re-widens the pin.
#[skuld::test]
fn a_file_name_rule_matching_the_lockfile_reaches_the_dependency() {
    for spelling in ["Cargo.lock", "*.lock", "**/Cargo.lock"] {
        let later = format!(
            r#"{{ "matchFileNames": ["{spelling}"], "matchDepNames": ["schemars"], "allowedVersions": "<2" }}"#
        );
        let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later} ] }}"#))
            .err()
            .unwrap_or_else(|| panic!("{spelling} matches the lockfile, so the rule applies"));
        assert!(err.to_string().contains("admits 0.9.0"), "unexpected error: {err}");
    }
    // And the pin itself may be scoped that way.
    check_renovate_rule(&renovate_config(&rule_with(r#""matchFileNames": ["Cargo.lock"]"#))).unwrap();
}

/// `config/index.ts` folds the manager's own block in with `mergeChildConfig`,
/// and `packageRules` is mergeable — so `cargo.packageRules` is appended after
/// the top-level ones and wins last-wins against them. Reading only the
/// top-level array misses a rule that is strictly later than every rule the
/// guard does read.
#[skuld::test]
fn a_manager_scoped_package_rule_is_merged_after_the_top_level_ones() {
    let widening = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "<2" }"#;
    let err = check_renovate_rule(&format!(
        r#"{{ "packageRules": [ {REAL_RULE} ], "cargo": {{ "packageRules": [ {widening} ] }} }}"#
    ))
    .expect_err("`cargo.packageRules` is appended last, so its `<2` is what resolves");
    let message = err.to_string();
    assert!(message.contains("admits 0.9.0"), "unexpected error: {message}");
    assert!(
        message.contains("cargo.packageRules"),
        "the error must name where the winning rule came from: {message}"
    );

    // The pin may equally live there, with nothing at the top level.
    check_renovate_rule(&format!(r#"{{ "cargo": {{ "packageRules": [ {REAL_RULE} ] }} }}"#)).unwrap();
}

/// `enabled` lists `.` and every manager among its `parents`, and `ignoreDeps`
/// is settable in a manager block too. Neither needs a selector to reach
/// `schemars`, and both cost the 0.8.x patches the range exists to keep.
#[skuld::test]
fn a_skip_set_outside_package_rules_is_rejected() {
    for (config, expected) in [
        (
            format!(r#"{{ "enabled": false, "packageRules": [ {REAL_RULE} ] }}"#),
            "the top level",
        ),
        (
            format!(r#"{{ "cargo": {{ "enabled": false }}, "packageRules": [ {REAL_RULE} ] }}"#),
            "cargo",
        ),
        (
            format!(r#"{{ "cargo": {{ "ignoreDeps": ["schemars"] }}, "packageRules": [ {REAL_RULE} ] }}"#),
            "cargo.ignoreDeps",
        ),
    ] {
        let err = check_renovate_rule(&config).expect_err("a skip outside packageRules still skips");
        assert!(
            err.to_string().contains(expected),
            "the error must name where the skip lives, expected {expected}: {err}"
        );
    }
    // `enabled: true` there is not a skip.
    check_renovate_rule(&format!(
        r#"{{ "cargo": {{ "enabled": true }}, "packageRules": [ {REAL_RULE} ] }}"#
    ))
    .unwrap();
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

/// Renovate does not descend into a nested `packageRules`: migration *flattens*
/// it, lifting each child out through `mergeChildConfig` with the parent's
/// fields folded in. So the pin nested inside another rule still resolves to
/// the pin, and there is nothing here for the guard to be blind to.
#[skuld::test]
fn the_pin_nested_inside_another_rule_still_resolves_to_the_pin() {
    let nested = format!(r#"{{ "matchManagers": ["cargo"], "packageRules": [ {REAL_RULE} ] }}"#);
    check_renovate_rule(&renovate_config(&nested)).unwrap();
}

/// The fold is `mergeChildConfig`, not an intersection: a *mergeable* array
/// option present on both sides is **concatenated**, so a parent scoped to
/// `npm` does not confine a child scoped to `cargo` — it widens to both, and
/// the child's `<2` reaches `schemars` after all. An option that is not
/// mergeable (`matchFileNames`) is replaced by the child's instead.
#[skuld::test]
fn a_nested_rule_is_flattened_the_way_migration_flattens_it() {
    let widening = r#"{ "matchManagers": ["npm"],
         "packageRules": [ { "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "<2" } ] }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {widening} ] }}"#))
        .expect_err("the joined `[npm, cargo]` still reaches schemars, and `<2` is last");
    assert!(err.to_string().contains("admits 0.9.0"), "unexpected error: {err}");

    // The direction that tells a join from a replacement: with the parent on
    // `cargo` and the child on `npm`, replacing would leave `[npm]` and the
    // rule would not reach schemars at all. Joining leaves `[cargo, npm]`,
    // which does.
    let joined = r#"{ "matchManagers": ["cargo"],
         "packageRules": [ { "matchManagers": ["npm"], "matchDepNames": ["schemars"], "allowedVersions": "<2" } ] }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {joined} ] }}"#))
        .expect_err("`matchManagers` is mergeable, so the parent's `cargo` rides down onto the child");
    assert!(err.to_string().contains("admits 0.9.0"), "unexpected error: {err}");

    let replaced = r#"{ "matchFileNames": ["crates/**"],
         "packageRules": [ { "matchFileNames": ["package.json"], "matchDepNames": ["schemars"],
             "allowedVersions": "<2" } ] }"#;
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {replaced} ] }}"#))
        .expect("`matchFileNames` is not mergeable, so the child's package.json replaces crates/**");
}

/// Flattening does not cost the guard its other answers: a nested rule that
/// cannot reach `schemars` stops tripping it, and an unreadable selector on one
/// that can is still rejected.
#[skuld::test]
fn a_nested_rule_is_judged_on_what_it_flattens_to() {
    let npm_only = r#"{ "matchManagers": ["npm"],
         "packageRules": [ { "matchDepNames": ["lodash"], "allowedVersions": "<5" } ] }"#;
    check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {npm_only} ] }}"#))
        .expect("an npm-scoped nested rule cannot touch a cargo dependency");

    let unreadable = r#"{ "matchJsonata": ["false"],
         "packageRules": [ { "matchDepNames": ["schemars"], "allowedVersions": "<2" } ] }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {unreadable} ] }}"#))
        .expect_err("the parent's unreadable selector rides down onto the flattened rule");
    assert!(err.to_string().contains("cannot determine"), "unexpected error: {err}");
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
/// The findings are what the *merge* resolves, not "a later rule could also
/// match": the range reported is the one that actually applies, evaluated, at
/// the position it came from. Asserting only "last-wins" passes against a guard
/// that stops at the first rule naming `schemars` and never reads the later
/// range at all.
#[skuld::test]
fn a_later_rule_that_rewidens_the_pin_is_rejected() {
    let later = r#"{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "<2" }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later} ] }}"#))
        .expect_err("a later rule overrides the pin");
    let message = err.to_string();
    assert!(message.contains("last-wins"), "unexpected error: {message}");
    assert!(
        message.contains("`<2` (packageRule #1)"),
        "the error must report the range that resolved, and where: {message}"
    );
    assert!(
        message.contains("admits 0.9.0"),
        "the resolved range has to be evaluated, not just named: {message}"
    );

    let later_disable = r#"{ "matchPackageNames": ["*"], "enabled": false }"#;
    let err = check_renovate_rule(&format!(r#"{{ "packageRules": [ {REAL_RULE}, {later_disable} ] }}"#))
        .expect_err("a later blanket disable overrides the pin");
    let message = err.to_string();
    assert!(message.contains("last-wins"), "unexpected error: {message}");
    assert!(
        message.contains("`enabled: false` (packageRule #1)"),
        "the error must report what resolved, and where: {message}"
    );
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
