//! `schemars_pin_still_tracks_typify` conformance test, plus unit coverage of
//! the readers it composes.
//!
//! The declared-requirement cases below are mutation proofs: each one starts
//! from `metadata()`'s synthetic two-package `cargo metadata` shape with a
//! single field changed to the shape that would silently reopen
//! bindreams/hole#379, asserting that the guard notices. The Renovate rule
//! itself is no longer modelled here — see the module doc for why.

use crate::schemars_pin::{
    check_declared_requirements, check_local_pin, check_renovate_boundary, declared_schemars_requirements,
    requirement_admits_beyond_pin, upstream_schemars, verify_offline, version_tracks_pin, PINNED_SERIES, UPSTREAM,
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

/// A range whose bounds cross admits nothing, so it admits nothing *beyond the
/// pin* either. It is still broken — it blocks every 0.8.x patch — but that
/// finding is no longer this module's to report; see the module doc.
#[skuld::test]
fn a_self_contradictory_range_is_not_reported_as_widening() {
    assert_eq!(requirement_admits_beyond_pin(">=2.0, <1.0").unwrap(), None);
}

#[skuld::test]
fn a_requirement_that_is_not_a_semver_range_is_reported_as_unreadable() {
    let err = requirement_admits_beyond_pin("/^0\\.8\\./").unwrap_err();
    assert!(
        err.to_string().contains("not a semver requirement range"),
        "unexpected error: {err}"
    );
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
    assert_eq!(
        (upstream.as_str(), schemars.as_slice()),
        ("0.6.2", ["0.8.22".to_string()].as_slice())
    );
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
    assert_eq!(schemars, vec!["0.8.22".to_string()]);
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
    assert_eq!(
        (upstream.as_str(), schemars.as_slice()),
        ("0.7.0", ["0.8.22".to_string()].as_slice())
    );
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
    assert!(schemars.iter().any(|v| !version_tracks_pin(v).unwrap()));
}

/// Dual resolution — schemars 0.8 kept locked alongside 1.x, the shape
/// `serde_with` already has in this very `Cargo.lock` (0.9.0 and 1.2.1
/// resolved together) — must be caught on every resolved edge, not just the
/// alphabetically-first one. MUTATION: taking only the first edge reports
/// `("0.7.0", "0.8.22")` here and never surfaces the 1.2.1 edge at all.
#[skuld::test]
fn every_resolved_schemars_is_returned_so_dual_resolution_cannot_hide() {
    let lock = r#"
[[package]]
name = "typify-impl"
version = "0.7.0"
dependencies = ["schemars 0.8.22", "schemars 1.2.1"]

[[package]]
name = "schemars"
version = "0.8.22"

[[package]]
name = "schemars"
version = "1.2.1"
"#;
    let (upstream, resolved) = upstream_schemars(lock).unwrap();
    assert_eq!(upstream, "0.7.0");
    assert_eq!(resolved, vec!["0.8.22".to_string(), "1.2.1".to_string()]);
    assert!(resolved.iter().any(|v| !version_tracks_pin(v).unwrap()));
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
        resolved.iter().all(|v| version_tracks_pin(v).unwrap()),
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

// check_renovate_boundary (.github/renovate.json) =====================================================================

fn renovate_json(allowed_versions: &str) -> String {
    format!(
        r#"{{ "packageRules": [
             {{ "matchDepNames": ["some-other-crate"], "allowedVersions": "<9" }},
             {{ "matchManagers": ["cargo"], "matchDepNames": ["schemars"], "allowedVersions": "{allowed_versions}" }}
           ] }}"#
    )
}

#[skuld::test]
fn a_renovate_boundary_matching_pinned_series_is_accepted() {
    check_renovate_boundary(&renovate_json("<0.9")).unwrap();
}

/// MUTATION: `PINNED_SERIES` moved but `.github/renovate.json` was not
/// updated in the same commit. Nothing else notices this drift —
/// `check_local_pin` never reads this file.
#[skuld::test]
fn a_renovate_boundary_off_pinned_series_is_rejected() {
    let err = check_renovate_boundary(&renovate_json("<1.0")).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("<1.0"), "unexpected error: {message}");
    assert!(message.contains("<0.9"), "unexpected error: {message}");
    assert!(message.contains("PINNED_SERIES"), "unexpected error: {message}");
}

#[skuld::test]
fn a_renovate_file_with_no_schemars_rule_is_reported() {
    let err = check_renovate_boundary(r#"{ "packageRules": [] }"#).unwrap_err();
    assert!(
        err.to_string().contains("no packageRules entry"),
        "unexpected error: {err}"
    );
}

// check_declared_requirements (the loop verify() runs) ================================================================

/// `verify`'s own wiring — `cargo_metadata_json` -> `declared_schemars_requirements`
/// -> this loop -> `bail!` on the first widened entry — is otherwise only ever
/// exercised live via `cargo xtask check-schemars-pin`. A regression that
/// checked only `reqs[0]`, or swallowed this loop's `Result`, would ship with
/// nothing failing; these two cases pin the loop's actual behaviour.
#[skuld::test]
fn check_declared_requirements_fails_on_a_widened_entry_anywhere_in_the_list() {
    let reqs = vec!["^0.8.22".to_string(), "^1.0.2".to_string()];
    let err =
        check_declared_requirements("0.6.2", &reqs).expect_err("the second, widened requirement must not be skipped");
    let message = err.to_string();
    assert!(message.contains("1.0.2"), "unexpected error: {message}");
    assert!(message.contains("0.6.2"), "unexpected error: {message}");
}

#[skuld::test]
fn check_declared_requirements_passes_when_every_entry_holds_the_pin() {
    check_declared_requirements("0.6.2", &["^0.8.22".to_string(), "<0.9".to_string()]).unwrap();
}

// The conformance test ================================================================================================

/// `schemars` is held at 0.8 because `typify` is, and for no other reason.
///
/// Two things have to hold, and this fails loud when either stops:
///
/// 1. `typify-impl` still resolves a 0.8 `schemars`.
/// 2. `crates/common/Cargo.toml` still names the series `PINNED_SERIES` does.
///
/// This does not check whether `.github/renovate.json`'s `allowedVersions`
/// rule would actually be applied by Renovate — that model was removed; see
/// the module doc for why. The rule is best-effort noise suppression, and the
/// enforcement that actually matters is `crates/common/build.rs` failing to
/// compile with `E0603` on a bump past `PINNED_SERIES`.
///
/// A third signal, `typify-impl`'s declared requirement, needs a registry and
/// so does not run here; `cargo xtask check-schemars-pin` covers it in the
/// `Lint` job and in the `check-schemars-pin` prek hook, which `prek.toml`
/// gates to commits touching the files this pin lives in. See the module doc
/// for why the split is by lane rather than by strength.
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
