//! `schemars_pin_still_tracks_typify` conformance test, plus unit coverage of
//! the two readers it composes.

use crate::schemars_pin::{renovate_rule_present, requirement_tracks_pin, upstream_schemars, PINNED_SERIES, UPSTREAM};

// requirement_tracks_pin ==============================================================================================

#[skuld::test]
fn a_caret_requirement_on_the_pinned_series_tracks_it() {
    assert!(requirement_tracks_pin("^0.8.22"));
    assert!(requirement_tracks_pin("0.8.22"));
    assert!(requirement_tracks_pin("=0.8.22"));
    assert!(requirement_tracks_pin("~0.8"));
    assert!(requirement_tracks_pin("0.8"));
}

#[skuld::test]
fn a_requirement_outside_the_pinned_series_does_not_track_it() {
    // The two that actually break `crates/common/build.rs` (`schema` went
    // private in both), plus the shapes a future upstream bump could take.
    assert!(!requirement_tracks_pin("^0.9.0"));
    assert!(!requirement_tracks_pin("^1.0"));
    assert!(!requirement_tracks_pin("1.2.2"));
    assert!(!requirement_tracks_pin(">=0.9"));
}

/// `0.8` must not match `0.81`: a prefix test on the bare string would, and
/// semver treats them as unrelated series.
#[skuld::test]
fn a_neighbouring_series_is_not_mistaken_for_the_pin() {
    assert!(!requirement_tracks_pin("^0.80.0"));
    assert!(!requirement_tracks_pin("^0.81"));
}

// renovate_rule_present ===============================================================================================

#[skuld::test]
fn the_renovate_reader_finds_a_constraining_schemars_rule() {
    let config = r#"{
      "packageRules": [
        { "matchDepNames": ["schemars"], "allowedVersions": "<0.9" }
      ]
    }"#;
    assert!(renovate_rule_present(config).unwrap());
}

/// A rule that names `schemars` but constrains nothing does not count — it is
/// the `allowedVersions` that suppresses the bump.
#[skuld::test]
fn a_schemars_rule_without_a_version_constraint_does_not_count() {
    let config = r#"{
      "packageRules": [
        { "matchDepNames": ["schemars"], "groupName": "whatever" }
      ]
    }"#;
    assert!(!renovate_rule_present(config).unwrap());
}

#[skuld::test]
fn an_unrelated_rule_set_has_no_schemars_rule() {
    let config = r#"{ "packageRules": [ { "matchDepNames": ["serde"], "allowedVersions": "<2" } ] }"#;
    assert!(!renovate_rule_present(config).unwrap());
    assert!(!renovate_rule_present(r#"{ "extends": ["config:recommended"] }"#).unwrap());
}

// upstream_schemars ===================================================================================================

/// A lockfile shaped like this repo's: two `schemars` in the graph, so the
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
"#;

#[skuld::test]
fn a_qualified_dependency_entry_yields_the_resolved_pair() {
    let (upstream, schemars) = upstream_schemars(QUALIFIED_LOCK).unwrap();
    assert_eq!((upstream.as_str(), schemars.as_str()), ("0.6.2", "0.8.22"));
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
    assert!(
        err.to_string().contains("no longer depends on schemars"),
        "unexpected error: {err}"
    );
}

#[skuld::test]
fn a_missing_upstream_is_reported() {
    let err = upstream_schemars(
        "[[package]]
name = \"serde\"
version = \"1.0.0\"
",
    )
    .unwrap_err();
    assert!(err.to_string().contains("not in Cargo.lock"), "unexpected error: {err}");
}

/// The one that actually fires when upstream moves.
#[skuld::test]
fn a_resolved_schemars_outside_the_pin_does_not_track_it() {
    let lock = QUALIFIED_LOCK.replace("schemars 0.8.22", "schemars 1.2.2");
    let (_, schemars) = upstream_schemars(&lock).unwrap();
    assert!(!requirement_tracks_pin(&schemars));
}

// The conformance test ================================================================================================

/// `schemars` is held at 0.8 because `typify` is, and for no other reason.
///
/// Two things have to hold, and this fails loud when either stops:
///
/// 1. `typify-impl` still resolves a 0.8 `schemars`. When it stops, the pin's
///    whole justification is gone.
/// 2. `.github/renovate.json` still suppresses a bump past it.
///
/// It deliberately does not check that `crates/common/Cargo.toml` agrees with
/// upstream: a mismatch there fails `build.rs` to compile (`E0603`), so this
/// test could only ever run when that is already true. See the module doc.
///
/// If this fails on (1), upstream moved: read oxidecomputer/typify#886 first —
/// the maintainer's stated plan is to drop the schemars schema types for
/// typify's own IR, so the fix may not be `schemars = "1"` at all. Then delete
/// the `allowedVersions` rule from `.github/renovate.json` and this module, and
/// let Renovate re-propose the update it has been holding back
/// (bindreams/hole#379, closed as upstream-blocked).
#[skuld::test]
fn schemars_pin_still_tracks_typify() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent");

    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("failed to read Cargo.lock");
    let (upstream_version, upstream_req) = upstream_schemars(&lock).unwrap();
    assert!(
        requirement_tracks_pin(&upstream_req),
        "{UPSTREAM} {upstream_version} now requires schemars {upstream_req}, not {PINNED_SERIES}.\n\
         The pin in crates/common/Cargo.toml and the allowedVersions rule in .github/renovate.json \
         exist only because of that requirement, so both are now suppressing an update that may be \
         possible.\n\
         Read oxidecomputer/typify#886 before assuming the answer is `schemars = \"1\"`: the stated \
         plan is to drop schemars' schema types for typify's own IR, in which case \
         crates/common/build.rs changes shape rather than changing version.\n\
         Then remove the Renovate rule and this module, and let bindreams/hole#379 be re-proposed."
    );

    let renovate =
        std::fs::read_to_string(root.join(".github/renovate.json")).expect("failed to read .github/renovate.json");
    assert!(
        renovate_rule_present(&renovate).unwrap(),
        ".github/renovate.json no longer constrains `schemars`. Without an `allowedVersions` rule \
         Renovate re-proposes the bump past {PINNED_SERIES} that {UPSTREAM} {upstream_version} cannot \
         compile against — which is bindreams/hole#379, permanently red. Restore the rule, or, if \
         upstream has moved, delete this module too."
    );
}
