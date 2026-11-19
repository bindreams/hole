use std::path::PathBuf;

use super::config::Ecosystem;
use super::{check_overrides_used, default_output, write_from, write_output, Component, Config, NoticesError, Origin};
use crate::manifest::{Arch, Os, Platform};

const WINDOWS: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MACOS: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};

fn component(name: &str, version: &str) -> Component {
    Component {
        name: name.to_owned(),
        version: version.to_owned(),
        origin: Origin::Crate,
        license: Some("MIT".to_owned()),
        source_dir: None,
        url: None,
        modified_copy: false,
        replaces: None,
        text_dir: None,
    }
}

fn config(overrides: &str) -> Config {
    Config::parse(&format!("licenses:\n  - {{id: MIT, text: own}}\noverrides:{overrides}")).unwrap()
}

#[skuld::test]
fn the_hosts_own_artifact_has_one_fixed_path_however_the_host_was_named() {
    // The platform is the resolved one: `--os windows --arch amd64` on a Windows host is the host.
    for platform in [WINDOWS, MACOS] {
        assert_eq!(
            default_output(&platform, Some(platform)),
            PathBuf::from(".cache/notices/NOTICES.md")
        );
    }
}

#[skuld::test]
fn another_platforms_file_is_in_its_own_folder() {
    assert_eq!(
        default_output(&MACOS, Some(WINDOWS)),
        PathBuf::from(".cache/notices/darwin-arm64/NOTICES.md")
    );
    assert_eq!(
        default_output(&WINDOWS, Some(MACOS)),
        PathBuf::from(".cache/notices/windows-amd64/NOTICES.md")
    );
}

#[skuld::test]
fn on_a_host_that_is_not_known_a_named_platform_is_another() {
    assert_eq!(
        default_output(&MACOS, None),
        PathBuf::from(".cache/notices/darwin-arm64/NOTICES.md")
    );
}

#[skuld::test]
fn an_override_for_a_component_of_the_artifact_is_used() {
    let config = config("\n  - {name: tun, ecosystem: crate, version: 0.8.13, license: MIT}\n  - {name: tun, ecosystem: crate, version: \"0.8.13\", texts: [{license: MIT, text: t, source: u}]}\n");
    check_overrides_used(&config, &[component("tun", "0.8.13")]).unwrap();
}

#[skuld::test]
fn an_override_that_matches_no_component_fails() {
    let config = config("\n  - {name: dropped-crate, ecosystem: crate, version: 1.0.0, license: MIT}\n");
    let err = check_overrides_used(&config, &[component("tun", "0.8.13")]).unwrap_err();
    assert!(matches!(err, NoticesError::UnusedEntry { .. }), "{err:?}");
    assert!(err.to_string().contains("dropped-crate"), "{err}");
}

#[skuld::test]
fn an_override_that_matches_nothing_says_which_artifact_and_how_to_scope_it() {
    let config = config("\n  - {name: dropped-crate, ecosystem: crate, version: 1.0.0, license: MIT}\n");
    let message = check_overrides_used(&config, &[component("tun", "0.8.13")])
        .unwrap_err()
        .to_string();
    assert!(message.contains("this artifact"), "{message}");
    assert!(message.contains("platforms:"), "{message}");
}

#[skuld::test]
fn an_override_for_a_version_that_was_bumped_away_fails() {
    let config = config("\n  - {name: tun, ecosystem: crate, version: \"0.8.12\", license: MIT}\n");
    let err = check_overrides_used(&config, &[component("tun", "0.8.13")]).unwrap_err();
    assert!(err.to_string().contains("0.8.12"), "{err}");
}

#[skuld::test]
fn writing_the_output_again_does_not_change_a_file_linked_to_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("windows-amd64").join("NOTICES.md");
    write_output(&out, "first").unwrap();
    // What `stage` leaves in a staged directory: a hard link of the generated file.
    let staged = dir.path().join("staged-NOTICES.md");
    std::fs::hard_link(&out, &staged).unwrap();

    write_output(&out, "second").unwrap();

    assert_eq!(std::fs::read_to_string(&staged).unwrap(), "first");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "second");
}

/// One value of every variant of [`NoticesError`], with whether the generator collects it with the other components
/// that cannot be placed (`true`) or stops at it (`false`). A new variant has to be added here by hand: it is not
/// compiled until `NoticesError::is_about_one_component` has an arm for it.
pub(super) fn every_variant() -> Vec<(NoticesError, bool)> {
    let text = |s: &str| s.to_owned();
    vec![
        (
            NoticesError::Io {
                path: PathBuf::from("x"),
                source: std::io::Error::other("e"),
            },
            false,
        ),
        (
            NoticesError::NotUtf8 {
                path: PathBuf::from("x"),
            },
            false,
        ),
        (
            NoticesError::Config {
                path: text("p"),
                reason: text("r"),
            },
            false,
        ),
        (
            NoticesError::Provision {
                what: text("w"),
                command: text("c"),
            },
            false,
        ),
        (
            NoticesError::Tool {
                command: text("c"),
                reason: text("r"),
            },
            false,
        ),
        (
            NoticesError::UnusedEntry {
                entry: text("e"),
                reason: text("r"),
            },
            false,
        ),
        (NoticesError::UnlistedFile { path: text("p") }, false),
        (
            NoticesError::BadExpression {
                component: text("c"),
                ecosystem: Ecosystem::Crate,
                name: text("n"),
                version: text("v"),
                expression: text("e"),
                reason: text("r"),
            },
            true,
        ),
        (
            NoticesError::LicenseNotOnList {
                component: text("c"),
                expression: text("e"),
            },
            true,
        ),
        (
            NoticesError::NoLicense {
                component: text("c"),
                ecosystem: Ecosystem::Crate,
                name: text("n"),
                version: text("v"),
            },
            true,
        ),
        (
            NoticesError::NoText {
                component: text("c"),
                origin: Origin::Crate,
                name: text("n"),
                license: text("l"),
            },
            true,
        ),
        (
            NoticesError::UnusedText {
                component: text("c"),
                name: text("n"),
                license: text("l"),
            },
            true,
        ),
        (
            NoticesError::LicenseConflict {
                component: text("c"),
                name: text("n"),
                version: text("v"),
                declared: text("d"),
                entry: text("e"),
            },
            true,
        ),
    ]
}

#[skuld::test]
fn a_failure_about_one_components_licence_is_collected_and_any_other_stops_the_run() {
    for (error, collected) in every_variant() {
        assert_eq!(error.is_about_one_component(), collected, "{error}");
    }
}

#[skuld::test]
fn an_entry_whose_crate_was_dropped_is_unused_though_an_npm_package_of_the_name_remains() {
    let config = config("\n  - {name: widget, ecosystem: crate, version: 1.0.0, license: MIT}\n");
    let mut package = component("widget", "1.0.0");
    package.origin = Origin::Npm;
    let err = check_overrides_used(&config, &[package]).unwrap_err();
    assert!(matches!(err, NoticesError::UnusedEntry { .. }), "{err:?}");
    assert!(err.to_string().contains("widget"), "{err}");
}

#[skuld::test]
fn an_entry_is_used_by_a_component_of_its_ecosystem() {
    let config = config("\n  - {name: widget, ecosystem: npm, version: 1.0.0, license: MIT}\n");
    let mut package = component("widget", "1.0.0");
    package.origin = Origin::Npm;
    check_overrides_used(&config, &[package, component("widget", "1.0.0")]).unwrap();
}

fn mit_only() -> Config {
    Config::parse(
        "licenses:
  - {id: MIT, text: own}
",
    )
    .unwrap()
}

/// A component that cannot be placed: its licence is not on the list.
fn unplaceable(name: &str) -> Component {
    Component {
        license: Some("GPL-2.0-only".to_owned()),
        ..component(name, "1.0.0")
    }
}

#[skuld::test]
fn every_component_that_cannot_be_placed_is_named_in_one_error_and_no_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out").join("NOTICES.md");
    let components = vec![
        unplaceable("first"),
        Component {
            license: None,
            ..component("second", "2.0.0")
        },
        // Placed, but only when the others are.
        Component {
            source_dir: Some(dir.path().to_owned()),
            ..component("fine", "3.0.0")
        },
    ];
    std::fs::write(dir.path().join("LICENSE"), "MIT text").unwrap();

    let err = write_from(components, &mit_only(), "9.9.9", &out).unwrap_err();

    let message = err.to_string();
    assert!(message.starts_with("2 components cannot be placed:"), "{message}");
    assert!(
        message.contains("first 1.0.0") && message.contains("second 2.0.0"),
        "{message}"
    );
    assert!(!message.contains("fine"), "{message}");
    assert!(
        !out.exists() && !out.parent().unwrap().exists(),
        "nothing is written on failure"
    );
}

#[skuld::test]
fn an_error_that_is_not_about_one_component_stops_the_run_where_it_arises() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("NOTICES.md");
    let components = vec![
        unplaceable("first"),
        // MIT asks for its own file, and the folder is not there: an error about the run, not about the licence.
        Component {
            source_dir: Some(dir.path().join("missing")),
            ..component("unreadable", "2.0.0")
        },
        unplaceable("third"),
    ];

    let err = write_from(components, &mit_only(), "9.9.9", &out).unwrap_err();

    let notices = err.downcast_ref::<NoticesError>().expect("the run's own error");
    assert!(matches!(notices, NoticesError::Io { .. }), "{notices:?}");
    assert!(!err.to_string().contains("cannot be placed"), "{err}");
    assert!(!out.exists());
}

#[skuld::test]
fn placed_components_are_written_to_the_given_file_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("widget");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("LICENSE"), "MIT text of widget").unwrap();
    let out = dir.path().join("deep").join("NOTICES.md");
    let components = vec![Component {
        source_dir: Some(source),
        ..component("widget", "1.0.0")
    }];

    let written = write_from(components, &mit_only(), "9.9.9", &out).unwrap();

    let text = std::fs::read_to_string(&out).unwrap();
    assert!(
        text.contains("Hole 9.9.9") && text.contains("MIT text of widget"),
        "{text}"
    );
    assert_eq!(written.bytes, text.len());
    assert_eq!(written.taken.len(), 1);
}
