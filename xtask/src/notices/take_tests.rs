use std::path::Path;

use super::config::Config;
use super::take::{take, TextKind};
use super::{Component, NoticesError, Origin};

const LIST: &str = "
licenses:
  - {id: Apache-2.0, text: shared-with-notice}
  - {id: MIT, text: own}
  - {id: ISC, text: own}
  - {id: WTFPL, text: shared}
";

fn config(extra: &str) -> Config {
    Config::parse(&format!("{LIST}{extra}")).expect("the test config parses")
}

/// A crate of `license` whose source folder holds `files`.
fn component(license: Option<&str>, files: &[(&str, &str)]) -> (Component, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    let component = Component {
        name: "widget".to_owned(),
        version: "1.2.3".to_owned(),
        origin: Origin::Crate,
        license: license.map(str::to_owned),
        source_dir: Some(dir.path().to_owned()),
        url: None,
        modified_copy: false,
        replaces: None,
        text_dir: None,
    };
    (component, dir)
}

fn titles(taken: &super::Taken) -> Vec<&str> {
    taken.texts.iter().map(|text| text.title.as_str()).collect()
}

#[skuld::test]
fn the_first_listed_licence_an_expression_allows_is_taken() {
    let config = config("");
    for expression in [
        "MIT OR Apache-2.0",
        "Apache-2.0 OR MIT",
        "MIT/Apache-2.0",
        "(MIT OR ISC) OR Apache-2.0",
    ] {
        let (component, _dir) = component(Some(expression), &[("LICENSE-MIT", "MIT text")]);
        let taken = take(&component, &config).unwrap();
        assert_eq!(taken.license, "Apache-2.0", "for `{expression}`");
        assert_eq!(titles(&taken), ["Apache-2.0"], "for `{expression}`");
    }
}

#[skuld::test]
fn a_licence_that_is_not_on_the_list_fails_naming_the_component() {
    let (component, _dir) = component(Some("GPL-2.0-only OR BSD-3-Clause"), &[]);
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::LicenseNotOnList { .. }), "{err:?}");
    let message = err.to_string();
    assert!(message.contains("widget 1.2.3"), "{message}");
    assert!(
        message.contains("licenses:"),
        "the message names the entry to add: {message}"
    );
}

#[skuld::test]
fn a_component_without_licence_metadata_fails() {
    let (component, _dir) = component(None, &[("LICENSE", "MIT text")]);
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::NoLicense { .. }), "{err:?}");
    assert!(err.to_string().contains("widget 1.2.3"));
}

#[skuld::test]
fn a_licence_the_ecosystem_does_not_declare_comes_from_the_config() {
    let (component, _dir) = component(None, &[("LICENSE", "Copyright the Widget authors\nMIT text")]);
    let taken = take(
        &component,
        &config("overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n"),
    )
    .unwrap();
    assert_eq!(taken.license, "MIT");
}

#[skuld::test]
fn a_config_licence_does_not_replace_a_declared_one() {
    let (component, _dir) = component(Some("MIT"), &[("LICENSE", "MIT text")]);
    let err = take(
        &component,
        &config("overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: ISC}\n"),
    )
    .unwrap_err();
    assert!(matches!(err, NoticesError::LicenseConflict { .. }), "{err:?}");
}

#[skuld::test]
fn a_config_licence_replaces_a_declared_one_that_does_not_parse() {
    let (component, _dir) = component(Some("BSD"), &[("LICENSE", "MIT text")]);
    let taken = take(
        &component,
        &config("overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n"),
    )
    .unwrap();
    assert_eq!(taken.license, "MIT");
}

#[skuld::test]
fn a_config_licence_equal_to_the_declared_one_is_no_conflict() {
    let (component, _dir) = component(Some("MIT"), &[("LICENSE", "MIT text")]);
    let taken = take(
        &component,
        &config("overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n"),
    )
    .unwrap();
    assert_eq!(taken.license, "MIT");
}

#[skuld::test]
fn an_override_licence_is_for_the_version_it_names_only() {
    let entry = "overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n";
    let (mut other_version, _dir) = component(None, &[("LICENSE", "MIT text")]);
    other_version.version = "1.2.4".to_owned();
    let err = take(&other_version, &config(entry)).unwrap_err();
    assert!(matches!(err, NoticesError::NoLicense { .. }), "{err:?}");
}

#[skuld::test]
fn the_licence_errors_that_ask_for_an_entry_print_the_version_it_is_for() {
    let (bad, _dir) = component(Some("BSD"), &[]);
    let err = take(&bad, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::BadExpression { .. }), "{err:?}");
    assert!(err.to_string().contains("version: \"1.2.3\", license:"), "{err}");

    let (none, _dir) = component(None, &[]);
    let err = take(&none, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::NoLicense { .. }), "{err:?}");
    assert!(err.to_string().contains("version: \"1.2.3\", license:"), "{err}");

    let (conflicting, _dir) = component(Some("MIT"), &[]);
    let entry = "overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: ISC}\n";
    let err = take(&conflicting, &config(entry)).unwrap_err();
    assert!(matches!(err, NoticesError::LicenseConflict { .. }), "{err:?}");
    assert!(err.to_string().contains("version 1.2.3"), "{err}");
}

#[skuld::test]
fn a_postfix_plus_on_a_gpl_licence_is_read_as_crates_io_accepts_it() {
    for expression in ["GPL-3.0+", "LGPL-2.1+"] {
        let (component, _dir) = component(Some(expression), &[]);
        let err = take(&component, &config("")).unwrap_err();
        assert!(
            matches!(err, NoticesError::LicenseNotOnList { .. }),
            "`{expression}`: {err:?}"
        );
    }
}

#[skuld::test]
fn a_text_that_names_a_holder_is_printed_whole_from_the_components_own_file() {
    // CRLF and a trailing space: printed exactly as the component distributes it.
    let body = "MIT License\r\n\r\nCopyright (c) 2020 Jane Widget \r\n\r\nPermission is hereby granted";
    let (component, _dir) = component(Some("MIT"), &[("LICENSE", body)]);
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(taken.license, "MIT");
    assert_eq!(taken.texts.len(), 1);
    assert_eq!(taken.texts[0].body, body);
    assert_eq!(taken.texts[0].kind, TextKind::Own);
    assert_eq!(taken.texts[0].title, "LICENSE");
}

#[skuld::test]
fn a_text_that_names_no_holder_comes_from_the_standard_text() {
    let (component, _dir) = component(Some("Apache-2.0"), &[]);
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(taken.texts.len(), 1);
    assert_eq!(taken.texts[0].kind, TextKind::Shared);
    assert_eq!(taken.texts[0].title, "Apache-2.0");
    assert_eq!(taken.texts[0].body, spdx::license_id("Apache-2.0").unwrap().text());
}

#[skuld::test]
fn a_notice_licence_without_its_text_fails_until_the_config_supplies_it() {
    let (component, _dir) = component(Some("MIT"), &[]);
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::NoText { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains("widget 1.2.3") && message.contains("MIT") && message.contains("texts:"),
        "{message}"
    );

    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - {license: MIT, text: \"Copyright (c) 2019 Jane Widget\\nPermission is hereby granted\", source: \"https://example.com/widget/LICENSE\"}
";
    let taken = take(&component, &config(supplied)).unwrap();
    assert_eq!(taken.texts.len(), 1);
    assert_eq!(
        taken.texts[0].body,
        "Copyright (c) 2019 Jane Widget\nPermission is hereby granted"
    );
    assert_eq!(
        taken.texts[0].source.as_deref(),
        Some("https://example.com/widget/LICENSE")
    );
}

#[skuld::test]
fn a_holder_line_is_printed_above_the_standard_text_without_its_template_line() {
    let (component, _dir) = component(Some("MIT"), &[]);
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - {license: MIT, notice: \"Copyright (c) 2019 Jane Widget\", source: \"https://example.com/widget\"}
";
    let taken = take(&component, &config(supplied)).unwrap();
    // The standard text leaves a line for a holder; the supplied line is the holder.
    let template = "Copyright (c) <year> <copyright holders>\n\n";
    let standard = spdx::license_id("MIT").unwrap().text();
    assert!(
        standard.contains(template),
        "the premise: the standard MIT text has the template line"
    );
    assert_eq!(
        taken.texts[0].body,
        format!(
            "Copyright (c) 2019 Jane Widget\n\n{}",
            standard.replacen(template, "", 1)
        )
    );
    assert!(!taken.texts[0].body.contains("<copyright holders>"));
}

#[skuld::test]
fn every_supplied_text_of_a_followed_licence_is_printed() {
    // Two holders of one licence: both lines are the notice.
    let (component, _dir) = component(Some("MIT"), &[]);
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - {license: MIT, notice: \"Copyright (c) 2019 Jane Widget\", source: \"https://example.com/jane\"}
      - {license: MIT, notice: \"Copyright (c) 2021 John Widget\", source: \"https://example.com/john\"}
";
    let taken = take(&component, &config(supplied)).unwrap();
    assert_eq!(titles(&taken), ["MIT", "MIT"]);
    assert!(taken.texts[0].body.starts_with(
        "Copyright (c) 2019 Jane Widget
"
    ));
    assert!(taken.texts[1].body.starts_with(
        "Copyright (c) 2021 John Widget
"
    ));
}

#[skuld::test]
fn supplied_text_wins_over_the_components_files() {
    let (component, _dir) = component(Some("MIT"), &[("LICENSE", "a file with no holder")]);
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - {license: MIT, text: \"Copyright (c) Jane\", source: \"https://example.com\"}
";
    let taken = take(&component, &config(supplied)).unwrap();
    assert_eq!(titles(&taken), ["MIT"]);
    assert_eq!(taken.texts[0].body, "Copyright (c) Jane");
}

#[skuld::test]
fn supplied_text_for_a_licence_that_is_not_followed_fails() {
    let (component, _dir) = component(Some("MIT OR Apache-2.0"), &[]);
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - {license: MIT, text: \"Copyright (c) Jane\", source: \"https://example.com\"}
";
    let err = take(&component, &config(supplied)).unwrap_err();
    assert!(matches!(err, NoticesError::UnusedText { .. }), "{err:?}");
}

#[skuld::test]
fn an_override_for_another_version_does_not_apply() {
    let (component, _dir) = component(Some("MIT"), &[]);
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    version: \"9.9.9\"
    texts:
      - {license: MIT, text: \"Copyright (c) Jane\", source: \"https://example.com\"}
";
    let err = take(&component, &config(supplied)).unwrap_err();
    assert!(matches!(err, NoticesError::NoText { .. }), "{err:?}");
}

#[skuld::test]
fn every_licence_file_of_a_component_is_printed() {
    // `ring` 0.17.14: `Apache-2.0 AND ISC`, files LICENSE, LICENSE-BoringSSL and LICENSE-other-bits. The metadata does
    // not say which file belongs to which licence, so a taken licence that asks for its own text prints them all.
    let (component, _dir) = component(
        Some("Apache-2.0 AND ISC"),
        &[
            ("LICENSE", "ring licence"),
            ("LICENSE-BoringSSL", "boringssl licence"),
            ("LICENSE-other-bits", "other bits"),
            ("README.md", "not a licence"),
        ],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(taken.license, "Apache-2.0 AND ISC");
    assert_eq!(
        titles(&taken),
        ["Apache-2.0", "LICENSE", "LICENSE-BoringSSL", "LICENSE-other-bits"]
    );
    let own: Vec<_> = taken
        .texts
        .iter()
        .filter(|text| text.kind == TextKind::Own)
        .map(|t| t.body.as_str())
        .collect();
    assert_eq!(own, ["ring licence", "boringssl licence", "other bits"]);
}

#[skuld::test]
fn a_component_whose_licences_all_have_standard_texts_prints_none_of_its_files() {
    let (component, _dir) = component(
        Some("MIT OR Apache-2.0"),
        &[
            ("LICENSE-MIT", "Copyright someone"),
            ("LICENSE-APACHE", "Apache with a filled appendix"),
        ],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["Apache-2.0"]);
}

#[skuld::test]
fn an_and_expression_takes_every_part() {
    let (component, _dir) = component(Some("Apache-2.0 AND ISC"), &[("LICENSE", "Copyright ISC holder")]);
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(taken.license, "Apache-2.0 AND ISC");
    assert_eq!(titles(&taken), ["Apache-2.0", "LICENSE"]);
}

#[skuld::test]
fn an_and_with_an_unlisted_part_fails_even_when_the_other_part_is_listed() {
    let (component, _dir) = component(Some("Apache-2.0 AND GPL-2.0-only"), &[]);
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::LicenseNotOnList { .. }), "{err:?}");
}

#[skuld::test]
fn a_notice_file_is_printed_with_apache() {
    let (component, _dir) = component(
        Some("Apache-2.0"),
        &[("NOTICE", "Widget\nCopyright 2020 Widget authors")],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["Apache-2.0", "NOTICE"]);
    assert_eq!(taken.texts[1].body, "Widget\nCopyright 2020 Widget authors");
    assert_eq!(taken.texts[1].kind, TextKind::Own);
}

#[skuld::test]
fn a_notice_file_is_not_printed_for_a_licence_that_asks_for_none() {
    let (component, _dir) = component(Some("MIT"), &[("LICENSE", "Copyright Jane"), ("NOTICE", "unrelated")]);
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["LICENSE"]);
}

#[skuld::test]
fn an_expression_that_does_not_parse_fails_naming_the_component() {
    let (component, _dir) = component(Some("MIT OR"), &[]);
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::BadExpression { .. }), "{err:?}");
    assert!(err.to_string().contains("widget 1.2.3"));
}

#[skuld::test]
fn a_vague_licence_name_fails_naming_the_component_instead_of_being_read_as_one_licence() {
    // spdx maps these to Apache-2.0 and MIT, but the metadata does not say which version of the licence it means.
    for expression in ["Apache", "apache2", "MPL", "BSD", "MIT OR Apache"] {
        let (component, _dir) = component(Some(expression), &[("LICENSE", "text")]);
        let err = take(
            &component,
            &config(
                "  - {id: MPL-2.0, text: shared}
  - {id: BSD-2-Clause, text: shared}
",
            ),
        )
        .unwrap_err();
        assert!(
            matches!(err, NoticesError::BadExpression { .. }),
            "`{expression}`: {err:?}"
        );
        assert!(err.to_string().contains("widget 1.2.3"), "`{expression}`: {err}");
    }
}

#[skuld::test]
fn the_spellings_crates_io_metadata_uses_are_still_read() {
    let config = config("");
    // `/` for `OR`, and a deprecated identifier (parsed, then not on the list).
    let (slash, _dir) = component(Some("MIT/Apache-2.0"), &[]);
    assert_eq!(take(&slash, &config).unwrap().license, "Apache-2.0");
    let (deprecated, _dir) = component(Some("BSD-2-Clause-FreeBSD"), &[]);
    let err = take(&deprecated, &config).unwrap_err();
    assert!(matches!(err, NoticesError::LicenseNotOnList { .. }), "{err:?}");
}

#[skuld::test]
fn a_licence_file_that_is_not_text_fails() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("LICENSE"), [0xff, 0xfe, 0x00, 0x41]).unwrap();
    let (mut component, _keep) = component(Some("MIT"), &[]);
    component.source_dir = Some(dir.path().to_owned());
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::NotUtf8 { .. }), "{err:?}");
}

#[skuld::test]
fn a_source_folder_that_is_missing_fails_naming_it() {
    let (mut component, _dir) = component(Some("MIT"), &[]);
    component.source_dir = Some(Path::new("no-such-folder").to_owned());
    let err = take(&component, &config("")).unwrap_err();
    assert!(matches!(err, NoticesError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("no-such-folder"), "{err}");
}

#[skuld::test]
fn an_upstream_without_a_licence_text_gets_the_standard_text_and_its_own_words() {
    let words = "authors = [\"Jane Widget <jane@example.com>\"]\nlicense = \"MIT\"\n\n## License\n\nMIT\n";
    let supplied = "overrides:
  - name: widget
    ecosystem: crate
    texts:
      - license: MIT
        upstream_words: |
          authors = [\"Jane Widget <jane@example.com>\"]
          license = \"MIT\"

          ## License

          MIT
        source: \"https://example.com/widget/README.md\"
";
    let (component, _dir) = component(Some("MIT"), &[]);
    let taken = take(&component, &config(supplied)).unwrap();
    assert_eq!(taken.license, "MIT");
    assert_eq!(taken.texts.len(), 2, "{:?}", titles(&taken));

    // Upstream's words come first, verbatim, marked as upstream's and with where they were read.
    let upstream = &taken.texts[0];
    assert_eq!(upstream.body, words);
    assert_eq!(upstream.kind, TextKind::Own);
    assert!(upstream.title.contains("upstream's own words"), "{}", upstream.title);
    assert_eq!(upstream.source.as_deref(), Some("https://example.com/widget/README.md"));

    // The standard text follows without the template's copyright line, and says upstream names no holder.
    let standard = &taken.texts[1];
    let mit = spdx::license_id("MIT").unwrap().text();
    assert_eq!(
        standard.body,
        mit.replace("Copyright (c) <year> <copyright holders>\n\n", "")
    );
    assert!(
        standard.title.contains("MIT") && standard.title.contains("names no holder"),
        "{}",
        standard.title
    );
    assert_eq!(standard.kind, TextKind::Own);
}

#[skuld::test]
fn a_source_file_named_like_a_licence_is_not_a_licence_file() {
    let (component, _dir) = component(
        Some("MIT"),
        &[
            ("LICENSE-MIT", "the licence"),
            ("license.go", "package license"),
            ("licensing.go", "package licensing"),
            ("copying_test.go", "package copying"),
            ("license_test.go", "package license"),
            ("licenses.go", "package licenses"),
        ],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["LICENSE-MIT"]);
}

#[skuld::test]
fn licence_files_are_recognised_by_their_whole_name() {
    for name in [
        "LICENSE",
        "LICENSE.md",
        "license.txt",
        "LICENCE",
        "COPYING",
        "UNLICENSE",
        "LICENSE-APACHE",
        "LICENSE_MIT",
        "LICENSE-other-bits",
        "LICENSE-2.0.txt",
        "LICENSE.MIT",
        "LICENSE.BSD-3-Clause",
        "LICENSE.httprouter",
    ] {
        let (component, _dir) = component(Some("MIT"), &[(name, "text")]);
        assert_eq!(titles(&take(&component, &config("")).unwrap()), [name], "{name}");
    }
}

#[skuld::test]
fn a_source_file_named_like_a_notice_is_not_a_notice_file() {
    let (component, _dir) = component(
        Some("Apache-2.0"),
        &[
            ("NOTICE", "the notice"),
            ("notice.go", "package notice"),
            ("noticeboard.go", "package board"),
        ],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["Apache-2.0", "NOTICE"]);
}

#[skuld::test]
fn an_entry_for_a_crate_does_not_apply_to_an_npm_package_of_the_same_name() {
    let (mut package, _dir) = component(None, &[("LICENSE", "MIT text")]);
    package.origin = Origin::Npm;
    let for_the_crate = "overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n";
    let err = take(&package, &config(for_the_crate)).unwrap_err();
    assert!(matches!(err, NoticesError::NoLicense { .. }), "{err:?}");

    let for_the_package = "overrides:\n  - {name: widget, ecosystem: npm, version: 1.2.3, license: MIT}\n";
    assert_eq!(take(&package, &config(for_the_package)).unwrap().license, "MIT");
}

#[skuld::test]
fn a_go_package_of_a_module_and_a_go_module_are_both_the_go_ecosystem() {
    for origin in [Origin::GoModule, Origin::GoPackage] {
        let (mut go, _dir) = component(None, &[("LICENSE", "MIT text")]);
        go.origin = origin;
        let entry = "overrides:\n  - {name: widget, ecosystem: go, version: 1.2.3, license: MIT}\n";
        assert_eq!(take(&go, &config(entry)).unwrap().license, "MIT", "{origin:?}");
    }
}

#[skuld::test]
fn a_declared_component_is_not_matched_by_an_override() {
    let (mut declared, _dir) = component(Some("MIT"), &[]);
    declared.origin = Origin::Declared;
    let entry = "overrides:\n  - {name: widget, ecosystem: crate, version: 1.2.3, license: MIT}\n";
    // A declared component states its licence in its own entry; an override cannot reach it.
    let err = take(&declared, &config(entry)).unwrap_err();
    assert!(matches!(err, NoticesError::NoText { .. }), "{err:?}");
}

/// The text between the first pair of backticks after `after` in `message`.
fn quoted_after<'a>(message: &'a str, after: &str) -> &'a str {
    let start = message
        .find(after)
        .unwrap_or_else(|| panic!("`{after}` not in: {message}"))
        + after.len();
    let rest = &message[start..];
    let rest = rest
        .strip_prefix('`')
        .unwrap_or_else(|| panic!("no quote after `{after}`: {message}"));
    &rest[..rest.find('`').expect("the quote is closed")]
}

/// The config a hint tells the reader to write, written as the hint says. `component` is the one that failed, `base`
/// the `declared:` entry that already exists when the component is a declared one.
fn config_following(message: &str, component: &Component) -> Config {
    let hint = quoted_after(message, "Add ");
    let hint = hint
        .replace("...", "\"Copyright (c) 2019 Jane Widget\"")
        .replace("<upstream URL>", "\"https://example.com\"");
    match component.origin {
        // The hint is a field to add to the entry the component already has.
        Origin::Declared => config(&format!("declared:\n  - {{name: widget, license: MIT, {hint}}}\n")),
        // The hint is the whole entry.
        _ => config(&hint),
    }
}

#[skuld::test]
fn the_hint_for_a_missing_text_names_the_entry_that_settles_it_for_every_origin() {
    for origin in [
        Origin::Crate,
        Origin::GoModule,
        Origin::GoPackage,
        Origin::Npm,
        Origin::Declared,
    ] {
        let (mut component, _dir) = component(Some("MIT"), &[]);
        component.origin = origin;
        let declared = "declared:\n  - {name: widget, license: MIT}\n";
        let err = take(&component, &config(declared)).unwrap_err();
        assert!(matches!(err, NoticesError::NoText { .. }), "{origin:?}: {err:?}");
        let message = err.to_string();

        match origin {
            Origin::Declared => assert!(
                message.contains("`declared:` entry for `widget`") && !message.contains("overrides:"),
                "{origin:?}: {message}"
            ),
            _ => assert!(
                message.contains("overrides:") && !message.contains("declared:"),
                "{origin:?}: {message}"
            ),
        }
        let followed = config_following(&message, &component);
        let taken = take(&component, &followed)
            .unwrap_or_else(|e| panic!("{origin:?}: the hint did not settle it: {e}\n{message}"));
        assert_eq!(taken.texts[0].body, "Copyright (c) 2019 Jane Widget", "{origin:?}");
    }
}

#[skuld::test]
fn the_hint_for_a_missing_licence_names_the_entry_that_settles_it_for_every_origin() {
    // A declared component always states its licence, so only the ecosystems that declare none reach this.
    for origin in [Origin::Crate, Origin::GoModule, Origin::GoPackage, Origin::Npm] {
        let (mut component, _dir) = component(None, &[("LICENSE", "MIT text")]);
        component.origin = origin;
        let err = take(&component, &config("")).unwrap_err();
        assert!(matches!(err, NoticesError::NoLicense { .. }), "{origin:?}: {err:?}");
        let message = err.to_string();

        let hint = quoted_after(&message, "Add ").replace("<SPDX expression>", "MIT");
        assert!(hint.contains("overrides:"), "{origin:?}: {message}");
        let taken = take(&component, &config(&hint))
            .unwrap_or_else(|e| panic!("{origin:?}: the hint did not settle it: {e}\n{message}"));
        assert_eq!(taken.license, "MIT", "{origin:?}");
    }
}

#[skuld::test]
fn a_plural_or_numbered_licence_name_is_a_licence_file() {
    for name in ["LICENSES", "COPYING3", "LICENSE2", "LICENSES.md", "COPYING.LESSER"] {
        let (component, _dir) = component(Some("MIT"), &[(name, "text"), ("LICENSE-MIT", "the licence")]);
        let mut expected = vec![name, "LICENSE-MIT"];
        expected.sort();
        assert_eq!(titles(&take(&component, &config("")).unwrap()), expected, "{name}");
    }
}

#[skuld::test]
fn a_plural_notice_name_is_a_notice_file() {
    for name in ["NOTICES", "NOTICES.md", "NOTICE.txt"] {
        let (component, _dir) = component(Some("Apache-2.0"), &[(name, "the notice")]);
        assert_eq!(
            titles(&take(&component, &config("")).unwrap()),
            ["Apache-2.0", name],
            "{name}"
        );
    }
}

#[skuld::test]
fn a_file_of_the_package_whose_extension_is_source_or_data_is_neither_a_licence_nor_a_notice_file() {
    let (component, _dir) = component(
        Some("Apache-2.0"),
        &[
            ("license.go", "package license"),
            ("licensing.go", "package licensing"),
            ("copying_test.go", "package copying"),
            ("licenses.json", "{}"),
            ("notices.py", "x = 1"),
        ],
    );
    let taken = take(&component, &config("")).unwrap();
    assert_eq!(titles(&taken), ["Apache-2.0"]);
}

/// A declared component whose text is the file `text_from` names, in a folder of its own that holds a copyright file
/// naming `Unicode-3.0` for one in-tree file.
fn declared_with_text_from(license: &str) -> (Component, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("licenses")).unwrap();
    std::fs::write(
        dir.path().join("COPYRIGHT-library.html"),
        "<html><body><div><p><b>License:</b> Unicode-3.0</p></div></body></html>",
    )
    .unwrap();
    std::fs::write(dir.path().join("licenses/Unicode-3.0.txt"), "UNICODE TEXT\n").unwrap();
    let component = Component {
        name: "std".to_owned(),
        version: "1.98.0".to_owned(),
        origin: Origin::Declared,
        license: Some(license.to_owned()),
        source_dir: None,
        url: None,
        modified_copy: false,
        replaces: None,
        text_dir: Some(dir.path().to_owned()),
    };
    (component, dir)
}

const TEXT_FROM: &str = "declared:\n  - {name: std, license: MIT, text_from: rust-toolchain-copyright}\n";

#[skuld::test]
fn a_component_whose_text_is_read_from_a_file_is_taken_under_the_licence_the_list_prefers() {
    let (component, _dir) = declared_with_text_from("MIT OR Apache-2.0");
    let taken = take(&component, &config(TEXT_FROM)).unwrap();
    assert_eq!(taken.license, "Apache-2.0");
    assert!(taken.texts.iter().any(|text| text.body == "UNICODE TEXT\n"));
}

const GO_TEXT_FROM: &str = "declared:\n  - {name: go, license: MIT, text_from: go-toolchain}\n";

fn declared_in_goroot(goroot: &Path) -> Component {
    Component {
        name: "go".to_owned(),
        version: "go1.27.0".to_owned(),
        origin: Origin::Declared,
        license: Some("MIT".to_owned()),
        source_dir: None,
        url: None,
        modified_copy: false,
        replaces: None,
        text_dir: Some(goroot.to_owned()),
    }
}

#[skuld::test]
fn a_component_whose_text_is_the_go_toolchains_licence_prints_that_file_whole() {
    let goroot = tempfile::tempdir().unwrap();
    // Not the Go licence: any bytes, as long as they come back untouched, with the file's own name.
    let licence = "Copyright 2009 The Go Authors.\r\n\r\n  indented  \n";
    std::fs::write(goroot.path().join("LICENSE"), licence).unwrap();
    std::fs::write(goroot.path().join("PATENTS"), "not a licence file").unwrap();

    let taken = take(&declared_in_goroot(goroot.path()), &config(GO_TEXT_FROM)).unwrap();

    assert_eq!(taken.license, "MIT");
    assert_eq!(titles(&taken), ["LICENSE"]);
    assert_eq!(taken.texts[0].body, licence);
    assert_eq!(taken.texts[0].kind, TextKind::Own);
}

#[skuld::test]
fn a_go_toolchain_without_a_licence_file_fails_naming_it() {
    let goroot = tempfile::tempdir().unwrap();
    let err = take(&declared_in_goroot(goroot.path()), &config(GO_TEXT_FROM)).unwrap_err();
    assert!(matches!(err, NoticesError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("LICENSE"), "{err}");
}

#[skuld::test]
fn a_component_whose_text_is_read_from_a_file_still_needs_a_licence_on_the_list() {
    let (component, _dir) = declared_with_text_from("GPL-2.0-only");
    let err = take(&component, &config(TEXT_FROM)).unwrap_err();
    assert!(matches!(err, NoticesError::LicenseNotOnList { .. }), "{err:?}");
}

#[skuld::test]
fn a_holder_line_is_printed_above_the_standard_text_with_no_template_holder_line_left() {
    const HOLDER: &str = "Copyright (c) 2019 Jane Widget";
    for id in super::config::HOLDER_LINE_LICENCES.iter().copied() {
        let texts = format!("overrides:\n  - name: widget\n    ecosystem: crate\n    texts: [{{license: {id}, notice: \"{HOLDER}\", source: u}}]\n");
        let config = config_with(id, &texts);
        let (component, _dir) = component(Some(id), &[]);

        let taken = take(&component, &config).unwrap();

        let standard = spdx::license_id(id).unwrap().text();
        let printed = taken.texts[0].body.strip_prefix(&format!("{HOLDER}\n\n")).unwrap();
        for line in printed.lines() {
            let line = line.trim_start().to_ascii_lowercase();
            assert!(
                !line.starts_with("copyright") && !line.contains('<'),
                "{id}: a template holder line is left: {line}"
            );
        }
        // Nothing but the template's holder line (and a blank line after it) is missing.
        let dropped: Vec<&str> = standard
            .lines()
            .filter(|line| !printed.lines().any(|p| p == *line))
            .collect();
        assert!(
            dropped
                .iter()
                .all(|line| line.trim().is_empty() || line.to_ascii_lowercase().starts_with("copyright")),
            "{id}: more than the template's holder line was dropped: {dropped:?}"
        );
    }
}

fn config_with(id: &str, extra: &str) -> Config {
    Config::parse(&format!("licenses:\n  - {{id: {id}, text: own}}\n{extra}")).unwrap()
}
