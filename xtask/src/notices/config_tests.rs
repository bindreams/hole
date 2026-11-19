use super::config::{Config, TextPolicy, CONFIG_PATH, HOLDER_LINE_LICENCES};
use super::NoticesError;
use crate::download::sha256_hex;
use crate::manifest::{Arch, Os, Platform};

const WINDOWS: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MACOS: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};

#[skuld::test]
fn the_list_keeps_its_order_and_each_licences_text_policy() {
    let config = Config::parse("licenses:\n  - {id: Apache-2.0, text: shared-with-notice}\n  - {id: MIT, text: own}\n  - {id: Zlib, text: own}\n")
        .unwrap();
    assert_eq!(config.rank("Apache-2.0"), Some(0));
    assert_eq!(config.rank("MIT"), Some(1));
    assert_eq!(config.rank("Zlib"), Some(2));
    assert_eq!(config.rank("ISC"), None);
    assert_eq!(config.text_policy("Apache-2.0"), Some(TextPolicy::SharedWithNotice));
    assert_eq!(config.text_policy("MIT"), Some(TextPolicy::Own));
}

/// The one requirement of a single-requirement expression.
fn requirement(expression: &str) -> spdx::LicenseReq {
    let parsed = spdx::Expression::parse(expression).unwrap();
    let first = parsed.requirements().next().unwrap().req.clone();
    first
}

#[skuld::test]
fn a_listed_licence_with_an_exception_covers_exactly_that_requirement() {
    let both = Config::parse(
        "licenses:
  - {id: Apache-2.0 WITH LLVM-exception, text: own}
  - {id: Apache-2.0, text: shared}
",
    )
    .unwrap();
    assert_eq!(both.rank_of(&requirement("Apache-2.0 WITH LLVM-exception")), Some(0));
    assert_eq!(both.rank_of(&requirement("Apache-2.0")), Some(1));
    assert_eq!(both.rank_of(&requirement("Apache-2.0 WITH Swift-exception")), None);
    assert_eq!(both.rank_of(&requirement("MIT WITH LLVM-exception")), None);

    let plain = Config::parse(
        "licenses:
  - {id: Apache-2.0, text: shared}
",
    )
    .unwrap();
    assert_eq!(plain.rank_of(&requirement("Apache-2.0 WITH LLVM-exception")), None);

    let excepted = Config::parse(
        "licenses:
  - {id: Apache-2.0 WITH LLVM-exception, text: own}
",
    )
    .unwrap();
    assert_eq!(excepted.rank_of(&requirement("Apache-2.0")), None);
}

#[skuld::test]
fn a_licence_id_spdx_does_not_know_is_rejected() {
    let err = Config::parse("licenses:\n  - {id: MITT, text: own}\n").unwrap_err();
    assert!(matches!(err, NoticesError::Config { .. }), "{err:?}");
    assert!(err.to_string().contains("MITT"), "{err}");
}

#[skuld::test]
fn a_licence_ref_is_accepted_for_a_licence_spdx_does_not_list() {
    Config::parse("licenses:\n  - {id: LicenseRef-Vendor-Binaries, text: own}\n").unwrap();
}

#[skuld::test]
fn a_licence_listed_twice_is_rejected() {
    let err = Config::parse("licenses:\n  - {id: MIT, text: own}\n  - {id: MIT, text: own}\n").unwrap_err();
    assert!(err.to_string().contains("twice"), "{err}");
}

#[skuld::test]
fn an_unknown_key_is_rejected() {
    let err = Config::parse("licenses: []\nlicences: []\n").unwrap_err();
    assert!(matches!(err, NoticesError::Config { .. }), "{err:?}");
}

#[skuld::test]
fn a_supplied_text_gives_exactly_one_of_text_and_notice() {
    let both = "licenses: []\noverrides:\n  - name: a\n    ecosystem: crate\n    texts: [{license: MIT, text: t, notice: n, source: u}]\n";
    let neither =
        "licenses: []\noverrides:\n  - name: a\n    ecosystem: crate\n    texts: [{license: MIT, source: u}]\n";
    assert!(Config::parse(both).is_err());
    assert!(Config::parse(neither).is_err());
}

#[skuld::test]
fn load_reads_the_file_under_the_repo_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".config")).unwrap();
    std::fs::write(root.path().join(CONFIG_PATH), "licenses:\n  - {id: MIT, text: own}\n").unwrap();
    assert_eq!(Config::load(root.path()).unwrap().rank("MIT"), Some(0));
}

#[skuld::test]
fn load_names_the_file_when_it_is_missing() {
    let root = tempfile::tempdir().unwrap();
    let err = Config::load(root.path()).unwrap_err();
    assert!(matches!(err, NoticesError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("notices.yaml"), "{err}");
}

#[skuld::test]
fn a_supplied_text_gives_exactly_one_of_text_notice_and_upstream_words() {
    let with = |keys: &str| {
        format!("licenses: []\noverrides:\n  - name: a\n    ecosystem: crate\n    texts: [{{license: MIT, {keys}, source: u}}]\n")
    };
    assert!(Config::parse(&with("upstream_words: w")).is_ok());
    assert!(Config::parse(&with("upstream_words: w, text: t")).is_err());
    assert!(Config::parse(&with("upstream_words: w, notice: n")).is_err());
}

/// SHA-256 of the SDK `LICENSE.txt` the config entry carries; a `webview2-com-sys` bump must re-read the entry.
const WEBVIEW2_SDK_LICENSE_SHA256: &str = "0af8f1b807512aae39c2ac1aa4d0cae65cabecb6fd554b8439a5162a0d6eca55";

/// The `webview2-com-sys` version whose bundled library the SDK entry was read for.
const WEBVIEW2_COM_SYS_READ_FOR: &str = "0.39.1";

#[skuld::test]
fn the_webview2_sdk_is_declared_for_windows_with_the_licence_of_its_package() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config = Config::load(repo).unwrap();

    let lock: toml::Table = std::fs::read_to_string(repo.join("Cargo.lock"))
        .unwrap()
        .parse()
        .unwrap();
    let locked: Vec<&str> = lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| package["name"].as_str() == Some("webview2-com-sys"))
        .map(|package| package["version"].as_str().unwrap())
        .collect();
    assert_eq!(
        locked,
        [WEBVIEW2_COM_SYS_READ_FOR],
        "`webview2-com-sys` changed from {WEBVIEW2_COM_SYS_READ_FOR}: the entry `Microsoft Edge WebView2 SDK` in \
         .config/notices.yaml was read for the SDK that version bundles (the NuGet package `Microsoft.Web.WebView2` its \
         repository takes `WebView2LoaderStatic.lib` from). Re-read which SDK the new version bundles, then update the \
         entry's `version`, `url` and texts, the SHA-256 and the source URL pinned in this test, and \
         WEBVIEW2_COM_SYS_READ_FOR"
    );

    let windows = config.for_platform(&WINDOWS);
    let sdk = windows
        .declared
        .iter()
        .find(|entry| entry.name == "Microsoft Edge WebView2 SDK")
        .expect("hole.exe links the SDK's static loader, so the Windows artifact declares the SDK");
    assert_eq!(sdk.license, "BSD-3-Clause");
    let text = sdk.texts[0]
        .text
        .as_deref()
        .expect("the text is the package's LICENSE.txt, whole");
    assert_eq!(sha256_hex(text.as_bytes()), WEBVIEW2_SDK_LICENSE_SHA256);
    assert!(sdk.texts[0].source.contains("microsoft.web.webview2.1.0.3800.47.nupkg"));

    assert!(
        config
            .for_platform(&MACOS)
            .declared
            .iter()
            .all(|entry| entry.name != "Microsoft Edge WebView2 SDK"),
        "no other platform links it"
    );
}

#[skuld::test]
fn an_override_must_name_its_ecosystem() {
    let without = "licenses: []\noverrides:\n  - {name: a, license: MIT}\n";
    let err = Config::parse(without).unwrap_err();
    assert!(err.to_string().contains("ecosystem"), "{err}");
    let unknown = "licenses: []\noverrides:\n  - {name: a, ecosystem: python, license: MIT}\n";
    assert!(Config::parse(unknown).is_err());
    for ecosystem in ["crate", "go", "npm"] {
        let text = format!("licenses:\n  - {{id: MIT, text: own}}\n  - {{id: ISC, text: own}}\noverrides:\n  - {{name: a, ecosystem: {ecosystem}, version: v1, license: MIT}}\n");
        assert!(Config::parse(&text).is_ok(), "{ecosystem}");
    }
}

#[skuld::test]
fn a_text_shared_between_entries_by_a_yaml_anchor_is_the_same_text_in_each() {
    let text = "licenses: []\noverrides:\n\
        \x20 - {name: a, ecosystem: crate, texts: [{license: MIT, source: u, text: &shared \"the text\"}]}\n\
        \x20 - {name: b, ecosystem: crate, texts: [{license: MIT, source: u, text: *shared}]}\n";
    let config = Config::parse(text).unwrap();
    let texts: Vec<_> = config
        .overrides
        .iter()
        .map(|entry| entry.texts[0].text.as_deref())
        .collect();
    assert_eq!(texts, [Some("the text"), Some("the text")]);
}

#[skuld::test]
fn texts_or_a_folder_beside_text_from_are_a_config_error() {
    let with = |extra: &str| {
        format!(
            "licenses:\n  - {{id: MIT, text: own}}\n  - {{id: ISC, text: own}}\ndeclared:\n  - {{name: std, license: MIT, text_from: rust-toolchain-copyright{extra}}}\n"
        )
    };
    assert!(Config::parse(&with("")).is_ok());

    let texts = Config::parse(&with(", texts: [{license: MIT, text: t, source: u}]")).unwrap_err();
    assert!(
        texts.to_string().contains("std") && texts.to_string().contains("texts"),
        "{texts}"
    );
    let dir = Config::parse(&with(", dir: somewhere")).unwrap_err();
    assert!(
        dir.to_string().contains("std") && dir.to_string().contains("dir"),
        "{dir}"
    );
}

#[skuld::test]
fn a_holder_line_or_upstream_words_are_accepted_only_for_a_licence_whose_template_line_is_known() {
    let with = |license: &str, field: &str| {
        format!(
            "licenses: []\noverrides:\n  - name: a\n    ecosystem: crate\n    texts: [{{license: {license}, {field}: x, source: u}}]\n"
        )
    };
    for license in ["OFL-1.1", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC"] {
        for field in ["notice", "upstream_words"] {
            assert!(Config::parse(&with(license, field)).is_ok(), "{license} {field}");
        }
    }
    // 0BSD's template line is `Copyright (C) YEAR by AUTHOR EMAIL`, which carries no `<`.
    for field in ["notice", "upstream_words"] {
        let err = Config::parse(&with("0BSD", field)).unwrap_err().to_string();
        assert!(err.contains("0BSD") && err.contains("`text:`"), "{field}: {err}");
    }
    // The whole text names no template line to strip.
    assert!(Config::parse(&with("0BSD", "text")).is_ok());
}

#[skuld::test]
fn every_licence_a_holder_line_may_accompany_has_a_standard_text() {
    for id in HOLDER_LINE_LICENCES {
        assert!(super::take::standard_text_of(id).is_some(), "{id}");
    }
}

/// A list that holds the licences the entries below state.
const LISTED: &str = "licenses:
  - {id: MIT, text: own}
  - {id: ISC, text: own}
";

fn overrides(entries: &str) -> String {
    format!(
        "{LISTED}overrides:
{entries}"
    )
}

#[skuld::test]
fn a_licence_the_config_states_is_accepted_when_it_parses_and_is_listed() {
    // Only an override that sets a licence names a version; one that supplies a text may name none.
    Config::parse(&overrides(
        "  - {name: a, ecosystem: crate, version: \"1.0.0\", license: MIT OR ISC}
  - {name: a, ecosystem: crate, texts: [{license: MIT, text: t, source: u}]}
",
    ))
    .unwrap();
    Config::parse(&format!(
        "{LISTED}declared:\n  - {{name: a, license: MIT AND (ISC OR MIT)}}\n"
    ))
    .unwrap();
}

#[skuld::test]
fn two_overrides_that_set_a_licence_for_one_component_are_a_config_error_naming_both() {
    let text = overrides(
        "  - {name: widget, ecosystem: go, version: v1.2.3, license: MIT}
  - {name: widget, ecosystem: go, version: v1.2.3, license: ISC}
",
    );
    let err = Config::parse(&text).unwrap_err();
    assert!(matches!(err, NoticesError::Config { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains("widget") && message.contains("#1") && message.contains("#2") && message.contains("license"),
        "{message}"
    );
}

#[skuld::test]
fn overrides_that_cannot_apply_to_one_component_may_each_set_a_licence() {
    for entries in [
        // Other versions of one module.
        "  - {name: a, ecosystem: go, version: v1, license: MIT}
  - {name: a, ecosystem: go, version: v2, license: ISC}
",
        // Other platforms.
        "  - {name: a, ecosystem: go, platforms: [windows], version: v1, license: MIT}
  - {name: a, ecosystem: go, platforms: [darwin], version: v1, license: ISC}
",
        // Other ecosystems.
        "  - {name: a, ecosystem: go, version: v1, license: MIT}
  - {name: a, ecosystem: npm, version: v1, license: ISC}
",
        // One sets the licence, the other only supplies a text.
        "  - {name: a, ecosystem: go, version: v1, license: MIT}
  - {name: a, ecosystem: go, texts: [{license: MIT, text: t, source: u}]}
",
    ] {
        Config::parse(&overrides(entries)).unwrap_or_else(|e| panic!("{entries}: {e}"));
    }
}

#[skuld::test]
fn two_declared_entries_for_one_component_are_a_config_error_naming_both() {
    let entry = |extra: &str| {
        format!(
            "  - {{name: std, license: MIT{extra}}}
"
        )
    };
    let with = |a: &str, b: &str| {
        format!(
            "{LISTED}declared:
{}{}",
            entry(a),
            entry(b)
        )
    };

    let both = Config::parse(&with(
        ", text_from: rust-toolchain-copyright",
        ", text_from: rust-toolchain-copyright",
    ))
    .unwrap_err()
    .to_string();
    assert!(
        both.contains("std") && both.contains("#1") && both.contains("#2") && both.contains("text_from"),
        "{both}"
    );
    // Entries for two versions are two components.
    Config::parse(&with(", version: \"1\"", ", version: \"2\"")).unwrap();
}

const DARWIN_AMD64: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Amd64,
};

fn override_names(config: &Config) -> Vec<&str> {
    config.overrides.iter().map(|entry| entry.name.as_str()).collect()
}

#[skuld::test]
fn an_override_for_one_os_is_in_that_oss_artifacts_only() {
    let config = Config::parse(&overrides(
        "  - {name: only-windows, ecosystem: crate, platforms: [windows], version: v1, license: MIT}\n  - {name: everywhere, ecosystem: crate, version: v1, license: MIT}\n",
    ))
    .unwrap();
    assert_eq!(
        override_names(&config.for_platform(&WINDOWS)),
        ["only-windows", "everywhere"]
    );
    assert_eq!(override_names(&config.for_platform(&MACOS)), ["everywhere"]);
    assert_eq!(override_names(&config.for_platform(&DARWIN_AMD64)), ["everywhere"]);
}

#[skuld::test]
fn an_entry_for_an_os_and_arch_is_in_that_architectures_artifact_only() {
    let config = Config::parse(concat!(
        "licenses:\n  - {id: MIT, text: own}\n  - {id: ISC, text: own}\n",
        "declared:\n",
        "  - {name: arm-only, license: MIT, platforms: [darwin/arm64]}\n",
        "overrides:\n",
        "  - {name: arm-only-fix, ecosystem: crate, platforms: [darwin/arm64, windows], version: v1, license: MIT}\n",
    ))
    .unwrap();
    let declared = |platform: &Platform| config.for_platform(platform).declared.len();
    assert_eq!(
        (declared(&MACOS), declared(&DARWIN_AMD64), declared(&WINDOWS)),
        (1, 0, 0)
    );
    let overrides = |platform: &Platform| config.for_platform(platform).overrides.len();
    assert_eq!(
        (overrides(&MACOS), overrides(&DARWIN_AMD64), overrides(&WINDOWS)),
        (1, 0, 1)
    );
}

#[skuld::test]
fn a_platform_that_is_neither_an_os_nor_an_os_and_arch_is_a_config_error() {
    for platforms in ["plan9", "darwin/x86", "windows/amd64/extra", "/arm64"] {
        let text = overrides(&format!(
            "  - {{name: a, ecosystem: crate, platforms: [{platforms}], version: v1, license: MIT}}\n"
        ));
        let err = Config::parse(&text).unwrap_err();
        assert!(matches!(err, NoticesError::Config { .. }), "{platforms}: {err:?}");
    }
}

#[skuld::test]
fn overrides_for_an_os_and_for_one_of_its_architectures_may_not_both_set_a_licence() {
    let text = |a: &str, b: &str| {
        overrides(&format!(
            "  - {{name: a, ecosystem: go, platforms: [{a}], version: v1, license: MIT}}\n  - {{name: a, ecosystem: go, platforms: [{b}], version: v1, license: ISC}}\n"
        ))
    };
    assert!(Config::parse(&text("darwin", "darwin/arm64")).is_err());
    assert!(Config::parse(&text("darwin/arm64", "darwin/arm64")).is_err());
    Config::parse(&text("darwin/amd64", "darwin/arm64")).unwrap();
}
