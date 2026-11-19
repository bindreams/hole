//! An error that tells the reader how to settle it must tell them something that works. Each case below is an input that
//! fails with one variant of [`NoticesError`]; the remedy is read out of the error's own text, applied to the config,
//! and generation over the same input must then pass.

use std::path::Path;

use serde_yml::Value;

use super::config::Config;
use super::{check_overrides_used, declared, go, npm, take, Component, NoticesError, Origin};
use crate::manifest::{Arch, Os, Platform};

const WINDOWS: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MACOS: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};

const BASE: &str = "licenses:\n  - {id: MIT, text: own}\n  - {id: Apache-2.0, text: shared}\n";
const INTER: &str = "  - {name: Inter, version: \"4.001\", license: MIT, files: [ui/fonts/inter.woff2], \
                     texts: [{license: MIT, text: t, source: u}]}\n";
const WINTUN: &str = "  - {name: Wintun, version: \"0.14.1\", license: MIT, platforms: [windows], \
                      files: [.cache/wintun/wintun.dll], dir: .cache/wintun}\n";

/// What the text of an error says to do.
enum Remedy {
    /// Applies the entry the error prints (or describes) to a config.
    Config(Box<dyn Fn(Value) -> Value>),
    /// A command the reader runs.
    Command(String),
    /// Not about one component or one file, so no entry of the config settles it.
    NotAConfigEntry,
}

/// The remedy `error` states, read from its message. One arm per variant: a new variant does not compile until it has one.
fn remedy(error: &NoticesError) -> Remedy {
    let message = error.to_string();
    match error {
        NoticesError::Io { .. } => Remedy::NotAConfigEntry,
        NoticesError::NotUtf8 { .. } => Remedy::NotAConfigEntry,
        NoticesError::Config { .. } => Remedy::NotAConfigEntry,
        NoticesError::Tool { .. } => Remedy::NotAConfigEntry,
        NoticesError::UnusedEntry { .. } => Remedy::NotAConfigEntry,
        NoticesError::Provision { .. } => Remedy::Command(between(&message, "; `", "`").to_owned()),
        NoticesError::UnlistedFile { .. } => Remedy::Config(Box::new(move |mut config| {
            // The message starts with the path, which is what `files:` takes.
            let path = message.split_whitespace().next().expect("a message");
            let entry = format!(
                "{{name: Added, version: \"1\", license: MIT, files: [{path}], texts: [{{license: MIT, text: t, source: u}}]}}"
            );
            sequence(&mut config, "declared").push(serde_yml::from_str(&entry).unwrap());
            config
        })),
        NoticesError::BadExpression { .. } => Remedy::Config(Box::new(move |config| printed_entry(&message, config))),
        NoticesError::NoLicense { .. } => Remedy::Config(Box::new(move |config| printed_entry(&message, config))),
        NoticesError::NoText { .. } => Remedy::Config(Box::new(move |config| printed_entry(&message, config))),
        NoticesError::LicenseNotOnList { .. } => Remedy::Config(Box::new(move |mut config| {
            assert!(message.contains("`licenses:`"), "{message}");
            let expression = between(&message, "no licence in `", "`");
            let listed = format!("{{id: {expression}, text: own}}");
            sequence(&mut config, "licenses").push(serde_yml::from_str(&listed).unwrap());
            config
        })),
        NoticesError::UnusedText { .. } => Remedy::Config(Box::new(move |mut config| {
            assert!(message.contains("remove"), "{message}");
            without_key(&mut config, between(&message, "entry for `", "`"), "texts");
            config
        })),
        NoticesError::LicenseConflict { .. } => Remedy::Config(Box::new(move |mut config| {
            assert!(message.contains("remove `license:`"), "{message}");
            without_key(&mut config, between(&message, "entry for `", "`"), "license");
            config
        })),
    }
}

/// The text of `message` between the first `after` and the next `until`.
fn between<'a>(message: &'a str, after: &str, until: &str) -> &'a str {
    let start = message
        .find(after)
        .unwrap_or_else(|| panic!("the error does not say {after:?}: {message}"))
        + after.len();
    let rest = &message[start..];
    &rest[..rest.find(until).expect("an unterminated span")]
}

/// Apply the entry the message prints after `Add `: an `overrides:` item, or a field of the `declared:` entry it names.
fn printed_entry(message: &str, mut config: Value) -> Value {
    let printed = between(message, "Add `", "` to").to_owned();
    let printed = printed
        .replace("<SPDX expression>", "MIT")
        .replace("<upstream URL>", "https://example.com/upstream")
        .replace("...", "the text");
    let fragment: Value = serde_yml::from_str(&format!("{{{printed}}}"))
        .unwrap_or_else(|e| panic!("the printed entry `{printed}` is not YAML: {e}"));
    let (key, value) = fragment.as_mapping().unwrap().iter().next().unwrap();
    match key.as_str() {
        "overrides" => sequence(&mut config, "overrides").extend(value.as_sequence().unwrap().iter().cloned()),
        field => {
            let name = between(message, "entry for `", "`");
            entry_named(&mut config, "declared", name)
                .as_mapping_mut()
                .expect("an entry is a mapping")
                .insert(field.to_owned(), value.clone());
        }
    }
    config
}

fn sequence<'a>(config: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let map = config.as_mapping_mut().unwrap();
    if !map.contains_key(key) {
        map.insert(key.to_owned(), Value::Sequence(Vec::new()));
    }
    config[key].as_sequence_mut().unwrap()
}

fn entry_named<'a>(config: &'a mut Value, list: &str, name: &str) -> &'a mut Value {
    sequence(config, list)
        .iter_mut()
        .find(|entry| entry["name"] == Value::from(name))
        .unwrap_or_else(|| panic!("`{list}:` has no entry for `{name}`"))
}

/// Remove `key` from the entry for `name`, in `overrides:` or `declared:`.
fn without_key(config: &mut Value, name: &str, key: &str) {
    for list in ["overrides", "declared"] {
        if let Some(entry) = sequence(config, list)
            .iter_mut()
            .find(|entry| entry["name"] == Value::from(name))
        {
            entry.as_mapping_mut().unwrap().remove(key);
            return;
        }
    }
    panic!("no entry for `{name}`");
}

// Inputs --------------------------------------------------------------------------------------------------------------

/// One input that fails with the variant `fails_with`.
struct Case {
    name: &'static str,
    fails_with: &'static str,
    /// Edits the fixture repository, which holds `widget/LICENSE` and an empty `ui/fonts/`.
    setup: fn(&Path),
    config: String,
    /// Generation over the input: each component placed, and every override used.
    generate: Generate,
}

type Generate = Box<dyn Fn(&Path, &Config) -> Result<(), NoticesError>>;

fn write(root: &Path, path: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "x").unwrap();
}

fn nothing(_: &Path) {}

fn widget(root: &Path, origin: Origin, license: Option<&str>) -> Component {
    Component {
        name: "widget".to_owned(),
        version: "1.0.0".to_owned(),
        origin,
        license: license.map(str::to_owned),
        source_dir: Some(root.join("widget")),
        url: None,
        modified_copy: false,
        replaces: None,
        text_dir: None,
    }
}

fn place(config: &Config, components: &[Component]) -> Result<(), NoticesError> {
    for component in components {
        take(component, config)?;
    }
    check_overrides_used(config, components)
}

/// Generation over one component of `origin` that declares `license`, whose licence file is in the fixture.
fn one(origin: Origin, license: Option<&'static str>) -> Generate {
    Box::new(move |root, config| place(config, &[widget(root, origin, license)]))
}

fn declared_on(platform: &Platform, root: &Path, config: &Config) -> Result<(), NoticesError> {
    let config = config.for_platform(platform);
    let components = declared::collect(platform, root, &config)?;
    place(&config, &components)
}

fn declared_on_windows() -> Generate {
    Box::new(|root, config| declared_on(&WINDOWS, root, config))
}

fn declared_on_macos() -> Generate {
    Box::new(|root, config| declared_on(&MACOS, root, config))
}

fn with_wintun(root: &Path) {
    write(root, ".cache/wintun/wintun.dll");
    write(root, ".cache/wintun/LICENSE.txt");
}

fn cases() -> Vec<Case> {
    let case = |name, fails_with, setup, config: String, generate: Generate| Case {
        name,
        fails_with,
        setup,
        config,
        generate,
    };
    let overrides = |entries: &str| format!("{BASE}overrides:\n{entries}");
    let declared = |entries: &str| format!("{BASE}declared:\n{entries}");
    vec![
        case(
            "a crate whose declared licence does not parse",
            "BadExpression",
            nothing,
            BASE.to_owned(),
            one(Origin::Crate, Some("BSD")),
        ),
        case(
            "an npm package whose declared licence does not parse",
            "BadExpression",
            nothing,
            BASE.to_owned(),
            one(Origin::Npm, Some("BSD")),
        ),
        case(
            "a licence that is not on the list",
            "LicenseNotOnList",
            nothing,
            BASE.to_owned(),
            one(Origin::Crate, Some("GPL-2.0-only")),
        ),
        case(
            "a licence with an exception that is not on the list",
            "LicenseNotOnList",
            nothing,
            BASE.to_owned(),
            one(Origin::Crate, Some("Apache-2.0 WITH LLVM-exception")),
        ),
        case(
            "a crate that declares no licence",
            "NoLicense",
            nothing,
            BASE.to_owned(),
            one(Origin::Crate, None),
        ),
        case(
            "a Go module, which declares no licence",
            "NoLicense",
            nothing,
            BASE.to_owned(),
            one(Origin::GoModule, None),
        ),
        case(
            "a licence that asks for its text, and a component that ships none",
            "NoText",
            nothing,
            BASE.to_owned(),
            Box::new(|_, config| {
                let component = Component {
                    source_dir: None,
                    ..widget(Path::new(""), Origin::Crate, Some("MIT"))
                };
                place(config, &[component])
            }),
        ),
        case(
            "a declared entry that ships no licence text",
            "NoText",
            nothing,
            declared("  - {name: widget, version: \"1\", license: MIT}\n"),
            declared_on_macos(),
        ),
        case(
            "a text supplied for a licence that is not followed",
            "UnusedText",
            nothing,
            overrides("  - {name: widget, ecosystem: crate, texts: [{license: Apache-2.0, text: t, source: u}]}\n"),
            one(Origin::Crate, Some("MIT")),
        ),
        case(
            "an override licence beside a declared one that parses and differs",
            "LicenseConflict",
            nothing,
            overrides("  - {name: widget, ecosystem: crate, version: \"1.0.0\", license: Apache-2.0}\n"),
            one(Origin::Crate, Some("MIT")),
        ),
        case(
            "a font with no entry",
            "UnlistedFile",
            |root| write(root, "ui/fonts/inter.woff2"),
            format!("{BASE}declared: []\n"),
            declared_on_macos(),
        ),
        case(
            "an upstream library of the BINDIR with no entry",
            "UnlistedFile",
            |root| {
                write(root, "ui/fonts/inter.woff2");
                with_wintun(root);
            },
            declared(INTER),
            declared_on_windows(),
        ),
        case(
            "an upstream library of the BINDIR whose file name an entry lists from another folder",
            "UnlistedFile",
            |root| {
                write(root, "ui/fonts/inter.woff2");
                write(root, "third_party/wintun.dll");
                with_wintun(root);
            },
            declared(&format!(
                "{INTER}  - {{name: Decoy, version: \"1\", license: MIT, files: [third_party/wintun.dll], \
                 texts: [{{license: MIT, text: t, source: u}}]}}\n"
            )),
            declared_on_windows(),
        ),
        case(
            "a provisioned file that is missing",
            "Provision",
            |root| write(root, "ui/fonts/inter.woff2"),
            declared(&format!("{INTER}{WINTUN}")),
            declared_on_windows(),
        ),
        case(
            "a provisioned folder without a licence file",
            "Provision",
            |root| {
                write(root, "ui/fonts/inter.woff2");
                write(root, ".cache/wintun/wintun.dll");
            },
            declared(&format!("{INTER}{WINTUN}")),
            declared_on_windows(),
        ),
        case(
            "no node_modules",
            "Provision",
            nothing,
            BASE.to_owned(),
            Box::new(|root, _| npm::collect(root, &WINDOWS).map(drop)),
        ),
        case(
            "a Go module that is not downloaded",
            "Provision",
            nothing,
            BASE.to_owned(),
            Box::new(|root, _| {
                let listing =
                    r#"{"ImportPath": "example.com/m", "Module": {"Path": "example.com/m", "Version": "v1.0.0"}}"#;
                go::collect(listing, root, "https://example.com").map(drop)
            }),
        ),
    ]
}

/// The name of the variant of `error`.
fn variant(error: &NoticesError) -> String {
    format!("{error:?}").split([' ', '{', '(']).next().unwrap().to_owned()
}

fn fixture(case: &Case) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("ui/fonts")).unwrap();
    std::fs::create_dir_all(root.path().join("widget")).unwrap();
    std::fs::write(root.path().join("widget/LICENSE"), "MIT text").unwrap();
    (case.setup)(root.path());
    root
}

/// Fails unless `command` is a `cargo xtask` subcommand, or `cargo xtask build` of a target `build.yaml` declares.
fn assert_command_exists(command: &str) {
    use clap::CommandFactory;

    let words: Vec<&str> = command.split_whitespace().collect();
    assert_eq!(
        words[..2],
        ["cargo", "xtask"],
        "`{command}` is not a `cargo xtask` command"
    );
    let cli = crate::Cli::command();
    assert!(
        cli.find_subcommand(words[2]).is_some(),
        "`{command}`: `cargo xtask` has no subcommand `{}`",
        words[2]
    );
    if words[2] == "build" {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest =
            crate::manifest::Manifest::parse(&std::fs::read_to_string(repo.join("build.yaml")).unwrap()).unwrap();
        assert!(
            manifest.get(words[3]).is_some(),
            "`{command}`: build.yaml has no target `{}`",
            words[3]
        );
    }
}

#[skuld::test]
fn the_remedy_an_error_states_settles_it() {
    let mut failed = Vec::new();
    for case in cases() {
        let root = fixture(&case);
        let base: Config = Config::parse(&case.config).unwrap();
        let error = match (case.generate)(root.path(), &base) {
            Ok(()) => {
                failed.push(format!(
                    "{}: generation passes, expected {}",
                    case.name, case.fails_with
                ));
                continue;
            }
            Err(error) => error,
        };
        if variant(&error) != case.fails_with {
            failed.push(format!("{}: expected {}, got {error:?}", case.name, case.fails_with));
            continue;
        }
        let base_yaml: Value = serde_yml::from_str(&case.config).unwrap();
        match remedy(&error) {
            Remedy::NotAConfigEntry => {
                failed.push(format!("{}: {} has no remedy to apply", case.name, case.fails_with))
            }
            Remedy::Command(command) => {
                if let Err(panic) = std::panic::catch_unwind(|| assert_command_exists(&command)) {
                    failed.push(format!("{}: {}", case.name, panic_text(&panic)));
                }
            }
            Remedy::Config(apply) => {
                let settled = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| apply(base_yaml))) {
                    Ok(settled) => settled,
                    Err(panic) => {
                        failed.push(format!("{}: {}", case.name, panic_text(&panic)));
                        continue;
                    }
                };
                let text = serde_yml::to_string(&settled).unwrap();
                match Config::parse(&text) {
                    Err(e) => failed.push(format!("{}: the settled config is rejected: {e}\n{text}", case.name)),
                    Ok(config) => {
                        if let Err(e) = (case.generate)(root.path(), &config) {
                            failed.push(format!("{}: after the remedy: {e}\n{text}", case.name));
                        }
                    }
                }
            }
        }
    }
    assert!(failed.is_empty(), "{} cases:\n{}", failed.len(), failed.join("\n"));
}

fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    match (panic.downcast_ref::<String>(), panic.downcast_ref::<&str>()) {
        (Some(text), _) => text.clone(),
        (None, Some(text)) => (*text).to_owned(),
        (None, None) => "panicked".to_owned(),
    }
}

/// An input the config rejects when it is loaded, so that generation never meets it.
struct Rejected {
    name: &'static str,
    config: String,
    /// What the message must name: the entry and the field that is wrong.
    names: [&'static str; 2],
}

#[skuld::test]
fn a_config_licence_that_cannot_be_used_is_rejected_when_the_config_is_loaded() {
    let overrides = |entry: &str| format!("{BASE}overrides:\n  - {entry}\n");
    let declared = |entry: &str| format!("{BASE}declared:\n  - {entry}\n");
    let rows = [
        Rejected {
            name: "an override licence that does not parse",
            config: overrides("{name: widget, ecosystem: crate, version: \"1.0.0\", license: BSD}"),
            names: ["widget", "license"],
        },
        Rejected {
            name: "a declared licence that does not parse",
            config: declared("{name: widget, version: \"1\", license: BSD}"),
            names: ["widget", "license"],
        },
        Rejected {
            name: "an override licence with an id that is not on the list",
            config: overrides("{name: widget, ecosystem: crate, version: \"1.0.0\", license: MIT AND ISC}"),
            names: ["widget", "ISC"],
        },
        Rejected {
            name: "a declared licence with an id that is not on the list",
            config: declared("{name: widget, version: \"1\", license: MIT AND ISC}"),
            names: ["widget", "ISC"],
        },
        Rejected {
            name: "an override licence with an exception, which changes the terms",
            config: overrides(
                "{name: widget, ecosystem: crate, version: \"1.0.0\", license: Apache-2.0 WITH LLVM-exception}",
            ),
            names: ["widget", "LLVM-exception"],
        },
        Rejected {
            name: "a shared licence that has no standard text",
            config: format!("{BASE}  - {{id: LicenseRef-Foo, text: shared}}\n"),
            names: ["LicenseRef-Foo", "text: own"],
        },
        Rejected {
            name: "a licence printed with its notice files that has no standard text",
            config: format!("{BASE}  - {{id: LicenseRef-Foo, text: shared-with-notice}}\n"),
            names: ["LicenseRef-Foo", "text: own"],
        },
        Rejected {
            name: "a licence with an exception printed with its standard text",
            config: format!(
                "{BASE}  - {{id: Apache-2.0 WITH LLVM-exception, text: shared}}
"
            ),
            names: ["Apache-2.0 WITH LLVM-exception", "text: own"],
        },
        Rejected {
            name: "a licence with an exception printed with its standard text and notice files",
            config: format!(
                "{BASE}  - {{id: Apache-2.0 WITH LLVM-exception, text: shared-with-notice}}
"
            ),
            names: ["Apache-2.0 WITH LLVM-exception", "text: own"],
        },
        Rejected {
            name: "an exception id that SPDX does not know",
            config: format!(
                "{BASE}  - {{id: Apache-2.0 WITH Not-An-Exception, text: own}}
"
            ),
            names: ["Not-An-Exception", "exception"],
        },
        Rejected {
            name: "an exception on a licence id that SPDX does not know",
            config: format!(
                "{BASE}  - {{id: Apche-2.0 WITH LLVM-exception, text: own}}
"
            ),
            names: ["Apche-2.0", "licenses"],
        },
        Rejected {
            name: "an override licence without a version",
            config: overrides("{name: widget, ecosystem: crate, license: MIT}"),
            names: ["widget", "version"],
        },
    ];
    let mut failed = Vec::new();
    for row in rows {
        match Config::parse(&row.config) {
            Ok(_) => failed.push(format!("{}: the config loads", row.name)),
            Err(error @ NoticesError::Config { .. }) => {
                let message = error.to_string();
                if !row.names.iter().all(|word| message.contains(word)) {
                    failed.push(format!(
                        "{}: the message does not name {:?}: {message}",
                        row.name, row.names
                    ));
                }
            }
            Err(other) => failed.push(format!("{}: expected a Config error, got {other:?}", row.name)),
        }
    }
    assert!(failed.is_empty(), "{} rows:\n{}", failed.len(), failed.join("\n"));
}

/// Two configs: one whose `overrides:` entry sets `license: <expression>`, and one whose `declared:` entry does.
fn with_licence(expression: &str) -> (String, String) {
    let overrides = format!(
        "{BASE}overrides:\n  - {{name: widget, ecosystem: crate, version: \"1.0.0\", license: {expression}}}\n"
    );
    let declared = format!("{BASE}declared:\n  - {{name: widget, version: \"1\", license: {expression}}}\n");
    (overrides, declared)
}

#[skuld::test]
fn a_config_licence_is_accepted_when_the_licence_followed_for_it_is_listed() {
    // `choose` follows MIT here, so the expression is as good as `MIT`, whatever else it offers.
    for expression in [
        "MIT OR GPL-2.0-only",
        "GPL-2.0-only OR MIT",
        "MIT OR Apache-2.0 WITH LLVM-exception",
        "(GPL-2.0-only OR ISC) OR MIT",
        "MIT AND (Apache-2.0 OR GPL-2.0-only)",
    ] {
        let (overrides, declared) = with_licence(expression);
        Config::parse(&overrides).unwrap_or_else(|e| panic!("override `{expression}`: {e}"));
        Config::parse(&declared).unwrap_or_else(|e| panic!("declared `{expression}`: {e}"));
    }
}

#[skuld::test]
fn a_config_licence_that_no_listed_licence_follows_says_which_and_why() {
    let message = |expression: &str| {
        let (overrides, declared) = with_licence(expression);
        let from_override = Config::parse(&overrides).unwrap_err().to_string();
        let from_declared = Config::parse(&declared).unwrap_err().to_string();
        assert!(
            from_override.contains("overrides") && from_declared.contains("declared"),
            "{from_override}\n{from_declared}"
        );
        from_override
    };

    // A licence that is not listed is named, and the message offers listing it; it does not blame an exception.
    let unlisted = message("GPL-2.0-only");
    assert!(
        unlisted.contains("GPL-2.0-only") && unlisted.contains("`licenses:`"),
        "{unlisted}"
    );
    assert!(!unlisted.contains("exception"), "{unlisted}");
    let either = message("GPL-2.0-only OR ISC");
    assert!(either.contains("GPL-2.0-only") && either.contains("ISC"), "{either}");

    // An exception changes the terms: the message says so, and offers listing the whole requirement with its own text.
    let excepted = message("Apache-2.0 WITH LLVM-exception");
    assert!(excepted.contains("an exception"), "{excepted}");
    assert!(
        excepted.contains("list `Apache-2.0 WITH LLVM-exception` on `licenses:` with `text: own`"),
        "{excepted}"
    );
}

#[skuld::test]
fn every_variant_the_remedy_table_reads_has_a_case_or_no_config_entry() {
    let with_a_case: std::collections::BTreeSet<&str> = cases().iter().map(|case| case.fails_with).collect();
    for (error, _) in super::notices_tests::every_variant() {
        let name = variant(&error);
        let settled_by_config = !matches!(remedy(&error), Remedy::NotAConfigEntry);
        assert!(
            !settled_by_config || with_a_case.contains(name.as_str()),
            "{name} states a remedy and no case in `cases()` produces it"
        );
    }
}
