//! The rustdoc targets document private items for exactly the crates that are not published: a
//! published crate's docs are built by docs.rs without them, so a link from its public docs to a
//! private item is a real break there; an unpublished crate's docs are only read in source, so
//! its steps also allow `private_intra_doc_links`, and no others.
//!
//! Every target of every workspace package is documented, read off the commands' text against
//! `cargo metadata`, so a target a command would silently skip fails here:
//! - A plain `cargo doc` skips a `[[bin]]` named like its package's `[lib]` (`hole`, `xtask`,
//!   `dev-console`, `galoshes`), which would leave `crates/hole`'s binary-only modules unchecked,
//!   so `--bins` is passed explicitly.
//! - A bin with `required-features` (`tombstone`'s `crash_child`) is skipped unless the command
//!   enables them, so each command that documents one must.
//!
//! `doc-hole` documents every member; `doc-ex-galoshes` every member but `EX_GALOSHES_EXCLUDED`,
//! so a new crate is in a command or in that list with a reason. `Doc::parse` rejects a flag it
//! does not model rather than ignoring it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use cargo_metadata::TargetKind;

use crate::manifest::{Manifest, Step};

/// What one `cargo doc` command documents.
struct Doc {
    selected: BTreeSet<String>,
    private_items: bool,
    what: What,
    /// `--features` values, as written (`pkg/feature` or a bare feature).
    features: BTreeSet<String>,
    all_features: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum What {
    Libs,
    Bins,
}

impl Doc {
    /// Reads a `cargo doc` command. A flag this does not model is an error, never ignored: an
    /// ignored `--exclude` or `--package` would leave `selected` describing a different command
    /// from the one CI runs.
    fn parse(command: &str, members: &BTreeSet<String>) -> Result<Doc, String> {
        let mut words = command.split_whitespace();
        if (words.next(), words.next()) != (Some("cargo"), Some("doc")) {
            return Err(format!("`{command}` is not a `cargo doc` command"));
        }
        let (mut workspace, mut lib, mut bins, mut private_items, mut all_features) =
            (false, false, false, false, false);
        let (mut excluded, mut packages, mut features) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        while let Some(word) = words.next() {
            // `--flag value` and `--flag=value` are the same flag.
            let (flag, inline) = match word.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (word, None),
            };
            let mut value = || {
                inline
                    .or_else(|| words.next())
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{command}`: `{flag}` has no value"))
            };
            match flag {
                "--exclude" => {
                    excluded.insert(value()?);
                }
                "-p" | "--package" => {
                    packages.insert(value()?);
                }
                "--features" | "-F" => features.extend(value()?.split(',').map(str::to_string)),
                "--workspace"
                | "--lib"
                | "--bins"
                | "--document-private-items"
                | "--all-features"
                | "--no-deps"
                | "--no-default-features" => {
                    if inline.is_some() {
                        return Err(format!("`{command}`: `{flag}` takes no value"));
                    }
                    match flag {
                        "--workspace" => workspace = true,
                        "--lib" => lib = true,
                        "--bins" => bins = true,
                        "--document-private-items" => private_items = true,
                        "--all-features" => all_features = true,
                        _ => {}
                    }
                }
                _ => return Err(format!("`{command}`: `{word}` is not a flag this test models")),
            }
        }
        let what = match (lib, bins) {
            (true, false) => What::Libs,
            (false, true) => What::Bins,
            _ => return Err(format!("`{command}` must pass exactly one of --lib / --bins")),
        };
        let selected = match (workspace, packages.is_empty()) {
            (true, true) => members.difference(&excluded).cloned().collect(),
            (false, false) if excluded.is_empty() => packages,
            _ => {
                return Err(format!(
                    "`{command}` must select with --workspace [--exclude] or -p, not both"
                ))
            }
        };
        Ok(Doc {
            selected,
            private_items,
            what,
            features,
            all_features,
        })
    }

    /// Whether this command turns `feature` of `package` on.
    fn enables(&self, package: &str, feature: &str) -> bool {
        self.all_features
            || self.features.contains(&format!("{package}/{feature}"))
            // A bare feature name applies to the selected package only when it is the sole one.
            || (self.selected.len() == 1 && self.selected.contains(package) && self.features.contains(feature))
    }

    /// Whether this command documents a bin of `package` that needs `required_features`.
    fn documents_bin(&self, package: &str, required_features: &[String]) -> bool {
        self.what == What::Bins
            && self.selected.contains(package)
            && required_features.iter().all(|f| self.enables(package, f))
    }
}

fn is_lib(kind: &TargetKind) -> bool {
    *kind == TargetKind::Lib || *kind == TargetKind::ProcMacro
}

/// Workspace packages `doc-ex-galoshes` does not document, each with why. Everything else is
/// documented there, so a crate that compiles on those legs is checked per platform, and a new
/// crate is either in that command or in this list.
const EX_GALOSHES_EXCLUDED: &[(&str, &str)] = &[
    ("hole", "does not compile on linux or windows/arm64"),
    ("hole-bridge", "does not compile on linux or windows/arm64"),
    ("tun-engine", "does not compile on linux or windows/arm64"),
];

#[skuld::test]
fn doc_targets_document_private_items_of_unpublished_crates_only() {
    let root = crate::repo_root().expect("repo root");
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .expect("cargo metadata");
    let packages = metadata.workspace_packages();
    let members: BTreeSet<String> = packages.iter().map(|p| p.name.to_string()).collect();
    // `publish = false` is `Some([])`; an absent key is `None` (publishable anywhere).
    let unpublished: BTreeSet<String> = packages
        .iter()
        .filter(|p| p.publish.as_ref().is_some_and(Vec::is_empty))
        .map(|p| p.name.to_string())
        .collect();
    assert!(
        !unpublished.is_empty() && unpublished != members,
        "the workspace must hold both published and unpublished crates for this test to mean anything"
    );
    let manifest = Manifest::parse(&fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml");

    let mut documented_by: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for target in ["doc-hole", "doc-ex-galoshes"] {
        let t = manifest.get(target).unwrap_or_else(|| panic!("{target} missing"));
        let mut docs = Vec::new();
        for step in &t.run {
            let Step::Bash { command, environment } = step else {
                panic!("{target}: expected bash steps, got {step:?}");
            };
            let doc = Doc::parse(command, &members).unwrap_or_else(|e| panic!("{target}: {e}"));
            let expected_flags = if doc.private_items {
                "-D warnings -A rustdoc::private_intra_doc_links"
            } else {
                "-D warnings"
            };
            assert_eq!(
                environment.get("RUSTDOCFLAGS").map(String::as_str),
                Some(expected_flags),
                "{target}: `{command}` must run with RUSTDOCFLAGS=`{expected_flags}`"
            );
            assert!(!doc.selected.is_empty(), "{target}: `{command}` selects no package");
            for package in &doc.selected {
                assert!(
                    members.contains(package),
                    "{target}: `{package}` is not a workspace member"
                );
                assert_eq!(
                    doc.private_items,
                    unpublished.contains(package),
                    "{target}: `{package}` must be documented {} --document-private-items (`{command}`)",
                    if unpublished.contains(package) {
                        "with"
                    } else {
                        "without"
                    },
                );
            }
            documented_by
                .entry(target)
                .or_default()
                .extend(doc.selected.iter().cloned());
            docs.push(doc);
        }
        let selected_anywhere: BTreeSet<&String> = docs.iter().flat_map(|d| &d.selected).collect();
        for package in packages
            .iter()
            .filter(|p| selected_anywhere.contains(&p.name.to_string()))
        {
            for tgt in &package.targets {
                if tgt.kind.iter().any(is_lib) {
                    assert!(
                        docs.iter()
                            .any(|d| d.what == What::Libs && d.selected.contains(package.name.as_str())),
                        "{target}: the library of `{}` is not documented by any `--lib` command",
                        package.name
                    );
                }
                if tgt.is_bin() {
                    assert!(
                        docs.iter()
                            .any(|d| d.documents_bin(&package.name, &tgt.required_features)),
                        "{target}: the bin `{}` of `{}` is documented by no command, or by one that does not \
                         enable its required features {:?}",
                        tgt.name,
                        package.name,
                        tgt.required_features,
                    );
                }
            }
        }
    }
    assert_eq!(
        documented_by["doc-hole"], members,
        "doc-hole runs on the legs where the whole workspace compiles, so it must document every member"
    );

    let excluded: BTreeSet<String> = EX_GALOSHES_EXCLUDED.iter().map(|(name, _)| name.to_string()).collect();
    assert_eq!(
        excluded.difference(&members).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "EX_GALOSHES_EXCLUDED names a package that is not a workspace member"
    );
    assert_eq!(
        documented_by["doc-ex-galoshes"],
        members.difference(&excluded).cloned().collect::<BTreeSet<_>>(),
        "doc-ex-galoshes must document every member except EX_GALOSHES_EXCLUDED: add the package to the \
         command, or to the list with a reason"
    );

    assert!(
        packages
            .iter()
            .flat_map(|p| &p.targets)
            .any(|t| t.is_bin() && !t.required_features.is_empty()),
        "no bin has `required-features`, so the check that a command enables them proves nothing"
    );
}

// Doc::parse / documents_bin ==========================================================================================

fn members(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

fn features(f: &[&str]) -> Vec<String> {
    f.iter().map(|f| f.to_string()).collect()
}

const BINS: &str = "cargo doc --workspace --exclude garter --bins --no-deps --document-private-items \
                    --no-default-features --features garter/test-utils,tombstone/crash-child";

#[skuld::test]
fn doc_parse_reads_a_workspace_command() {
    let all = members(&["garter", "tombstone", "hole"]);
    let doc = Doc::parse(BINS, &all).unwrap();
    assert_eq!(doc.selected, members(&["tombstone", "hole"]));
    assert_eq!(doc.what, What::Bins);
    assert!(doc.private_items);
    assert_eq!(doc.features, members(&["garter/test-utils", "tombstone/crash-child"]));
}

#[skuld::test]
fn doc_parse_treats_flag_value_and_flag_equals_value_alike() {
    let all = members(&["garter", "tombstone", "hole"]);
    let spaced = Doc::parse(
        "cargo doc --workspace --exclude garter --lib --features tombstone/crash-child",
        &all,
    )
    .unwrap();
    let equals = Doc::parse(
        "cargo doc --workspace --exclude=garter --lib --features=tombstone/crash-child",
        &all,
    )
    .unwrap();
    assert_eq!(equals.selected, members(&["tombstone", "hole"]));
    assert_eq!(equals.selected, spaced.selected);
    assert_eq!(equals.features, spaced.features);
    for command in [
        "cargo doc -p hole --lib",
        "cargo doc --package hole --lib",
        "cargo doc --package=hole --lib",
    ] {
        assert_eq!(
            Doc::parse(command, &all).unwrap().selected,
            members(&["hole"]),
            "{command}"
        );
    }
    assert_eq!(
        Doc::parse("cargo doc -p tombstone --bins -F crash-child", &all)
            .unwrap()
            .features,
        members(&["crash-child"])
    );
}

#[skuld::test]
fn doc_parse_rejects_what_it_does_not_model() {
    let all = members(&["garter", "hole"]);
    for command in [
        "cargo build --workspace --lib",
        "cargo doc --workspace --lib --target x86_64-unknown-linux-gnu",
        "cargo doc --workspace --exclude-foo garter --lib",
        "cargo doc -p hole --lib --offline",
        "cargo doc --workspace --lib=true",
        "cargo doc --workspace --exclude",
        "cargo doc --workspace --lib --bins",
        "cargo doc --workspace",
        "cargo doc --exclude garter --lib",
        "cargo doc -p hole --exclude garter --lib",
        "cargo doc --workspace -p hole --lib",
        "cargo doc --lib",
    ] {
        assert!(Doc::parse(command, &all).is_err(), "`{command}` must not parse");
    }
}

#[skuld::test]
fn a_bins_command_without_the_required_feature_does_not_document_the_bin() {
    let all = members(&["garter", "tombstone"]);
    let crash_child = features(&["crash-child"]);
    let with = Doc::parse(BINS, &all).unwrap();
    assert!(with.documents_bin("tombstone", &crash_child));

    let without = Doc::parse(&BINS.replace(",tombstone/crash-child", ""), &all).unwrap();
    assert!(!without.documents_bin("tombstone", &crash_child));
    // A bin with no required features is documented either way.
    assert!(without.documents_bin("tombstone", &[]));
}

#[skuld::test]
fn documents_bin_needs_a_bins_command_that_selects_the_package() {
    let all = members(&["garter", "tombstone"]);
    let libs = Doc::parse("cargo doc --workspace --lib --features tombstone/crash-child", &all).unwrap();
    assert!(!libs.documents_bin("tombstone", &[]));
    let other = Doc::parse("cargo doc -p garter --bins", &all).unwrap();
    assert!(!other.documents_bin("tombstone", &[]));
    assert!(other.documents_bin("garter", &[]));
}

#[skuld::test]
fn enables_reads_a_bare_feature_only_for_a_sole_package() {
    let all = members(&["garter", "tombstone"]);
    let sole = Doc::parse("cargo doc -p tombstone --bins --features crash-child", &all).unwrap();
    assert!(sole.enables("tombstone", "crash-child"));
    let several = Doc::parse("cargo doc -p tombstone -p garter --bins --features crash-child", &all).unwrap();
    assert!(!several.enables("tombstone", "crash-child"));
    let every = Doc::parse("cargo doc -p tombstone --bins --all-features", &all).unwrap();
    assert!(every.enables("tombstone", "crash-child"));
}
