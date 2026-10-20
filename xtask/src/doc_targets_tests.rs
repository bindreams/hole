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

use std::collections::BTreeSet;
use std::fs;

use cargo_metadata::{Package, Target, TargetKind};

use crate::manifest::{Manifest, Step};

/// What one `cargo doc` command documents.
struct Doc {
    /// The packages it selects.
    selected: BTreeSet<String>,
    private_items: bool,
    what: What,
    /// `--features` values, as written (`pkg/feature` or a bare feature).
    features: BTreeSet<String>,
    all_features: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum What {
    /// `cargo doc --lib`
    Libs,
    /// `cargo doc --bins`
    Bins,
}

impl Doc {
    fn parse(command: &str, members: &BTreeSet<String>) -> Doc {
        let words: Vec<&str> = command.split_whitespace().collect();
        assert!(
            command.starts_with("cargo doc "),
            "`{command}` is not a `cargo doc` command"
        );
        let after = |flag: &str| -> BTreeSet<String> {
            words
                .windows(2)
                .filter(|w| w[0] == flag)
                .map(|w| w[1].to_string())
                .collect()
        };
        let selected = if words.contains(&"--workspace") {
            members.difference(&after("--exclude")).cloned().collect()
        } else {
            after("-p")
        };
        let what = match (words.contains(&"--lib"), words.contains(&"--bins")) {
            (true, false) => What::Libs,
            (false, true) => What::Bins,
            (lib, bins) => panic!("`{command}` must pass exactly one of --lib / --bins (--lib: {lib}, --bins: {bins})"),
        };
        Doc {
            selected,
            private_items: words.contains(&"--document-private-items"),
            what,
            features: after("--features")
                .iter()
                .flat_map(|v| v.split(',').map(str::to_string))
                .collect(),
            all_features: words.contains(&"--all-features"),
        }
    }

    /// Whether this command turns `feature` of `package` on.
    fn enables(&self, package: &str, feature: &str) -> bool {
        self.all_features
            || self.features.contains(&format!("{package}/{feature}"))
            // A bare feature name applies to the selected package only when it is the sole one.
            || (self.selected.len() == 1 && self.selected.contains(package) && self.features.contains(feature))
    }

    /// Whether this command documents the bin `target` of `package`, with its required features on.
    fn documents_bin(&self, package: &Package, target: &Target) -> bool {
        let covers = match &self.what {
            What::Libs => false,
            What::Bins => self.selected.contains(package.name.as_str()),
        };
        covers && target.required_features.iter().all(|f| self.enables(&package.name, f))
    }
}

fn is_lib(kind: &TargetKind) -> bool {
    *kind == TargetKind::Lib || *kind == TargetKind::ProcMacro
}

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

    let mut documented_by_doc_hole = BTreeSet::new();
    for target in ["doc-hole", "doc-ex-galoshes"] {
        let t = manifest.get(target).unwrap_or_else(|| panic!("{target} missing"));
        let mut docs = Vec::new();
        for step in &t.run {
            let Step::Bash { command, environment } = step else {
                panic!("{target}: expected bash steps, got {step:?}");
            };
            let doc = Doc::parse(command, &members);
            // Public docs of an unpublished crate may link its private items: nobody reads them
            // without private items, and the check always builds with them.
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
            if target == "doc-hole" {
                documented_by_doc_hole.extend(doc.selected.iter().cloned());
            }
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
                        docs.iter().any(|d| d.documents_bin(package, tgt)),
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
        documented_by_doc_hole, members,
        "doc-hole runs on the legs where the whole workspace compiles, so it must document every member"
    );
}
