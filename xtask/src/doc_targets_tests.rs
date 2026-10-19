//! The rustdoc targets document private items for exactly the crates that are not published: a
//! published crate's docs are built by docs.rs without them, so a link from its public docs to a
//! private item is a real break there; an unpublished crate's docs are only read in source.

use std::collections::BTreeSet;
use std::fs;

use crate::manifest::{Manifest, Step};

/// The packages one `cargo doc` command selects, and whether it documents private items.
fn selection(command: &str, members: &BTreeSet<String>) -> (BTreeSet<String>, bool) {
    let words: Vec<&str> = command.split_whitespace().collect();
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
    (selected, words.contains(&"--document-private-items"))
}

#[skuld::test]
fn doc_targets_document_private_items_of_unpublished_crates_only() {
    let root = crate::repo_root().expect("repo root");
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .expect("cargo metadata");
    let members: BTreeSet<String> = metadata
        .workspace_packages()
        .iter()
        .map(|p| p.name.to_string())
        .collect();
    // `publish = false` is `Some([])`; an absent key is `None` (publishable anywhere).
    let unpublished: BTreeSet<String> = metadata
        .workspace_packages()
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
        for step in &t.run {
            let Step::Bash { command, environment } = step else {
                panic!("{target}: expected bash steps, got {step:?}");
            };
            assert_eq!(
                environment.get("RUSTDOCFLAGS").map(String::as_str),
                Some("-D warnings"),
                "{target}: `{command}` must deny rustdoc warnings"
            );
            let (selected, with_private) = selection(command, &members);
            assert!(!selected.is_empty(), "{target}: `{command}` selects no package");
            for package in &selected {
                assert!(
                    members.contains(package),
                    "{target}: `{package}` is not a workspace member"
                );
                assert_eq!(
                    with_private,
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
                documented_by_doc_hole.extend(selected);
            }
        }
    }
    assert_eq!(
        documented_by_doc_hole, members,
        "doc-hole runs on the legs where the whole workspace compiles, so it must document every member"
    );
}
