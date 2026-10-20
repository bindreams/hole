//! The rustdoc targets document private items for exactly the crates that are not published: a
//! published crate's docs are built by docs.rs without them, so a link from its public docs to a
//! private item is a real break there; an unpublished crate's docs are only read in source, so
//! its steps also allow `private_intra_doc_links`, and no others.
//!
//! Library and binary targets are documented by separate commands: a plain `cargo doc` skips a
//! `[[bin]]` named like its package's `[lib]` (`hole`, `xtask`, `dev-console`, `galoshes`), which
//! would leave `crates/hole`'s binary-only modules unchecked, and `--lib --bins` together makes
//! the two write the same `target/doc/<name>/` directory.

use std::collections::BTreeSet;
use std::fs;

use cargo_metadata::TargetKind;

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

/// The target kind one `cargo doc` command is restricted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Libs,
    Bins,
}

/// `--lib` xor `--bins`; a command with neither or both is the shape that hides a bin or races it.
fn kind(command: &str) -> Kind {
    let words: Vec<&str> = command.split_whitespace().collect();
    match (words.contains(&"--lib"), words.contains(&"--bins")) {
        (true, false) => Kind::Libs,
        (false, true) => Kind::Bins,
        (lib, bins) => panic!("`{command}` must pass exactly one of --lib / --bins (--lib: {lib}, --bins: {bins})"),
    }
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

    let has_target = |package: &str, wanted: &[TargetKind]| {
        metadata
            .workspace_packages()
            .iter()
            .find(|p| p.name == package)
            .is_some_and(|p| p.targets.iter().any(|t| wanted.iter().any(|k| t.is_kind(k.clone()))))
    };

    let mut documented_by_doc_hole = BTreeSet::new();
    for target in ["doc-hole", "doc-ex-galoshes"] {
        let t = manifest.get(target).unwrap_or_else(|| panic!("{target} missing"));
        let mut libs_documented = BTreeSet::new();
        let mut bins_documented = BTreeSet::new();
        for step in &t.run {
            let Step::Bash { command, environment } = step else {
                panic!("{target}: expected bash steps, got {step:?}");
            };
            let (selected, with_private) = selection(command, &members);
            // Public docs of an unpublished crate may link its private items: nobody reads them
            // without private items, and the check always builds with them.
            let expected_flags = if with_private {
                "-D warnings -A rustdoc::private_intra_doc_links"
            } else {
                "-D warnings"
            };
            assert_eq!(
                environment.get("RUSTDOCFLAGS").map(String::as_str),
                Some(expected_flags),
                "{target}: `{command}` must run with RUSTDOCFLAGS=`{expected_flags}`"
            );
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
            match kind(command) {
                Kind::Libs => libs_documented.extend(selected.iter().cloned()),
                Kind::Bins => bins_documented.extend(selected.iter().cloned()),
            }
            if target == "doc-hole" {
                documented_by_doc_hole.extend(selected);
            }
        }
        let selected_anywhere: BTreeSet<&String> = libs_documented.union(&bins_documented).collect();
        for package in selected_anywhere {
            assert!(
                !has_target(package, &[TargetKind::Lib, TargetKind::ProcMacro]) || libs_documented.contains(package),
                "{target}: the library of `{package}` is not documented by any `--lib` command"
            );
            assert!(
                !has_target(package, &[TargetKind::Bin]) || bins_documented.contains(package),
                "{target}: the binaries of `{package}` are not documented by any `--bins` command"
            );
        }
    }
    assert_eq!(
        documented_by_doc_hole, members,
        "doc-hole runs on the legs where the whole workspace compiles, so it must document every member"
    );
}
