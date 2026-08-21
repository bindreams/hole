//! Unit tests for [`crate::ci_toolchain_pins`] plus the
//! `ci_toolchain_steps_name_the_pin` structural conformance test.

use std::fs;

use crate::ci_toolchain_pins::{audit_document, GO_VERSION_FILE};

#[skuld::test]
fn setup_go_naming_the_pinned_go_mod_is_clean() {
    let yaml = format!(
        "jobs:\n  a:\n    steps:\n      - uses: actions/setup-go@v7\n        with:\n          go-version-file: {GO_VERSION_FILE}\n"
    );
    assert_eq!(audit_document("f.yaml", &yaml).unwrap(), vec![]);
}

#[skuld::test]
fn bare_go_version_is_flagged() {
    let yaml =
        "jobs:\n  a:\n    steps:\n      - uses: actions/setup-go@v7\n        with:\n          go-version: stable\n";
    let found = audit_document("f.yaml", yaml).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].why.contains("go-version-file"), "{found:?}");
}

/// The release workflow used to point at `go.mod` and get the `go` directive
/// (1.25.5) because there was no `toolchain` line; the path is right, so this
/// must stay clean now that the directive exists.
#[skuld::test]
fn setup_go_pointing_at_another_file_is_flagged() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/setup-go@v7\n        with:\n          go-version-file: .go-version\n";
    let found = audit_document("f.yaml", yaml).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].why.contains("expected"), "{found:?}");
}

#[skuld::test]
fn rust_toolchain_without_a_toolchain_input_is_flagged() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n";
    let found = audit_document("f.yaml", yaml).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].why.contains("toolchain"), "{found:?}");
}

#[skuld::test]
fn rust_toolchain_naming_a_toolchain_is_clean() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@master\n        with:\n          toolchain: ${{ steps.rust-version.outputs.toolchain }}\n";
    assert_eq!(audit_document("f.yaml", yaml).unwrap(), vec![]);
}

/// `setup-build` is a composite action, so its steps live under `runs.steps`
/// rather than `jobs.*.steps` — the shape most of CI's toolchain setup uses.
#[skuld::test]
fn composite_action_steps_are_audited() {
    let yaml = "runs:\n  using: composite\n  steps:\n    - uses: dtolnay/rust-toolchain@stable\n";
    assert_eq!(audit_document("action.yaml", yaml).unwrap().len(), 1);
}

#[skuld::test]
fn unrelated_actions_are_ignored() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n      - uses: actions/setup-node@v7\n        with:\n          node-version-file: package.json\n";
    assert_eq!(audit_document("f.yaml", yaml).unwrap(), vec![]);
}

/// Every `.github/` workflow and composite action, audited for real. This is
/// the test that closes the class: a new job that installs a toolchain without
/// naming the pin fails here at commit time rather than on the day the next
/// release ships.
#[skuld::test]
fn ci_toolchain_steps_name_the_pin() {
    let root = crate::repo_root().expect("repo root");

    let mut docs: Vec<(String, String)> = Vec::new();
    let workflows = root.join(".github/workflows");
    for entry in fs::read_dir(&workflows).expect("read .github/workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            let rel = format!(".github/workflows/{}", path.file_name().unwrap().to_string_lossy());
            docs.push((rel, fs::read_to_string(&path).expect("read workflow")));
        }
    }
    for entry in fs::read_dir(root.join(".github/actions")).expect("read .github/actions") {
        let dir = entry.expect("dir entry").path();
        for name in ["action.yaml", "action.yml"] {
            let path = dir.join(name);
            if path.is_file() {
                let rel = format!(".github/actions/{}/{name}", dir.file_name().unwrap().to_string_lossy());
                docs.push((rel, fs::read_to_string(&path).expect("read action")));
            }
        }
    }

    // A silent zero-file walk would pass vacuously; the workflow dir is large
    // and the action dir is not empty.
    assert!(docs.len() > 5, "found only {} .github documents", docs.len());

    let mut unpinned = Vec::new();
    for (file, contents) in &docs {
        unpinned.extend(audit_document(file, contents).expect("audit"));
    }

    assert!(
        unpinned.is_empty(),
        "these CI steps install a toolchain without naming the repo's pin, so they \
         resolve a release at job time:\n{}",
        unpinned
            .iter()
            .map(|u| format!("  {} — `{}`: {}", u.file, u.uses, u.why))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Naming the pin is only half of it: the step still has to read it
    // correctly. A mangled `sed` here yields an empty `toolchain:` input, which
    // an expression-valued `with:` hides from the check above and which would
    // otherwise surface at release time. Every site runs the identical command,
    // so hold them byte-equal rather than re-deriving the extraction.
    let mut readers: Vec<(&str, String)> = Vec::new();
    for (file, contents) in &docs {
        for line in contents.lines() {
            if line.contains("rust-toolchain.toml") && line.contains("GITHUB_OUTPUT") {
                readers.push((file, line.trim().to_owned()));
            }
        }
    }
    assert!(!readers.is_empty(), "no step reads rust-toolchain.toml");
    let (first_file, first) = &readers[0];
    for (file, cmd) in &readers {
        assert_eq!(
            cmd, first,
            "the pin-reading command differs between {first_file} and {file}; one of them \
             is not extracting `channel` and will install an empty toolchain"
        );
    }
}
