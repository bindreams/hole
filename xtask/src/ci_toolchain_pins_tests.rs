//! Unit tests for [`crate::ci_toolchain_pins`] plus the
//! `ci_toolchain_steps_name_the_pin` and `ci_toolchain_reads_are_checkout_gated`
//! structural conformance tests.

use std::collections::BTreeMap;
use std::fs;

use crate::ci_toolchain_pins::{audit_checkout_gating, audit_document, resolve_local_pin_readers, GO_VERSION_FILE};

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

// Checkout-gating =====================================================================================================

#[skuld::test]
fn reader_matching_its_checkout_if_is_clean() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - name: read\n        if: ${{ inputs.x }}\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    assert_eq!(audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap(), vec![]);
}

/// A checkout gated on a condition, followed by an unconditional read of a
/// file that checkout produces.
#[skuld::test]
fn ungated_reader_after_conditional_checkout_is_flagged() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - name: read\n        id: rust-version\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].step, "rust-version");
    assert_eq!(found[0].depends_on_if.as_deref(), Some("${{ inputs.x }}"));
    assert_eq!(found[0].step_if, None);
}

/// A job with no `actions/checkout` step at all has an empty workspace, so a
/// root-relative read there is a guaranteed failure — not an exemption.
#[skuld::test]
fn reader_with_no_preceding_checkout_in_a_job_is_flagged() {
    let yaml =
        "jobs:\n  a:\n    steps:\n      - name: read\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].depends_on_if, None);
}

/// The likeliest way to reintroduce #859's shape: a reader placed above the
/// checkout it was meant to follow. At the point the reader runs, no
/// checkout has happened yet in this job, regardless of what comes later.
#[skuld::test]
fn reader_placed_before_its_checkout_is_flagged() {
    let yaml = "jobs:\n  a:\n    steps:\n      - name: read\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n      - uses: actions/checkout@v7\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

/// A checkout that relocates the tree (`path:`) doesn't satisfy a
/// root-relative read — it must not become the baseline.
#[skuld::test]
fn checkout_with_path_does_not_satisfy_a_root_relative_read() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n        with:\n          path: source\n      - name: read\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].depends_on_if, None);
}

#[skuld::test]
fn go_version_file_input_is_a_direct_reader() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - uses: actions/setup-go@v7\n        with:\n          go-version-file: crates/ex-ray/go.mod\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[skuld::test]
fn node_version_file_input_is_a_direct_reader() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - uses: actions/setup-node@v7\n        with:\n          node-version-file: package.json\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

/// An install step consuming a read step's output, gated differently from
/// that read step, is #859's second broken pairing — independent of any
/// checkout, and present even inside a single composite action's own steps.
#[skuld::test]
fn consumer_of_a_readers_output_gated_differently_is_flagged() {
    let yaml = "runs:\n  using: composite\n  steps:\n    - id: rust-version\n      if: ${{ inputs.x }}\n      run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n    - uses: dtolnay/rust-toolchain@master\n      if: ${{ inputs.y }}\n      with:\n        toolchain: ${{ steps.rust-version.outputs.toolchain }}\n";
    let found = audit_checkout_gating("action.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].depends_on_if.as_deref(), Some("${{ inputs.x }}"));
    assert_eq!(found[0].step_if.as_deref(), Some("${{ inputs.y }}"));
}

#[skuld::test]
fn consumer_matching_the_readers_condition_is_clean() {
    let yaml = "runs:\n  using: composite\n  steps:\n    - id: rust-version\n      if: ${{ inputs.x }}\n      run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n    - uses: dtolnay/rust-toolchain@master\n      if: ${{ inputs.x }}\n      with:\n        toolchain: ${{ steps.rust-version.outputs.toolchain }}\n";
    assert_eq!(
        audit_checkout_gating("action.yaml", yaml, &BTreeMap::new()).unwrap(),
        vec![]
    );
}

#[skuld::test]
fn bare_if_and_wrapped_if_are_the_same_condition() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: inputs.x\n      - name: read\n        if: ${{ inputs.x }}\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    assert_eq!(audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap(), vec![]);
}

#[skuld::test]
fn whitespace_variance_in_if_is_the_same_condition() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x  &&  inputs.y }}\n      - name: read\n        if: ${{ inputs.x && inputs.y }}\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    assert_eq!(audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap(), vec![]);
}

#[skuld::test]
fn unconditional_checkout_requires_unconditional_reader() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n      - name: read\n        if: ${{ inputs.x }}\n        run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    let found = audit_checkout_gating("f.yaml", yaml, &BTreeMap::new()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

/// A step calling a local composite action known (via the reader graph) to
/// read the pin is treated the same as reading it directly.
#[skuld::test]
fn local_action_call_is_treated_as_a_reader() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - uses: ./.github/actions/setup-rust\n";
    let mut readers = BTreeMap::new();
    readers.insert("./.github/actions/setup-rust".to_owned(), true);
    let found = audit_checkout_gating("f.yaml", yaml, &readers).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[skuld::test]
fn local_action_not_known_to_read_the_pin_is_ignored() {
    let yaml = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        if: ${{ inputs.x }}\n      - uses: ./.github/actions/mint-nathan-token\n";
    let mut readers = BTreeMap::new();
    readers.insert("./.github/actions/setup-rust".to_owned(), true);
    assert_eq!(audit_checkout_gating("f.yaml", yaml, &readers).unwrap(), vec![]);
}

#[skuld::test]
fn composite_actions_own_steps_have_no_checkout_to_compare() {
    let yaml = "runs:\n  using: composite\n  steps:\n    - name: read\n      run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n";
    assert_eq!(
        audit_checkout_gating("action.yaml", yaml, &BTreeMap::new()).unwrap(),
        vec![]
    );
}

#[skuld::test]
fn resolve_local_pin_readers_finds_direct_readers() {
    let mut actions = BTreeMap::new();
    actions.insert(
        "./.github/actions/setup-rust".to_owned(),
        "runs:\n  using: composite\n  steps:\n    - run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n".to_owned(),
    );
    let readers = resolve_local_pin_readers(&actions).unwrap();
    assert_eq!(readers.get("./.github/actions/setup-rust"), Some(&true));
}

/// `setup-build` doesn't read the pin itself post-refactor; it calls
/// `setup-rust`, which does. The graph has to follow that call to still
/// treat `setup-build`'s own callers as reading the pin transitively.
#[skuld::test]
fn resolve_local_pin_readers_follows_transitive_local_calls() {
    let mut actions = BTreeMap::new();
    actions.insert(
        "./.github/actions/setup-rust".to_owned(),
        "runs:\n  using: composite\n  steps:\n    - run: sed rust-toolchain.toml >> \"$GITHUB_OUTPUT\"\n".to_owned(),
    );
    actions.insert(
        "./.github/actions/setup-build".to_owned(),
        "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/setup-rust\n".to_owned(),
    );
    let readers = resolve_local_pin_readers(&actions).unwrap();
    assert_eq!(readers.get("./.github/actions/setup-build"), Some(&true));
}

/// Every `.github/` workflow and composite action, audited for real. This is
/// the test that closes the class: a new job that installs a toolchain without
/// naming the pin fails here at commit time rather than on the day the next
/// release ships.
#[skuld::test]
fn ci_toolchain_steps_name_the_pin() {
    let docs = collect_github_docs();

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

/// Every `.github/` workflow and composite-action document, read from disk.
/// Shared by the structural conformance tests below.
fn collect_github_docs() -> Vec<(String, String)> {
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
    docs
}

/// Extends the pin-naming test above: a step (or a local composite action
/// that reads it) must not run under a condition weaker than the checkout it
/// depends on.
#[skuld::test]
fn ci_toolchain_reads_are_checkout_gated() {
    let docs = collect_github_docs();

    let local_actions: BTreeMap<String, String> = docs
        .iter()
        .filter_map(|(file, contents)| {
            let rest = file.strip_prefix(".github/actions/")?;
            let dir = rest
                .strip_suffix("/action.yaml")
                .or_else(|| rest.strip_suffix("/action.yml"))?;
            Some((format!("./.github/actions/{dir}"), contents.clone()))
        })
        .collect();
    let local_pin_readers = resolve_local_pin_readers(&local_actions).expect("resolve local pin readers");

    let mut ungated = Vec::new();
    for (file, contents) in &docs {
        ungated.extend(audit_checkout_gating(file, contents, &local_pin_readers).expect("audit"));
    }

    assert!(
        ungated.is_empty(),
        "these steps read a repository file under a condition weaker than (or merely \
         different from) the checkout they depend on, so they can run against a workspace \
         that was never checked out:\n{}",
        ungated
            .iter()
            .map(|u| format!(
                "  {} job `{}` step `{}`: if={:?}, depends on if={:?}",
                u.file, u.job, u.step, u.step_if, u.depends_on_if
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
