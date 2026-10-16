//! Unit tests for the prek hook split plus the structural conformance test that
//! holds every `prek.toml` hook to an explicit, evidenced classification.

use std::collections::BTreeSet;
use std::fs;

use crate::manifest::Manifest;
use crate::prek_split::{hook_ids, host_bound_hooks, portable_skip};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ===== hook_ids ======================================================================================================

#[skuld::test]
fn hook_ids_cover_table_form_and_inline_form_and_dedupe() {
    let toml = r#"
[[repos]]
repo = "local"

[[repos.hooks]]
id = "local-one"

[[repos]]
repo = "https://example.invalid/hooks"
rev = "v1"
hooks = [
  { id = "inline-a" },
  { id = "inline-b", args = ["--x"] },
]

[[repos]]
repo = "https://example.invalid/fmt"
rev = "v1"

[[repos.hooks]]
id = "twice"

[[repos.hooks]]
id = "twice"
name = "second config of the same hook"
"#;
    assert_eq!(
        hook_ids(toml).unwrap(),
        set(&["local-one", "inline-a", "inline-b", "twice"])
    );
}

// ===== portable_skip / host_bound_hooks ==============================================================================

fn fixture() -> Manifest {
    Manifest::parse(
        r#"
targets:
  portable:
    platforms: [linux/amd64]
    run:
      - bash:
          command: prek run --all-files --show-diff-on-failure
          environment: { SKIP: "cargo-clippy, go-lint" }
  host-bound:
    platforms: [linux/amd64]
    run: prek run go-lint other --all-files --show-diff-on-failure
  no-skip:
    platforms: [linux/amd64]
    run: prek run --all-files
  no-prek:
    platforms: [linux/amd64]
    run: echo
"#,
    )
    .unwrap()
}

#[skuld::test]
fn the_skip_set_is_read_from_the_prek_step_environment() {
    assert_eq!(
        portable_skip(&fixture(), "portable").unwrap(),
        set(&["cargo-clippy", "go-lint"])
    );
    assert_eq!(portable_skip(&fixture(), "no-skip").unwrap(), set(&[]));
}

#[skuld::test]
fn the_host_bound_ids_are_the_positional_arguments_of_prek_run() {
    assert_eq!(
        host_bound_hooks(&fixture(), "host-bound").unwrap(),
        set(&["go-lint", "other"])
    );
}

/// A bare `prek run --all-files` would run every hook: it is not a host-bound
/// target, and returning an empty set for it would pass vacuously.
#[skuld::test]
fn a_target_that_names_no_hook_or_no_prek_step_is_an_error() {
    assert!(host_bound_hooks(&fixture(), "no-skip").is_err());
    assert!(host_bound_hooks(&fixture(), "no-prek").is_err());
    assert!(portable_skip(&fixture(), "no-prek").is_err());
    assert!(portable_skip(&fixture(), "gone").is_err());
}

// ===== conformance ===================================================================================================

/// How a hook's verdict depends on the machine that runs it.
enum Class {
    /// Same verdict on every host: run once, in the linux/amd64 leg.
    Portable(&'static str),
    /// The verdict depends on the host's OS or arch: run in every leg.
    HostBound(&'static str),
    /// Host-bound, and run per leg by the `clippy-*` steps instead of prek.
    PerLegClippy(&'static str),
}

impl Class {
    fn evidence(&self) -> &'static str {
        match self {
            Class::Portable(e) | Class::HostBound(e) | Class::PerLegClippy(e) => e,
        }
    }
}

/// EVERY hook in `prek.toml`, classified with the evidence for the class. A new
/// hook fails `every_prek_hook_is_classified` until it is added here, which is
/// the point: the default for an unclassified hook must not be "run once".
///
/// "Measured" entries were run on a darwin host on 2026-10-16.
fn classes() -> Vec<(&'static str, Class)> {
    use Class::{HostBound, PerLegClippy, Portable};
    vec![
        ("no-std-test", Portable("pygrep over file text")),
        ("no-cargo-in-tests", Portable("pygrep over file text")),
        (
            "cargo-fmt",
            Portable(
                "measured: `cargo fmt --check` on darwin flagged a mis-formatted line appended to the \
                 `#![cfg(windows)]` file crates/tun-engine/src/dns_confine/privileged_tests.rs; rustfmt parses \
                 every module without evaluating cfg",
            ),
        ),
        (
            "cargo-clippy",
            PerLegClippy("type-checks the cfg-gated code of the host's own target; skipped in prek, run by clippy-*"),
        ),
        (
            "go-fmt",
            Portable(
                "measured: `golangci-lint fmt --diff` on darwin flagged mis-formatted lines appended to BOTH \
                 keepalive_windows.go and keepalive_linux.go; gofumpt reads files and applies no build tags",
            ),
        ),
        (
            "go-lint",
            HostBound(
                "measured: with a self-assignment appended to keepalive_windows.go, `golangci-lint run` on darwin \
                 reported 0 issues and GOOS=windows reported the finding; it type-checks packages under the host's \
                 GOOS, so _windows/_linux/_darwin files are linted only on their own platform",
            ),
        ),
        ("check-version-hole", Portable("compares Cargo.toml with git tags")),
        ("check-version-garter", Portable("compares Cargo.toml with git tags")),
        ("check-version-galoshes", Portable("compares Cargo.toml with git tags")),
        ("check-version-ex-ray", Portable("compares version.toml with git tags")),
        (
            "gen-ui-constants",
            Portable("parses Rust source text, writes TypeScript"),
        ),
        ("check-vendoring-integrity", Portable("text scan of vendored trees")),
        (
            "check-schemars-pin",
            Portable("`cargo metadata` without --filter-platform resolves every target's dependencies"),
        ),
        ("check-workspace-lints", Portable("python over Cargo.toml text")),
        ("format-section-comments", Portable("python over file text")),
        (
            "ty",
            Portable("ty.toml sets python-platform = \"all\", so POSIX-only and Windows-only APIs both resolve"),
        ),
        (
            "validate-docs",
            Portable("Sphinx build of docs/, no host-specific input"),
        ),
        (
            "check-executables-have-shebangs",
            Portable("reads file content and the git file mode"),
        ),
        (
            "check-shebang-scripts-are-executable",
            Portable(
                "compares the shebang against the committed git file mode; moving it from a Windows checkout to \
                 Linux makes the working-tree mode real, so a previously invisible finding is a true finding",
            ),
        ),
        ("mixed-line-ending", Portable("reads file bytes")),
        ("editorconfig-checker", Portable("reads file text")),
        ("yapf", Portable("formats Python source text")),
        ("mdformat", Portable("formats Markdown text")),
        ("biome-check", Portable("lints and formats JS/TS source text")),
    ]
}

fn read_repo(rel: &str) -> String {
    let root = crate::repo_root().expect("repo root");
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn ids_of(want_portable: bool) -> BTreeSet<String> {
    classes()
        .into_iter()
        .filter(|(_, c)| matches!(c, Class::Portable(_)) == want_portable)
        .map(|(id, _)| id.to_string())
        .collect()
}

/// The lint split runs platform-independent hooks once and platform-dependent
/// hooks on every leg. Which is which is a fact about each hook, so each hook is
/// classified by name here, with its evidence; the build.yaml targets are then
/// held to that classification.
#[skuld::test]
fn every_prek_hook_is_classified() {
    let hooks = hook_ids(&read_repo("prek.toml")).expect("parse prek.toml");
    let classified: BTreeSet<String> = classes().into_iter().map(|(id, _)| id.to_string()).collect();
    assert_eq!(
        hooks.symmetric_difference(&classified).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "prek.toml hooks and the classification in prek_split_tests.rs disagree: classify any new hook \
         as Portable (same verdict on every host) or HostBound, with evidence"
    );
}

/// The portable run skips exactly the hooks that are not portable.
#[skuld::test]
fn the_portable_run_skips_exactly_the_non_portable_hooks() {
    let manifest = Manifest::parse(&read_repo("build.yaml")).expect("parse build.yaml");
    assert_eq!(portable_skip(&manifest, "prek-portable").unwrap(), ids_of(false));
}

/// The per-leg run names exactly the host-bound hooks prek itself runs.
#[skuld::test]
fn the_host_bound_run_names_exactly_the_host_bound_hooks_prek_runs() {
    let manifest = Manifest::parse(&read_repo("build.yaml")).expect("parse build.yaml");
    let want: BTreeSet<String> = classes()
        .into_iter()
        .filter(|(_, c)| matches!(c, Class::HostBound(_)))
        .map(|(id, _)| id.to_string())
        .collect();
    assert_eq!(host_bound_hooks(&manifest, "prek-host-bound").unwrap(), want);
}

#[skuld::test]
fn every_classification_cites_evidence() {
    for (id, class) in classes() {
        assert!(
            class.evidence().len() > 10,
            "{id}: classify with evidence, not a bare label"
        );
    }
}
