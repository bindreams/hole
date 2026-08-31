//! Backs the `prek_go_hooks_run_the_provisioned_binary` conformance test.

use serde::Deserialize;

use crate::golangci_lint::CACHE_DIR;

#[derive(Deserialize)]
struct Prek {
    repos: Vec<Repo>,
}

#[derive(Deserialize)]
struct Repo {
    #[serde(default)]
    hooks: Vec<Hook>,
}

#[derive(Deserialize)]
struct Hook {
    id: String,
    /// Absent on the external repos' inline hooks, which supply only an `id`.
    entry: Option<String>,
}

/// prek has no per-hook working directory, so the Go hooks reach the binary by
/// an absolute path they spell out themselves. Nothing makes that path follow
/// [`crate::golangci_lint::ensure`]: they agreed only because both were edited
/// together, and a pin bump that missed one would leave the hooks pointing at a
/// directory that was never downloaded.
#[skuld::test]
fn prek_go_hooks_run_the_provisioned_binary() {
    let root = crate::repo_root().expect("repo root");
    let text = std::fs::read_to_string(root.join("prek.toml")).expect("read prek.toml");
    let prek: Prek = toml::from_str(&text).expect("parse prek.toml");

    let expected = format!("{CACHE_DIR}/golangci-lint");
    let go_hooks: Vec<&Hook> = prek
        .repos
        .iter()
        .flat_map(|r| &r.hooks)
        .filter(|h| h.entry.as_deref().is_some_and(|e| e.contains("golangci-lint")))
        .collect();

    assert_eq!(
        go_hooks.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
        ["go-fmt", "go-lint"],
        "the set of golangci-lint hooks changed; this test enumerates them so a new one cannot skip the check"
    );
    for hook in go_hooks {
        let entry = hook.entry.as_deref().expect("filtered on Some");
        assert!(
            entry.contains(&expected),
            "prek hook `{}` does not run the provisioned binary\n  expected to contain: {expected}\n  entry: {entry}",
            hook.id
        );
    }
}
