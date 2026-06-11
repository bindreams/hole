use crate::repo_root::repo_root_from;

#[skuld::test]
fn finds_workspace_root_from_nested_member() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let member = root.path().join("crates").join("dev-console");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::write(member.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    let found = repo_root_from(&member).unwrap();
    assert_eq!(found.canonicalize().unwrap(), root.path().canonicalize().unwrap());
}

#[skuld::test]
fn rejects_tree_without_workspace_manifest() {
    let dir = tempfile::tempdir().unwrap();
    assert!(repo_root_from(dir.path()).is_err());
}

#[skuld::test]
fn ignores_non_workspace_manifests_on_the_way_up() {
    // A [package]-only Cargo.toml between the start dir and the real root
    // must not be mistaken for the workspace root.
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let mid = root.path().join("crates");
    std::fs::create_dir_all(mid.join("inner")).unwrap();
    std::fs::write(mid.join("Cargo.toml"), "[package]\nname = \"mid\"\n").unwrap();
    let found = repo_root_from(&mid.join("inner")).unwrap();
    assert_eq!(found.canonicalize().unwrap(), root.path().canonicalize().unwrap());
}
