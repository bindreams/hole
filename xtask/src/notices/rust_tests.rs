use std::path::Path;

use cargo_metadata::MetadataCommand;

use super::rust::{collect, read_metadata};
use super::{Component, Origin};

const WINDOWS: &str = "x86_64-pc-windows-msvc";
const MACOS: &str = "aarch64-apple-darwin";

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A package at `dir` named like it, `license` as given, with the dependency tables in `deps` (TOML).
fn package(root: &Path, dir: &str, name: &str, license: &str, extra: &str) {
    write(
        root,
        &format!("{dir}/Cargo.toml"),
        &format!(
            "[package]\nname = \"{name}\"\nversion = \"0.3.0\"\nedition = \"2021\"\nlicense = \"{license}\"\n\n{extra}\n"
        ),
    );
    write(root, &format!("{dir}/src/lib.rs"), "");
}

/// A workspace whose member `app` depends on one crate of every kind the generator must tell apart. The third-party
/// crates are path dependencies under `vendor/`, outside the workspace's members.
fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    write(
        path,
        "Cargo.toml",
        "[workspace]\nmembers = [\"app\", \"first-party\"]\nexclude = [\"vendor\"]\nresolver = \"2\"\n",
    );
    package(
        path,
        "app",
        "app",
        "MIT",
        "[dependencies]\n\
         normal-dep = { path = \"../vendor/normal-dep\" }\n\
         macro-dep = { path = \"../vendor/macro-dep\" }\n\
         first-party = { path = \"../first-party\" }\n\
         [build-dependencies]\n\
         build-dep = { path = \"../vendor/build-dep\" }\n\
         [dev-dependencies]\n\
         dev-dep = { path = \"../vendor/dev-dep\" }\n\
         [target.'cfg(windows)'.dependencies]\n\
         windows-dep = { path = \"../vendor/windows-dep\" }\n\
         [target.'cfg(target_os = \"macos\")'.dependencies]\n\
         macos-dep = { path = \"../vendor/macos-dep\" }\n",
    );
    package(
        path,
        "first-party",
        "first-party",
        "MIT",
        "[dependencies]\nunder-first-party = { path = \"../vendor/under-first-party\" }\n",
    );
    for name in [
        "normal-dep",
        "build-dep",
        "dev-dep",
        "windows-dep",
        "macos-dep",
        "under-first-party",
        "only-via-macro",
    ] {
        package(path, &format!("vendor/{name}"), name, "MIT OR Apache-2.0", "");
    }
    package(
        path,
        "vendor/macro-dep",
        "macro-dep",
        "MIT",
        "[lib]\nproc-macro = true\n[dependencies]\nonly-via-macro = { path = \"../only-via-macro\" }\n",
    );
    // `read_metadata` runs with `--locked`: the lock a checkout commits is there before it runs.
    MetadataCommand::new()
        .manifest_path(path.join("Cargo.toml"))
        .other_options(vec!["--offline".to_owned()])
        .exec()
        .expect("the fixture workspace resolves");
    root
}

fn names(components: &[Component]) -> Vec<&str> {
    components.iter().map(|c| c.name.as_str()).collect()
}

fn collected(root: &Path, triple: &str) -> Vec<Component> {
    let metadata = read_metadata(root, triple).unwrap();
    collect(&metadata, &["app"]).unwrap()
}

#[skuld::test]
fn proc_macro_crates_are_not_components() {
    let root = fixture();
    let found = collected(root.path(), WINDOWS);
    let names = names(&found);
    assert!(!names.contains(&"macro-dep"), "{names:?}");
    // Reachable only through the proc-macro, so it is not linked either.
    assert!(!names.contains(&"only-via-macro"), "{names:?}");
    assert!(names.contains(&"normal-dep"), "{names:?}");
}

#[skuld::test]
fn build_and_dev_dependencies_are_not_components() {
    let root = fixture();
    let found = collected(root.path(), WINDOWS);
    let names = names(&found);
    assert!(
        !names.contains(&"build-dep") && !names.contains(&"dev-dep"),
        "{names:?}"
    );
}

#[skuld::test]
fn workspace_members_are_not_components() {
    let root = fixture();
    let found = collected(root.path(), WINDOWS);
    let names = names(&found);
    assert!(!names.contains(&"app") && !names.contains(&"first-party"), "{names:?}");
    // A member is walked through: what it links is linked.
    assert!(names.contains(&"under-first-party"), "{names:?}");
}

#[skuld::test]
fn a_dependency_of_another_platform_is_not_a_component() {
    let root = fixture();
    let windows = collected(root.path(), WINDOWS);
    let macos = collected(root.path(), MACOS);
    assert!(names(&windows).contains(&"windows-dep") && !names(&windows).contains(&"macos-dep"));
    assert!(names(&macos).contains(&"macos-dep") && !names(&macos).contains(&"windows-dep"));
}

#[skuld::test]
fn a_component_carries_what_cargo_declares() {
    let root = fixture();
    let found = collected(root.path(), WINDOWS);
    let normal = found.iter().find(|c| c.name == "normal-dep").unwrap();
    assert_eq!(normal.version, "0.3.0");
    assert_eq!(normal.origin, Origin::Crate);
    assert_eq!(normal.license.as_deref(), Some("MIT OR Apache-2.0"));
    let dir = normal.source_dir.as_ref().unwrap();
    assert!(dir.join("Cargo.toml").is_file(), "{}", dir.display());
}

#[skuld::test]
fn a_root_that_is_not_in_the_workspace_fails_naming_it() {
    let root = fixture();
    let metadata = read_metadata(root.path(), WINDOWS).unwrap();
    let err = collect(&metadata, &["no-such-binary"]).unwrap_err();
    assert!(err.to_string().contains("no-such-binary"), "{err}");
}

#[skuld::test]
fn a_lock_that_is_out_of_date_fails_at_once_and_is_left_as_it_was() {
    let root = fixture();
    // A new dependency the lock does not know.
    package(root.path(), "vendor/newcomer", "newcomer", "MIT", "");
    let manifest = root.path().join("app/Cargo.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(
        &manifest,
        text.replace(
            "[dependencies]\n",
            "[dependencies]\nnewcomer = { path = \"../vendor/newcomer\" }\n",
        ),
    )
    .unwrap();
    let lock = root.path().join("Cargo.lock");
    let before = std::fs::read_to_string(&lock).unwrap();

    let err = read_metadata(root.path(), WINDOWS).unwrap_err();

    assert!(err.to_string().contains("--locked"), "{err}");
    assert_eq!(std::fs::read_to_string(&lock).unwrap(), before);
}

/// The metadata of the fixture with `edit` applied to its JSON.
fn edited_metadata(edit: impl FnOnce(&mut serde_json::Value)) -> cargo_metadata::Metadata {
    let root = fixture();
    let mut json = serde_json::to_value(read_metadata(root.path(), WINDOWS).unwrap()).unwrap();
    edit(&mut json);
    serde_json::from_value(json).unwrap()
}

/// Remove from the array at `path` of `json` the entries whose `id` contains `name`.
fn remove_by_id(json: &mut serde_json::Value, path: &str, name: &str) {
    let entries = json.pointer_mut(path).unwrap().as_array_mut().unwrap();
    let before = entries.len();
    entries.retain(|entry| !entry["id"].as_str().unwrap().contains(name));
    assert!(entries.len() < before, "the fixture has no {name} at {path}");
}

#[skuld::test]
fn a_package_of_the_resolve_graph_without_a_node_fails_naming_it() {
    let metadata = edited_metadata(|json| remove_by_id(json, "/resolve/nodes", "normal-dep"));
    let err = collect(&metadata, &["app"]).unwrap_err();
    assert!(matches!(err, super::NoticesError::Tool { .. }), "{err:?}");
    assert!(err.to_string().contains("normal-dep"), "{err}");
}

#[skuld::test]
fn a_package_of_the_resolve_graph_without_a_package_record_fails_naming_it() {
    let metadata = edited_metadata(|json| remove_by_id(json, "/packages", "normal-dep"));
    let err = collect(&metadata, &["app"]).unwrap_err();
    assert!(matches!(err, super::NoticesError::Tool { .. }), "{err:?}");
    assert!(err.to_string().contains("normal-dep"), "{err}");
}
