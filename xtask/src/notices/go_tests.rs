use std::path::Path;

use serde_json::{json, Value};

use super::go::{collect, nearest_licence_below};
use super::take::LicenceDirs;
use super::{Component, NoticesError, Origin};

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// One `go list -deps -json` record: a package of `module` (`Path`, `Version`, `Dir`) in `dir`.
fn package(import_path: &str, dir: &Path, module: Value) -> Value {
    json!({"ImportPath": import_path, "Dir": dir, "DepOnly": true, "Module": module})
}

/// What `go list` prints: one JSON object after another, no separators.
fn listing(records: &[Value]) -> String {
    records.iter().map(|r| format!("{r:#}\n")).collect()
}

fn module(path: &str, version: &str, dir: &Path) -> Value {
    json!({"Path": path, "Version": version, "Dir": dir})
}

/// A repository that is nowhere the listing's directories are, at a source address of its own.
fn collect_in_repo(listing: &str) -> Result<Vec<Component>, NoticesError> {
    collect(listing, Path::new("/not/a/repo"), REPO_URL)
}

const REPO_URL: &str = "https://example.com/tree/releases/v1";

fn named<'a>(components: &'a [Component], name: &str) -> &'a Component {
    components.iter().find(|c| c.name == name).unwrap_or_else(|| {
        panic!(
            "no component {name}: {:?}",
            components.iter().map(|c| &c.name).collect::<Vec<_>>()
        )
    })
}

#[skuld::test]
fn packages_are_mapped_to_their_modules() {
    let cache = tempfile::tempdir().unwrap();
    let base = cache.path();
    write(base, "x/net@v0.1.0/LICENSE", "BSD");
    write(base, "x/net@v0.1.0/idna/idna.go", "package idna");
    write(base, "x/net@v0.1.0/http/http.go", "package http");
    let net = module("golang.org/x/net", "v0.1.0", &base.join("x/net@v0.1.0"));
    let records = [
        package("golang.org/x/net/idna", &base.join("x/net@v0.1.0/idna"), net.clone()),
        package("golang.org/x/net/http", &base.join("x/net@v0.1.0/http"), net),
    ];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert_eq!(
        found.len(),
        1,
        "two packages of one module are one component: {found:?}"
    );
    let net = &found[0];
    assert_eq!(
        (net.name.as_str(), net.version.as_str()),
        ("golang.org/x/net", "v0.1.0")
    );
    assert_eq!(net.origin, Origin::GoModule);
    assert_eq!(net.source_dir.as_deref(), Some(base.join("x/net@v0.1.0").as_path()));
    assert_eq!(net.license, None, "go list declares no licence");
}

#[skuld::test]
fn the_main_module_is_not_a_component() {
    let tree = tempfile::tempdir().unwrap();
    let main = json!({"Path": "example.com/app", "Main": true, "Dir": tree.path()});
    let records = [package("example.com/app", tree.path(), main)];
    assert!(collect_in_repo(&listing(&records)).unwrap().is_empty());
}

#[skuld::test]
fn a_replaced_module_is_read_from_its_local_directory() {
    let tree = tempfile::tempdir().unwrap();
    let base = tree.path();
    write(base, "third_party/core/LICENSE", "MIT");
    write(base, "third_party/core/common/common.go", "package common");
    let replaced = json!({
        "Path": "github.com/v2fly/v2ray-core/v5", "Version": "v5.52.0",
        // `Dir` of the module a replacement points at: the replacement's directory is the one that holds the source.
        "Dir": base.join("module-cache-that-is-not-used"),
        "Replace": {"Path": "./third_party/core", "Dir": base.join("third_party/core")},
    });
    let records = [package(
        "github.com/v2fly/v2ray-core/v5/common",
        &base.join("third_party/core/common"),
        replaced,
    )];
    let found = collect(&listing(&records), base, REPO_URL).unwrap();
    let core = named(&found, "github.com/v2fly/v2ray-core/v5");
    assert_eq!(core.version, "v5.52.0");
    assert_eq!(
        core.source_dir.as_deref(),
        Some(base.join("third_party/core").as_path())
    );
}

#[skuld::test]
fn a_package_with_its_own_licence_adds_a_component() {
    let cache = tempfile::tempdir().unwrap();
    let base = cache.path();
    let root = base.join("klauspost/compress@v1.17.4");
    write(&root, "LICENSE", "BSD root");
    write(&root, "zstd/internal/xxhash/LICENSE.txt", "MIT xxhash");
    write(&root, "zstd/internal/xxhash/xxhash.go", "package xxhash");
    // A package below the nested licence still belongs to it; a package with no licence between it and the root does not.
    write(&root, "zstd/internal/xxhash/deeper/doc.go", "package deeper");
    let compress = module("github.com/klauspost/compress", "v1.17.4", &root);
    let records = [
        package(
            "github.com/klauspost/compress/zstd",
            &root.join("zstd"),
            compress.clone(),
        ),
        package(
            "github.com/klauspost/compress/zstd/internal/xxhash",
            &root.join("zstd/internal/xxhash"),
            compress.clone(),
        ),
        package(
            "github.com/klauspost/compress/zstd/internal/xxhash/deeper",
            &root.join("zstd/internal/xxhash/deeper"),
            compress,
        ),
    ];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    let nested = named(&found, "github.com/klauspost/compress/zstd/internal/xxhash");
    assert_eq!(nested.origin, Origin::GoPackage);
    assert_eq!(nested.version, "v1.17.4");
    assert_eq!(
        nested.source_dir.as_deref(),
        Some(root.join("zstd/internal/xxhash").as_path())
    );
    assert_eq!(named(&found, "github.com/klauspost/compress").origin, Origin::GoModule);
}

#[skuld::test]
fn a_nested_licence_with_no_linked_package_under_it_adds_nothing() {
    let cache = tempfile::tempdir().unwrap();
    let root = cache.path().join("m@v1.0.0");
    write(&root, "LICENSE", "root");
    write(&root, "unlinked/LICENSE", "elsewhere");
    let m = module("example.com/m", "v1.0.0", &root);
    let records = [package("example.com/m", &root, m)];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[skuld::test]
fn standard_packages_add_no_component() {
    // The `declared:` entry for the Go standard library covers them: its version is the toolchain's, not the listing's.
    let goroot = tempfile::tempdir().unwrap();
    write(goroot.path(), "LICENSE", "Go");
    let std_package = |import_path: &str| {
        json!({"ImportPath": import_path, "Dir": goroot.path().join("src").join(import_path),
               "Standard": true, "Root": goroot.path()})
    };
    let records = [
        std_package("fmt"),
        std_package("net/http"),
        std_package("internal/goarch"),
    ];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert!(found.is_empty(), "{found:?}");
}

#[skuld::test]
fn a_module_that_was_not_downloaded_fails_naming_the_command() {
    let records = [json!({"ImportPath": "example.com/m", "Module": {"Path": "example.com/m", "Version": "v1.0.0"}})];
    let err = collect_in_repo(&listing(&records)).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("example.com/m") && message.contains("cargo xtask ex-ray"),
        "{message}"
    );
}

#[skuld::test]
fn output_that_is_not_go_list_json_fails() {
    assert!(collect_in_repo("not json").is_err());
}

#[skuld::test]
fn a_replaced_module_is_a_modified_copy_at_its_directory_in_this_repository() {
    let tree = tempfile::tempdir().unwrap();
    let base = tree.path();
    write(base, "crates/app/third_party/core/LICENSE", "MIT");
    write(base, "crates/app/third_party/core/inner/LICENSE", "BSD");
    write(base, "crates/app/third_party/core/inner/inner.go", "package inner");
    write(base, "crates/app/third_party/core/common/common.go", "package common");
    let copy = base.join("crates/app/third_party/core");
    let replaced = json!({
        "Path": "github.com/v2fly/v2ray-core/v5", "Version": "v5.52.0",
        "Dir": base.join("module-cache-that-is-not-used"),
        "Replace": {"Path": "./third_party/core", "Dir": copy},
    });
    let records = [
        package(
            "github.com/v2fly/v2ray-core/v5/common",
            &copy.join("common"),
            replaced.clone(),
        ),
        package("github.com/v2fly/v2ray-core/v5/inner", &copy.join("inner"), replaced),
    ];

    let found = collect(&listing(&records), base, REPO_URL).unwrap();

    let core = named(&found, "github.com/v2fly/v2ray-core/v5");
    assert!(core.modified_copy);
    assert_eq!(
        core.url.as_deref(),
        Some("https://example.com/tree/releases/v1/crates/app/third_party/core")
    );
    assert_eq!(core.label(), "modified copy of github.com/v2fly/v2ray-core/v5 v5.52.0");
    let inner = named(&found, "github.com/v2fly/v2ray-core/v5/inner");
    assert!(inner.modified_copy);
    assert_eq!(
        inner.url.as_deref(),
        Some("https://example.com/tree/releases/v1/crates/app/third_party/core/inner")
    );
}

#[skuld::test]
fn a_module_replaced_by_another_modules_version_is_that_module_labelled_as_the_replacement() {
    let cache = tempfile::tempdir().unwrap();
    let fork = cache.path().join("fork@v1.0.1");
    write(&fork, "LICENSE", "MIT");
    write(&fork, "x.go", "package x");
    write(&fork, "sub/LICENSE", "sub");
    write(&fork, "sub/y.go", "package sub");
    let replaced = json!({
        "Path": "example.com/m", "Version": "v1.0.0", "Dir": cache.path().join("m@v1.0.0"),
        "Replace": {"Path": "example.com/fork", "Version": "v1.0.1", "Dir": fork},
    });
    let records = [
        package("example.com/m", &fork, replaced.clone()),
        package("example.com/m/sub", &fork.join("sub"), replaced),
    ];

    let found = collect_in_repo(&listing(&records)).unwrap();

    // What is linked is the fork's code at the fork's version: it is named, versioned and addressed as the fork.
    assert!(found.iter().all(|c| c.name != "example.com/m"), "{found:?}");
    let fork_module = named(&found, "example.com/fork");
    assert_eq!(fork_module.version, "v1.0.1");
    assert!(!fork_module.modified_copy);
    assert_eq!(
        fork_module.url.as_deref(),
        Some("https://pkg.go.dev/example.com/fork@v1.0.1")
    );
    assert_eq!(
        fork_module.label(),
        "example.com/fork v1.0.1 (replacing example.com/m v1.0.0)"
    );
    let nested = named(&found, "example.com/fork/sub");
    assert_eq!(nested.version, "v1.0.1");
    assert_eq!(
        nested.url.as_deref(),
        Some("https://pkg.go.dev/example.com/fork@v1.0.1")
    );

    // An override for the module is keyed to the name that is linked.
    let config = super::config::Config::parse(
        "licenses:
  - {id: MIT, text: own}
overrides:
  - {name: example.com/fork, ecosystem: go, version: v1.0.1, license: MIT}
  - {name: example.com/m, ecosystem: go, version: v1.0.0, license: MIT}
",
    )
    .unwrap();
    assert_eq!(config.overrides_for(fork_module).count(), 1);
    assert_eq!(
        config.overrides_for(fork_module).next().unwrap().name,
        "example.com/fork"
    );
}

#[skuld::test]
fn a_replacement_outside_the_repository_fails() {
    let tree = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    write(elsewhere.path(), "x.go", "package x");
    let replaced = json!({
        "Path": "example.com/m", "Version": "v1.0.0", "Dir": tree.path().join("unused"),
        "Replace": {"Path": "../elsewhere", "Dir": elsewhere.path()},
    });
    let records = [package("example.com/m", elsewhere.path(), replaced)];

    let err = collect(&listing(&records), tree.path(), REPO_URL).unwrap_err();

    assert!(err.to_string().contains("example.com/m"), "{err}");
}

#[skuld::test]
fn a_package_directory_with_a_source_file_named_like_a_licence_adds_nothing() {
    let cache = tempfile::tempdir().unwrap();
    let root = cache.path().join("m@v1.0.0");
    write(&root, "LICENSE", "root");
    write(&root, "sub/license.go", "package sub");
    write(&root, "sub/copying_test.go", "package sub");
    let m = module("example.com/m", "v1.0.0", &root);
    let records = [package("example.com/m/sub", &root.join("sub"), m)];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[skuld::test]
fn the_walk_for_nested_licences_decides_by_name_and_reads_nothing() {
    let cache = tempfile::tempdir().unwrap();
    let root = cache.path().join("m@v1.0.0");
    write(&root, "LICENSE", "root");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    // Not UTF-8: reading it to find out whether it is a licence file would fail the walk.
    std::fs::write(root.join("sub/LICENSE"), [0xff, 0xfe, 0xfd]).unwrap();
    let m = module("example.com/m", "v1.0.0", &root);
    let records = [package("example.com/m/sub", &root.join("sub"), m)];
    let found = collect_in_repo(&listing(&records)).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
}

#[skuld::test]
fn a_directory_is_listed_once_however_many_packages_walk_through_it() {
    let cache = tempfile::tempdir().unwrap();
    let root = cache.path().join("m@v1.0.0");
    write(&root, "LICENSE", "root");
    write(&root, "a/x/f.go", "package f");
    write(&root, "a/y/f.go", "package f");

    let mut finder = LicenceDirs::default();
    assert_eq!(
        nearest_licence_below(&root, &root.join("a/x"), &mut finder).unwrap(),
        None
    );
    // `a` gains a licence after the finder listed it: a second walk through `a` does not list it again.
    write(&root, "a/LICENSE", "late");
    assert_eq!(
        nearest_licence_below(&root, &root.join("a/y"), &mut finder).unwrap(),
        None
    );

    // A finder that has not listed `a` yet finds it.
    assert_eq!(
        nearest_licence_below(&root, &root.join("a/y"), &mut LicenceDirs::default()).unwrap(),
        Some(root.join("a"))
    );
}

#[skuld::test]
fn a_package_directory_outside_its_modules_root_fails_naming_both() {
    let cache = tempfile::tempdir().unwrap();
    let root = cache.path().join("m@v1.0.0");
    let elsewhere = cache.path().join("other@v2.0.0/pkg");
    let err = nearest_licence_below(&root, &elsewhere, &mut LicenceDirs::default()).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("m@v1.0.0") && message.contains("other@v2.0.0"),
        "{message}"
    );
}

/// A module `path` at `version` replaced by the version `fork_version` of `fork`, whose source is in `dir`.
fn replaced_by_a_fork(path: &str, version: &str, fork: &str, fork_version: &str, dir: &Path) -> Value {
    json!({
        "Path": path, "Version": version, "Dir": "/not/downloaded",
        "Replace": {"Path": fork, "Version": fork_version, "Dir": dir},
    })
}

#[skuld::test]
fn a_module_replaced_by_a_version_that_is_also_required_is_two_components() {
    let cache = tempfile::tempdir().unwrap();
    let c = cache.path().join("c@v1.0.0");
    write(&c, "LICENSE", "MIT");
    write(&c, "c.go", "package c");
    write(&c, "sub/LICENSE", "sub");
    write(&c, "sub/s.go", "package sub");
    let replaced = replaced_by_a_fork("example.com/a", "v0.1.0", "example.com/c", "v1.0.0", &c);
    let required = module("example.com/c", "v1.0.0", &c);
    let records = [
        package("example.com/a", &c, replaced.clone()),
        package("example.com/a/sub", &c.join("sub"), replaced),
        package("example.com/c", &c, required.clone()),
        package("example.com/c/sub", &c.join("sub"), required),
    ];

    let found = collect_in_repo(&listing(&records)).unwrap();

    let labels: Vec<String> = found.iter().map(|c| c.label()).collect();
    assert_eq!(
        labels,
        [
            "example.com/c v1.0.0",
            "example.com/c v1.0.0 (replacing example.com/a v0.1.0)",
            "example.com/c/sub v1.0.0",
            "example.com/c/sub v1.0.0 (replacing example.com/a v0.1.0)",
        ]
    );
}

#[skuld::test]
fn two_modules_replaced_by_one_fork_are_two_components() {
    let cache = tempfile::tempdir().unwrap();
    let fork = cache.path().join("fork@v1.0.0");
    write(&fork, "LICENSE", "MIT");
    write(&fork, "f.go", "package f");
    let records = [
        package(
            "example.com/a",
            &fork,
            replaced_by_a_fork("example.com/a", "v0.1.0", "example.com/fork", "v1.0.0", &fork),
        ),
        package(
            "example.com/b",
            &fork,
            replaced_by_a_fork("example.com/b", "v0.2.0", "example.com/fork", "v1.0.0", &fork),
        ),
    ];

    let found = collect_in_repo(&listing(&records)).unwrap();

    let labels: Vec<String> = found.iter().map(|c| c.label()).collect();
    assert_eq!(
        labels,
        [
            "example.com/fork v1.0.0 (replacing example.com/a v0.1.0)",
            "example.com/fork v1.0.0 (replacing example.com/b v0.2.0)",
        ]
    );
}
