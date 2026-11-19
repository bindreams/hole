use std::path::Path;

use serde_json::json;

use super::npm::{collect, collect_installed};
use super::{Component, NoticesError, Origin};
use crate::manifest::{Arch, Os, Platform};

const WINDOWS: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MACOS: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};

/// What npm leaves in `node_modules` for `installed` (`(lock key, version, dev)`): a folder per package with its
/// `package.json`, and `.package-lock.json`, its record of the packages that are there.
fn install(modules: &Path, installed: &[(&str, &str, bool)]) -> String {
    let mut packages = serde_json::Map::new();
    for (key, version, dev) in installed {
        let dir = modules.join(key.strip_prefix("node_modules/").unwrap_or(key));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            json!({"name": "x", "version": version}).to_string(),
        )
        .unwrap();
        let mut package = json!({"version": version});
        if *dev {
            package["dev"] = json!(true);
        }
        packages.insert((*key).to_owned(), package);
    }
    let record = json!({"name": "app", "lockfileVersion": 3, "requires": true, "packages": packages}).to_string();
    std::fs::write(modules.join(".package-lock.json"), &record).unwrap();
    record
}

const LOCK: &str = r#"{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"left-pad": "^1", "@scope/ui": "^2"}, "devDependencies": {"vite": "^8"}},
    "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"},
    "node_modules/@scope/ui": {"version": "2.1.0", "license": "Apache-2.0 OR MIT"},
    "node_modules/@scope/ui/node_modules/inner": {"version": "0.4.0", "license": "ISC"},
    "node_modules/vite": {"version": "8.0.3", "dev": true, "license": "MIT"},
    "node_modules/vite/node_modules/esbuild": {"version": "0.25.0", "dev": true, "license": "MIT"},
    "node_modules/no-licence-field": {"version": "1.0.0"}
  }
}"#;

const EVERYTHING: [(&str, &str, bool); 6] = [
    ("node_modules/left-pad", "1.3.0", false),
    ("node_modules/@scope/ui", "2.1.0", false),
    ("node_modules/@scope/ui/node_modules/inner", "0.4.0", false),
    ("node_modules/vite", "8.0.3", true),
    ("node_modules/vite/node_modules/esbuild", "0.25.0", true),
    ("node_modules/no-licence-field", "1.0.0", false),
];

/// The components of `lock` over what `install` left in a fresh `node_modules`, read on the platform they are for.
fn collected(lock: &str, installed: &[(&str, &str, bool)]) -> Result<Vec<Component>, NoticesError> {
    let modules = tempfile::tempdir().unwrap();
    let record = install(modules.path(), installed);
    collect_installed(lock, &record, modules.path(), &WINDOWS, Some(WINDOWS))
}

fn names(components: &[Component]) -> Vec<&str> {
    components.iter().map(|c| c.name.as_str()).collect()
}

/// Fails unless `result` is the `Provision` of the `npm-install` target and its message names every one of `words`.
fn assert_provision(result: Result<Vec<Component>, NoticesError>, words: &[&str]) {
    let err = result.unwrap_err();
    assert!(matches!(err, NoticesError::Provision { .. }), "{err:?}");
    let message = err.to_string();
    for word in words.iter().chain(&["npm-install"]) {
        assert!(message.contains(word), "{word}: {message}");
    }
}

#[skuld::test]
fn production_dependencies_are_components_and_dev_ones_are_not() {
    let found = collected(LOCK, &EVERYTHING).unwrap();
    assert_eq!(names(&found), ["@scope/ui", "inner", "left-pad", "no-licence-field"]);
}

#[skuld::test]
fn a_component_carries_what_the_lock_declares() {
    let modules = tempfile::tempdir().unwrap();
    let record = install(modules.path(), &EVERYTHING);
    let found = collect_installed(LOCK, &record, modules.path(), &WINDOWS, Some(WINDOWS)).unwrap();
    let ui = found.iter().find(|c| c.name == "@scope/ui").unwrap();
    assert_eq!(ui.version, "2.1.0");
    assert_eq!(ui.origin, Origin::Npm);
    assert_eq!(ui.license.as_deref(), Some("Apache-2.0 OR MIT"));
    assert_eq!(
        ui.source_dir.as_deref(),
        Some(modules.path().join("@scope/ui").as_path())
    );
    let inner = found.iter().find(|c| c.name == "inner").unwrap();
    assert_eq!(
        inner.source_dir.as_deref(),
        Some(modules.path().join("@scope/ui/node_modules/inner").as_path())
    );
    let bare = found.iter().find(|c| c.name == "no-licence-field").unwrap();
    assert_eq!(bare.license, None);
}

#[skuld::test]
fn a_lock_that_is_not_a_v2_or_later_lock_fails() {
    let err = collect_installed(
        r#"{"lockfileVersion": 1, "dependencies": {}}"#,
        r#"{"lockfileVersion": 3, "packages": {}}"#,
        Path::new("node_modules"),
        &WINDOWS,
        Some(WINDOWS),
    )
    .unwrap_err();
    assert!(err.to_string().contains("package-lock.json"), "{err}");
}

const OPTIONAL_LOCK: &str = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/native-win-x64": {"version": "1.0.0", "optional": true, "os": ["win32"], "cpu": ["x64"]},
    "node_modules/native-darwin-arm64": {"version": "1.0.0", "optional": true, "os": ["darwin"], "cpu": ["arm64"]},
    "node_modules/native-musl": {"version": "1.0.0", "optional": true, "os": ["linux"], "libc": ["musl"]},
    "node_modules/helper-of-a-skipped-package": {"version": "1.0.0", "optional": true},
    "node_modules/dev-native": {"version": "1.0.0", "dev": true, "optional": true, "os": ["darwin"]},
    "node_modules/required": {"version": "1.0.0"}
  }
}"#;

#[skuld::test]
fn a_package_the_lock_marks_optional_and_npm_skipped_is_no_concern() {
    // npm skipped the darwin and musl packages and the helper only they need (which the lock marks `optional`, with no
    // `os`, `cpu` or `libc` of its own to tell it by), and a dev package that is optional too.
    let installed = [
        ("node_modules/native-win-x64", "1.0.0", false),
        ("node_modules/required", "1.0.0", false),
    ];
    let found = collected(OPTIONAL_LOCK, &installed).unwrap();
    assert_eq!(names(&found), ["native-win-x64", "required"]);
}

#[skuld::test]
fn an_optional_package_npm_did_install_is_a_component_whatever_its_restrictions_say() {
    let installed = [
        ("node_modules/native-musl", "1.0.0", false),
        ("node_modules/helper-of-a-skipped-package", "1.0.0", false),
        ("node_modules/required", "1.0.0", false),
    ];
    let found = collected(OPTIONAL_LOCK, &installed).unwrap();
    assert_eq!(
        names(&found),
        ["helper-of-a-skipped-package", "native-musl", "required"]
    );
}

#[skuld::test]
fn an_installed_package_of_another_version_than_the_lock_fails_naming_the_npm_install_target() {
    for at in [0, 3] {
        let mut installed = EVERYTHING;
        installed[at].1 = "9.9.9";
        let name = installed[at].0.strip_prefix("node_modules/").unwrap();
        assert_provision(collected(LOCK, &installed), &[name, "9.9.9"]);
    }
    // Both versions are named.
    let mut installed = EVERYTHING;
    installed[0] = ("node_modules/left-pad", "1.2.0", false);
    assert_provision(collected(LOCK, &installed), &["left-pad", "1.3.0", "1.2.0"]);
}

#[skuld::test]
fn an_installed_package_the_lock_does_not_list_fails_dev_or_not() {
    for dev in [false, true] {
        let mut installed = EVERYTHING.to_vec();
        installed.push(("node_modules/stray", "9.9.9", dev));
        assert_provision(collected(LOCK, &installed), &["stray"]);
    }
}

#[skuld::test]
fn a_package_the_lock_ships_as_production_and_the_record_marks_dev_fails() {
    let mut installed = EVERYTHING;
    installed[0] = ("node_modules/left-pad", "1.3.0", true);
    assert_provision(collected(LOCK, &installed), &["left-pad", "dev"]);
}

#[skuld::test]
fn a_package_the_lock_marks_dev_and_the_record_does_not_fails() {
    let mut installed = EVERYTHING;
    installed[3] = ("node_modules/vite", "8.0.3", false);
    assert_provision(collected(LOCK, &installed), &["vite", "dev"]);
}

#[skuld::test]
fn a_package_the_lock_lists_as_production_and_npm_did_not_install_fails() {
    let installed: Vec<_> = EVERYTHING
        .iter()
        .copied()
        .filter(|(key, ..)| *key != "node_modules/left-pad")
        .collect();
    assert_provision(collected(LOCK, &installed), &["left-pad"]);
}

/// A lock with `required` and `left-out`, which carries `flag` (`"dev": true`, `"optional": true` or
/// `"devOptional": true`), and what npm installed of it when it left `left-out` out.
fn lock_with_a_package_npm_may_leave_out(flag: &str) -> String {
    format!(
        r#"{{"lockfileVersion": 3, "packages": {{
        "node_modules/required": {{"version": "1.0.0"}},
        "node_modules/left-out": {{"version": "1.0.0", {flag}}}}}}}"#
    )
}

const ONLY_REQUIRED: [(&str, &str, bool); 1] = [("node_modules/required", "1.0.0", false)];

#[skuld::test]
fn a_package_the_lock_marks_dev_or_optional_or_dev_optional_may_be_left_out_of_the_install() {
    // npm omits dev packages from a production-only install, and platform-bound ones on another platform.
    for flag in [r#""dev": true"#, r#""optional": true"#, r#""devOptional": true"#] {
        let found = collected(&lock_with_a_package_npm_may_leave_out(flag), &ONLY_REQUIRED)
            .unwrap_or_else(|e| panic!("{flag}: {e}"));
        assert_eq!(names(&found), ["required"], "{flag}");
    }
}

#[skuld::test]
fn a_dev_optional_package_npm_did_install_is_a_component() {
    // It is not dev-only: a non-dev package asks for it, as an optional dependency.
    let lock = lock_with_a_package_npm_may_leave_out(r#""devOptional": true"#);
    let installed = [
        ("node_modules/left-out", "1.0.0", false),
        ("node_modules/required", "1.0.0", false),
    ];
    assert_eq!(names(&collected(&lock, &installed).unwrap()), ["left-out", "required"]);
}

#[skuld::test]
fn a_package_the_lock_marks_with_none_of_the_three_cannot_be_left_out_of_the_install() {
    let lock = lock_with_a_package_npm_may_leave_out(r#""peer": true"#);
    assert_provision(collected(&lock, &ONLY_REQUIRED), &["left-out"]);
}

#[skuld::test]
fn a_component_whose_folder_is_gone_or_holds_another_version_fails_naming_the_npm_install_target() {
    let modules = tempfile::tempdir().unwrap();
    let record = install(modules.path(), &EVERYTHING);
    let read = || collect_installed(LOCK, &record, modules.path(), &WINDOWS, Some(WINDOWS));
    let manifest = modules.path().join("left-pad/package.json");

    std::fs::write(&manifest, json!({"name": "left-pad", "version": "1.2.9"}).to_string()).unwrap();
    assert_provision(read(), &["left-pad", "1.3.0", "1.2.9"]);

    std::fs::remove_file(&manifest).unwrap();
    assert_provision(read(), &["left-pad"]);

    std::fs::remove_dir_all(modules.path().join("left-pad")).unwrap();
    assert_provision(read(), &["left-pad"]);
}

#[skuld::test]
fn a_dev_package_whose_folder_is_gone_is_no_concern() {
    let modules = tempfile::tempdir().unwrap();
    let record = install(modules.path(), &EVERYTHING);
    std::fs::remove_dir_all(modules.path().join("vite")).unwrap();
    collect_installed(LOCK, &record, modules.path(), &WINDOWS, Some(WINDOWS)).unwrap();
}

#[skuld::test]
fn a_record_that_does_not_parse_fails_naming_the_file() {
    let modules = tempfile::tempdir().unwrap();
    let err = collect_installed(LOCK, "not json", modules.path(), &WINDOWS, Some(WINDOWS)).unwrap_err();
    assert!(err.to_string().contains(".package-lock.json"), "{err}");
}

#[skuld::test]
fn no_node_modules_fails_naming_the_npm_install_target() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("package-lock.json"), LOCK).unwrap();
    let err = collect(repo.path(), &WINDOWS).unwrap_err();
    assert!(matches!(err, NoticesError::Provision { .. }), "{err:?}");
    assert!(err.to_string().contains("npm-install"), "{err}");
}

#[skuld::test]
fn a_node_modules_without_npms_record_fails_naming_the_npm_install_target() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("package-lock.json"), LOCK).unwrap();
    std::fs::create_dir(repo.path().join("node_modules")).unwrap();
    let err = collect(repo.path(), &WINDOWS).unwrap_err();
    assert!(matches!(err, NoticesError::Provision { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains(".package-lock.json") && message.contains("npm-install"),
        "{message}"
    );
}

#[skuld::test]
fn the_components_are_read_from_the_repository_files() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("package-lock.json"), LOCK).unwrap();
    std::fs::create_dir(repo.path().join("node_modules")).unwrap();
    install(&repo.path().join("node_modules"), &EVERYTHING);
    let host = Platform::host().expect("the tests run on a supported host");
    let found = collect(repo.path(), &host).unwrap();
    assert_eq!(names(&found), ["@scope/ui", "inner", "left-pad", "no-licence-field"]);
}

/// A lock with one `optional` production package, `native-win-x64`, and what npm installed of it on Windows.
const NATIVE_LOCK: &str = r#"{"lockfileVersion": 3, "packages": {
    "node_modules/native-win-x64": {"version": "1.0.0", "optional": true, "os": ["win32"]},
    "node_modules/required": {"version": "1.0.0"}}}"#;

const NATIVE_INSTALLED: [(&str, &str, bool); 2] = [
    ("node_modules/native-win-x64", "1.0.0", false),
    ("node_modules/required", "1.0.0", false),
];

fn read_for(
    target: &Platform,
    host: Option<Platform>,
    lock: &str,
    installed: &[(&str, &str, bool)],
) -> Result<Vec<Component>, NoticesError> {
    let modules = tempfile::tempdir().unwrap();
    let record = install(modules.path(), installed);
    collect_installed(lock, &record, modules.path(), target, host)
}

#[skuld::test]
fn a_target_that_is_not_the_host_cannot_be_read_when_a_production_package_is_optional() {
    for host in [Some(WINDOWS), None] {
        let err = read_for(&MACOS, host, NATIVE_LOCK, &NATIVE_INSTALLED).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, NoticesError::Tool { .. }), "{err:?}");
        assert!(
            message.contains("native-win-x64") && message.contains("darwin/arm64") && message.contains("platform"),
            "{message}"
        );
    }
}

#[skuld::test]
fn a_target_that_is_not_the_host_cannot_be_read_when_a_package_is_dev_optional() {
    // Both a dev dependency and an optional one of a non-dev package: npm installs it only where it fits, like `optional`.
    let lock = NATIVE_LOCK.replace(r#""optional": true"#, r#""devOptional": true"#);
    for host in [Some(WINDOWS), None] {
        let err = read_for(&MACOS, host, &lock, &NATIVE_INSTALLED).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, NoticesError::Tool { .. }), "{err:?}");
        assert!(
            message.contains("native-win-x64") && message.contains("darwin/arm64"),
            "{message}"
        );
    }
}

#[skuld::test]
fn a_target_that_is_not_the_host_is_read_when_no_production_package_is_optional() {
    // The lock's only optional package is a dev one: the host's set is the target's.
    let lock = r#"{"lockfileVersion": 3, "packages": {
        "node_modules/required": {"version": "1.0.0"},
        "node_modules/dev-native": {"version": "1.0.0", "dev": true, "optional": true}}}"#;
    let installed = [("node_modules/required", "1.0.0", false)];
    let found = read_for(&MACOS, Some(WINDOWS), lock, &installed).unwrap();
    assert_eq!(names(&found), ["required"]);
}

#[skuld::test]
fn the_host_reads_its_own_set_whatever_the_lock_holds() {
    let found = read_for(&WINDOWS, Some(WINDOWS), NATIVE_LOCK, &NATIVE_INSTALLED).unwrap();
    assert_eq!(names(&found), ["native-win-x64", "required"]);
}
