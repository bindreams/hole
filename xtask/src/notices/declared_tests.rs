use std::path::Path;

use super::config::Config;
use super::declared;
use super::{NoticesError, Origin};
use crate::manifest::{Arch, Os, Platform};

const WINDOWS: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MACOS: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};

fn write(root: &Path, path: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "x").unwrap();
}

/// A repository with one font, the Wintun files, and a folder of licence files for each.
fn repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "ui/fonts/inter.woff2");
    write(root.path(), ".cache/wintun/wintun.dll");
    write(root.path(), ".cache/wintun/LICENSE.txt");
    root
}

const FONT_ENTRY: &str = "
  - name: Inter
    version: \"4.001\"
    license: OFL-1.1
    files: [ui/fonts/inter.woff2]
    texts: [{license: OFL-1.1, notice: \"Copyright 2016 The Inter Project Authors\", source: \"https://example.com\"}]
";
const WINTUN_ENTRY: &str = "
  - name: Wintun
    version: \"0.14.1\"
    license: LicenseRef-Wintun
    platforms: [windows]
    files: [.cache/wintun/wintun.dll]
    dir: .cache/wintun
    url: https://www.wintun.net/
";

/// `declared::collect` as the generator calls it: with the config of the platform's artifact.
fn collect(platform: &Platform, repo_root: &Path, config: &Config) -> Result<Vec<super::Component>, NoticesError> {
    declared::collect(platform, repo_root, &config.for_platform(platform))
}

fn config(entries: &str) -> Config {
    Config::parse(&format!(
        "licenses:\n  - {{id: OFL-1.1, text: own}}\n  - {{id: LicenseRef-Wintun, text: own}}\n  - {{id: MIT, text: own}}\n  - {{id: Apache-2.0, text: shared}}\n  - {{id: BSD-3-Clause, text: own}}\ndeclared: {entries}"
    ))
    .unwrap()
}

#[skuld::test]
fn declared_entries_are_components_with_their_folder_and_licence() {
    let root = repo();
    let found = collect(&WINDOWS, root.path(), &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}"))).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    let wintun = found.iter().find(|c| c.name == "Wintun").unwrap();
    assert_eq!(wintun.origin, Origin::Declared);
    assert_eq!(wintun.version, "0.14.1");
    assert_eq!(wintun.license.as_deref(), Some("LicenseRef-Wintun"));
    assert_eq!(
        wintun.source_dir.as_deref(),
        Some(root.path().join(".cache/wintun").as_path())
    );
    assert_eq!(wintun.url.as_deref(), Some("https://www.wintun.net/"));
}

#[skuld::test]
fn a_font_file_without_an_entry_fails() {
    let root = repo();
    let err = collect(&MACOS, root.path(), &config("[]")).unwrap_err();
    assert!(matches!(err, NoticesError::UnlistedFile { .. }), "{err:?}");
    assert!(err.to_string().contains("ui/fonts/inter.woff2"), "{err}");
}

#[skuld::test]
fn a_font_in_a_subfolder_without_an_entry_fails() {
    let root = repo();
    write(root.path(), "ui/fonts/more/inter-italic.woff2");
    let err = collect(&WINDOWS, root.path(), &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}"))).unwrap_err();
    assert!(matches!(err, NoticesError::UnlistedFile { .. }), "{err:?}");
    assert!(err.to_string().contains("ui/fonts/more/inter-italic.woff2"), "{err}");
}

#[skuld::test]
fn a_shipped_binary_without_an_entry_fails() {
    let root = repo();
    // The font is covered; `wintun.dll` is not.
    let err = collect(&WINDOWS, root.path(), &config(FONT_ENTRY)).unwrap_err();
    assert!(matches!(err, NoticesError::UnlistedFile { .. }), "{err:?}");
    assert!(err.to_string().contains("wintun.dll"), "{err}");
}

#[skuld::test]
fn an_entry_that_matches_nothing_fails() {
    let root = repo();
    std::fs::remove_file(root.path().join("ui/fonts/inter.woff2")).unwrap();
    write(root.path(), "ui/fonts/other.woff2");
    let both = format!("{FONT_ENTRY}{WINTUN_ENTRY}");
    let err = collect(&WINDOWS, root.path(), &config(&both)).unwrap_err();
    assert!(matches!(err, NoticesError::UnusedEntry { .. }), "{err:?}");
    assert!(
        err.to_string().contains("Inter") && err.to_string().contains("ui/fonts/inter.woff2"),
        "{err}"
    );
}

#[skuld::test]
fn an_entry_whose_folder_does_not_exist_fails() {
    let root = repo();
    std::fs::remove_dir_all(root.path().join(".cache/wintun")).unwrap();
    write(root.path(), ".cache/elsewhere/x");
    let entry = WINTUN_ENTRY.replace("files: [.cache/wintun/wintun.dll]", "files: [.cache/elsewhere/x]");
    let err = collect(&WINDOWS, root.path(), &config(&format!("{FONT_ENTRY}{entry}"))).unwrap_err();
    assert!(err.to_string().contains(".cache/wintun"), "{err}");
}

#[skuld::test]
fn a_provisioned_file_that_is_missing_names_the_command_that_makes_it() {
    let root = repo();
    std::fs::remove_dir_all(root.path().join(".cache/wintun")).unwrap();
    let err = collect(&WINDOWS, root.path(), &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}"))).unwrap_err();
    assert!(matches!(err, NoticesError::Provision { .. }), "{err:?}");
    assert!(err.to_string().contains("cargo xtask deps"), "{err}");
}

#[skuld::test]
fn a_provisioned_folder_without_a_licence_file_names_the_command_that_fills_it() {
    // A cache that `cargo xtask wintun` filled before it kept the licence: the DLL is there, the licence is not.
    let root = repo();
    std::fs::remove_file(root.path().join(".cache/wintun/LICENSE.txt")).unwrap();
    let err = collect(&WINDOWS, root.path(), &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}"))).unwrap_err();
    assert!(matches!(err, NoticesError::Provision { .. }), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains(".cache/wintun") && message.contains("cargo xtask deps"),
        "{message}"
    );
}

#[skuld::test]
fn an_entry_for_another_platform_is_left_out() {
    // macOS ships no Wintun: the Windows entry is neither a component there nor checked against the files.
    let root = repo();
    std::fs::remove_dir_all(root.path().join(".cache")).unwrap();
    let found = collect(&MACOS, root.path(), &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}"))).unwrap();
    let names: Vec<_> = found.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["Inter"]);
}

const STD_ENTRY: &str = "
  - name: Rust standard library
    version_from: rust-toolchain
    license: MIT OR Apache-2.0
    url: https://github.com/rust-lang/rust
";

#[skuld::test]
fn the_rust_standard_library_takes_the_version_of_the_pinned_toolchain() {
    let root = repo();
    std::fs::write(
        root.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.3\"\ncomponents = [\"clippy\"]\n",
    )
    .unwrap();
    for platform in [WINDOWS, MACOS] {
        let found = collect(
            &platform,
            root.path(),
            &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}{STD_ENTRY}")),
        )
        .unwrap();
        let std = found.iter().find(|c| c.name == "Rust standard library").unwrap();
        assert_eq!(std.version, "1.97.3");
        assert_eq!(std.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(std.url.as_deref(), Some("https://github.com/rust-lang/rust"));
        assert_eq!(std.origin, Origin::Declared);
    }
}

#[skuld::test]
fn a_toolchain_file_without_a_channel_fails() {
    let root = repo();
    std::fs::write(
        root.path().join("rust-toolchain.toml"),
        "[toolchain]\ncomponents = []\n",
    )
    .unwrap();
    let err = collect(
        &WINDOWS,
        root.path(),
        &config(&format!("{FONT_ENTRY}{WINTUN_ENTRY}{STD_ENTRY}")),
    )
    .unwrap_err();
    assert!(matches!(err, NoticesError::Tool { .. }), "{err:?}");
    assert!(err.to_string().contains("rust-toolchain.toml"), "{err}");
}

#[skuld::test]
fn an_entry_gives_a_version_or_takes_it_from_the_toolchain_not_both() {
    let both = "licenses:\n  - {id: MIT, text: own}\ndeclared:\n  - {name: a, version: \"1\", version_from: rust-toolchain, license: MIT}\n";
    assert!(Config::parse(both).is_err());
}

#[skuld::test]
fn an_entry_whose_text_is_the_toolchains_copyright_file_has_the_toolchains_doc_folder() {
    let root = repo();
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::fs::copy(
        real.join("rust-toolchain.toml"),
        root.path().join("rust-toolchain.toml"),
    )
    .unwrap();
    let entry = format!("{FONT_ENTRY}{WINTUN_ENTRY}{STD_ENTRY}").replace(
        "version_from: rust-toolchain",
        "version_from: rust-toolchain\n    text_from: rust-toolchain-copyright",
    );

    let found = collect(&WINDOWS, root.path(), &config(&entry)).unwrap();

    let std = found.iter().find(|c| c.name == "Rust standard library").unwrap();
    let dir = std.text_dir.as_deref().unwrap();
    assert!(dir.join("COPYRIGHT-library.html").is_file(), "{}", dir.display());
}

const GO_ENTRY: &str = "
  - name: Go standard library
    version_from: go-toolchain
    text_from: go-toolchain
    license: BSD-3-Clause
    url: https://go.dev/
";

#[skuld::test]
fn the_go_standard_library_is_versioned_by_the_toolchain_that_builds_ex_ray() {
    let root = repo();
    std::fs::create_dir_all(root.path().join("crates/ex-ray")).unwrap();
    std::fs::write(
        root.path().join("crates/ex-ray/go.mod"),
        "module example.com/m\n\ngo 1.21\n",
    )
    .unwrap();

    let found = collect(&MACOS, root.path(), &config(&format!("{FONT_ENTRY}{GO_ENTRY}"))).unwrap();

    let go = found.iter().find(|c| c.name == "Go standard library").unwrap();
    assert_eq!(go.origin, Origin::Declared);
    assert_eq!(go.license.as_deref(), Some("BSD-3-Clause"));
    assert_eq!(go.url.as_deref(), Some("https://go.dev/"));
    let goroot = go.text_dir.as_deref().expect("the text is read from GOROOT");
    assert!(goroot.join("LICENSE").is_file(), "{}", goroot.display());
    // A Go release says what it is in the first line of its `VERSION` file, whichever toolchain `go.mod` selected.
    let release = std::fs::read_to_string(goroot.join("VERSION")).unwrap();
    assert_eq!(go.version, release.lines().next().unwrap());
}

#[skuld::test]
fn the_config_declares_every_file_the_bindir_ships_as_it_came_from_upstream() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let config = Config::load(repo).unwrap();
    let mut checked = 0;
    for platform in [WINDOWS, MACOS] {
        let for_artifact = config.for_platform(&platform);
        let declared_paths: Vec<&str> = for_artifact
            .declared
            .iter()
            .flat_map(|entry| entry.files.iter().map(String::as_str))
            .collect();
        for entry in crate::bindir::bindir_entries(platform.os) {
            if entry.kind.needs_a_declared_entry() {
                checked += 1;
                let path = crate::bindir::upstream_library_path(&entry.name)
                    .unwrap_or_else(|| panic!("{platform}: `{}` has no provisioned path", entry.name));
                assert!(
                    declared_paths.contains(&path),
                    "{platform}: `{}` ships as it came, and no `declared:` entry lists `{path}` under `files:`",
                    entry.name
                );
            }
        }
    }
    assert!(checked > 0, "the Windows artifact ships wintun.dll as it came");
}
