use std::env::consts::EXE_SUFFIX;
use std::path::{Path, PathBuf};

use super::*;
use crate::plugin_repair::{PluginDirLayout, Prepared, RepairOutcome, RepairVerdict};
use util::versioned_file::{CannotRead, WhyUnreadable};

/// A plugin folder in a temp folder of its own, because a folder that is judged sound must sit in a parent its owner
/// owns, and the system's temp folder is not.
struct PluginFolder {
    _parent: tempfile::TempDir,
    dir: PathBuf,
}

impl PluginFolder {
    fn path(&self) -> &Path {
        &self.dir
    }
}

/// An empty folder named `plugins` in a temp folder of its own, with mode 0755 whatever the umask says: a mode the
/// test does not set is the umask's, and 0775 is a folder others can write.
fn empty_folder() -> PluginFolder {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("plugins");
    std::fs::create_dir(&dir).unwrap();
    set_mode(&dir, 0o755);
    PluginFolder { _parent: parent, dir }
}

/// Sets the mode of `path`, a no-op where there are no modes.
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// A folder holding both plugins (mode 0755) and, if given, a stamp with this text.
fn plugin_folder(stamp: Option<&str>) -> PluginFolder {
    let folder = empty_folder();
    for binary in ["ex-ray", "galoshes"] {
        let file = folder.path().join(format!("{binary}{EXE_SUFFIX}"));
        std::fs::write(&file, b"fake").unwrap();
        set_mode(&file, 0o755);
    }
    if let Some(text) = stamp {
        std::fs::write(folder.path().join("layout.json"), text).unwrap();
    }
    folder
}

/// A layout at `dir`, owned by whoever owns it: the test's own folder.
fn layout_of(dir: &Path) -> PluginDirLayout {
    #[cfg(unix)]
    return PluginDirLayout::owned_by_this_process(dir);
    #[cfg(not(unix))]
    PluginDirLayout {
        dir: dir.to_path_buf(),
        owner: (0, 0),
    }
}

/// A managed source whose repair has made the folder hold what `hole` carries.
fn managed(dir: &Path) -> PluginSource {
    managed_after(dir, Some(RepairOutcome::Converged))
}

/// A managed source whose repair ended as `outcome` with the runtime folder made, or has not run.
fn managed_after(dir: &Path, outcome: Option<RepairOutcome>) -> PluginSource {
    managed_prepared(dir, outcome.map(|outcome| Prepared::new(outcome, Ok(()))))
}

/// A managed source whose start prepared as `prepared`, or has not.
fn managed_prepared(dir: &Path, prepared: Option<Prepared>) -> PluginSource {
    let verdict = RepairVerdict::default();
    if let Some(prepared) = prepared {
        verdict.record(prepared);
    }
    PluginSource::Managed {
        layout: layout_of(dir),
        runtime_dir: dir.join("run"),
        verdict,
    }
}

fn explicit_stamped(dir: &Path) -> PluginSource {
    PluginSource::ExplicitStamped { dir: dir.to_path_buf() }
}

fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().into_string().unwrap(), std::fs::read(e.path()).unwrap())
        })
        .collect();
    entries.sort();
    entries
}

#[skuld::test]
fn managed_resolves_into_its_fixed_folder_whatever_the_executable_is() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));

    let resolved = managed(folder.path()).resolve("v2ray-plugin").unwrap();

    assert_eq!(resolved.path(), folder.path().join(format!("ex-ray{EXE_SUFFIX}")));
    assert_eq!(resolved.descriptor().binary_name, "ex-ray");
}

#[skuld::test]
fn managed_refuses_until_the_repair_of_this_start_has_run() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));

    let err = managed_after(folder.path(), None).resolve("galoshes").unwrap_err();

    assert!(matches!(err, PluginResolveError::FolderNotPrepared { .. }), "{err:?}");
}

#[skuld::test]
fn managed_refuses_a_folder_the_repair_did_not_finish_and_says_so_without_a_path() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    let degraded = RepairOutcome::Degraded {
        notes: vec![],
        failures: vec!["write ex-ray: boom".to_owned()],
    };

    let err = managed_after(folder.path(), Some(degraded))
        .resolve("v2ray-plugin")
        .unwrap_err();

    let message = err.to_string();
    assert!(matches!(err, PluginResolveError::FolderNotRepaired { .. }), "{err:?}");
    assert!(
        message.contains("v2ray-plugin") && message.contains("Reinstall Hole"),
        "{message}"
    );
    assert!(
        !message.contains(&folder.path().to_string_lossy().into_owned()),
        "{message}"
    );
}

#[skuld::test]
fn managed_refuses_when_the_runtime_folder_was_not_made_and_blames_it_not_the_plugin_folder() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    let prepared = Prepared::new(
        RepairOutcome::Converged,
        Err(std::io::Error::other("a file is in the way")),
    );

    let err = managed_prepared(folder.path(), Some(prepared))
        .resolve("v2ray-plugin")
        .unwrap_err();

    let message = err.to_string();
    assert!(matches!(err, PluginResolveError::RuntimeDirNotMade { .. }), "{err:?}");
    assert!(message.contains("v2ray-plugin"), "{message}");
    assert!(
        message.contains(&folder.path().join("run").to_string_lossy().into_owned()),
        "names the folder that is in the way: {message}"
    );
    assert!(
        !message.contains("Reinstall"),
        "the plugin folder is not what is wrong: {message}"
    );
}

#[skuld::test]
fn managed_is_decided_by_the_repair_and_never_reads_the_stamp_of_a_folder_no_repair_judged() {
    // The folder holds a stamp this release cannot read, and a repair that says it converged: the repair is the
    // judge, the stamp of a folder it did not vouch for is not consulted.
    let folder = plugin_folder(Some("not json"));

    assert!(managed(folder.path()).resolve("galoshes").is_ok());
}

#[skuld::test]
fn managed_refuses_when_the_repair_found_a_stamp_it_cannot_read_and_names_it() {
    for (why, cause) in [
        (WhyUnreadable::CannotRead(CannotRead::Newer), "newer release"),
        (WhyUnreadable::CannotRead(CannotRead::Corrupt), "corrupt"),
    ] {
        let folder = plugin_folder(Some(r#"{"version": 1}"#));

        let err = managed_after(folder.path(), Some(RepairOutcome::Refused(why)))
            .resolve("v2ray-plugin")
            .unwrap_err();

        let message = err.to_string();
        assert!(
            matches!(err, PluginResolveError::LayoutUnreadable { .. }),
            "{why:?}: {err:?}"
        );
        assert!(message.contains(cause), "{message}");
        assert!(message.contains("layout.json"), "{message}");
        assert!(message.contains("refused"), "{message}");
    }
}

#[skuld::test]
fn an_explicit_stamped_folder_must_carry_a_current_stamp_and_is_never_written() {
    // (stamp text, resolves). Each case is its own expectation.
    let cases: [(Option<&str>, bool); 4] = [
        (None, false),
        (Some(r#"{"version": 2}"#), false),
        (Some("not json"), false),
        (Some(r#"{"version": 1}"#), true),
    ];
    for (stamp, resolves) in cases {
        let folder = plugin_folder(stamp);
        let before = listing(folder.path());

        let result = explicit_stamped(folder.path()).resolve("v2ray-plugin");

        assert_eq!(result.is_ok(), resolves, "{stamp:?}: {result:?}");
        assert_eq!(listing(folder.path()), before, "{stamp:?}: the folder was written");
    }
}

#[skuld::test]
fn a_folder_that_is_not_a_hole_plugin_folder_says_so_without_naming_a_path() {
    let folder = plugin_folder(None);

    let message = explicit_stamped(folder.path())
        .resolve("v2ray-plugin")
        .unwrap_err()
        .to_string();

    assert!(message.contains("--plugin-dir"), "{message}");
    assert!(
        !message.contains(&folder.path().to_string_lossy().into_owned()),
        "{message}"
    );
}

#[skuld::test]
fn an_unreadable_stamp_in_an_explicit_folder_is_named_without_its_path() {
    let folder = plugin_folder(Some(r#"{"version": 2}"#));

    let message = explicit_stamped(folder.path())
        .resolve("v2ray-plugin")
        .unwrap_err()
        .to_string();

    assert!(
        message.contains("--plugin-dir") && message.contains("newer release"),
        "{message}"
    );
    assert!(
        !message.contains(&folder.path().to_string_lossy().into_owned()),
        "{message}"
    );
}

#[skuld::test]
fn an_explicit_stamp_the_bridge_refuses_to_read_is_reported_as_refused_with_the_refusal() {
    // A directory at the stamp's name cannot be read as a file: the read refuses, and the message says so and why.
    let folder = plugin_folder(None);
    std::fs::create_dir(folder.path().join("layout.json")).unwrap();

    let err = explicit_stamped(folder.path()).resolve("v2ray-plugin").unwrap_err();

    let message = err.to_string();
    assert!(matches!(err, PluginResolveError::LayoutUnreadable { .. }), "{err:?}");
    assert!(message.contains("refused"), "{message}");
    assert!(message.contains("the read failed"), "{message}");
}

#[skuld::test]
fn an_explicit_stamped_folder_that_is_gone_is_reported_as_not_found_and_not_as_a_wrong_folder() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    let source = explicit_stamped(folder.path());
    std::fs::remove_dir_all(folder.path()).unwrap();

    let err = source.resolve("v2ray-plugin").unwrap_err();

    assert!(matches!(err, PluginResolveError::PluginDirNotFound { .. }), "{err:?}");
    assert!(err.to_string().contains("--plugin-dir"), "{err}");
    assert!(
        !err.to_string().contains(&folder.path().to_string_lossy().into_owned()),
        "{err}"
    );
}

#[cfg(unix)]
#[skuld::test]
fn an_explicit_stamped_folder_is_run_from_whoever_can_write_it() {
    // The stamp tells a Hole plugin folder from any other; who can write the folder is the admin's to know.
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o755, 0o775, 0o777] {
        let folder = plugin_folder(Some(r#"{"version": 1}"#));
        std::fs::set_permissions(folder.path(), std::fs::Permissions::from_mode(mode)).unwrap();

        let resolved = explicit_stamped(folder.path()).resolve("v2ray-plugin").unwrap();

        assert_eq!(
            resolved.path(),
            folder.path().join(format!("ex-ray{EXE_SUFFIX}")),
            "{mode:o}"
        );
        assert!(resolved.runtime_dir().is_none(), "{mode:o}");
    }
}

#[skuld::test]
fn an_explicit_stamped_folder_without_the_plugin_reports_it_missing() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    std::fs::remove_file(folder.path().join(format!("ex-ray{EXE_SUFFIX}"))).unwrap();

    let err = explicit_stamped(folder.path()).resolve("v2ray-plugin").unwrap_err();

    assert!(matches!(err, PluginResolveError::BinaryMissing { .. }), "{err:?}");
    assert!(explicit_stamped(folder.path()).resolve("galoshes").is_ok());
}

#[cfg(unix)]
#[skuld::test]
fn an_explicit_stamped_folder_reached_through_a_link_is_run_from_by_the_name_given() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(folder.path(), &link).unwrap();

    let resolved = explicit_stamped(&link).resolve("v2ray-plugin").unwrap();

    assert_eq!(resolved.path(), link.join(format!("ex-ray{EXE_SUFFIX}")));
}

#[skuld::test]
fn explicit_resolves_into_its_folder_whatever_the_executable_is_and_needs_no_stamp() {
    let folder = plugin_folder(None);

    let resolved = PluginSource::Explicit {
        dir: folder.path().to_path_buf(),
    }
    .resolve("galoshes")
    .unwrap();

    assert_eq!(resolved.path(), folder.path().join(format!("galoshes{EXE_SUFFIX}")));
}

#[skuld::test]
fn install_dir_and_build_dir_resolve_beside_the_executable() {
    let folder = plugin_folder(None);
    let exe = folder.path().join(format!("hole{EXE_SUFFIX}"));
    std::fs::write(&exe, b"fake").unwrap();
    let canonical = std::fs::canonicalize(&exe)
        .unwrap()
        .with_file_name(format!("ex-ray{EXE_SUFFIX}"));

    let install = PluginSource::InstallDir {
        exe: BridgeExe::At(exe.clone()),
    };
    let build = PluginSource::build_dir(BridgeExe::At(exe));

    assert_eq!(install.resolve("v2ray-plugin").unwrap().path(), canonical);
    assert_eq!(build.resolve("v2ray-plugin").unwrap().path(), canonical);
}

#[cfg(unix)]
#[skuld::test]
fn a_bridge_reached_through_a_symlink_resolves_beside_the_real_executable() {
    let folder = plugin_folder(None);
    let exe = folder.path().join("hole");
    std::fs::write(&exe, b"fake").unwrap();
    let other = tempfile::tempdir().unwrap();
    let link = other.path().join("hole");
    std::os::unix::fs::symlink(&exe, &link).unwrap();

    let resolved = PluginSource::build_dir(BridgeExe::At(link))
        .resolve("galoshes")
        .unwrap();

    assert_eq!(
        resolved.path(),
        std::fs::canonicalize(folder.path()).unwrap().join("galoshes")
    );
}

#[skuld::test]
fn a_missing_plugin_names_the_remedy_of_the_source_that_looked() {
    let empty = tempfile::tempdir().unwrap();
    let exe = empty.path().join(format!("hole{EXE_SUFFIX}"));
    std::fs::write(&exe, b"fake").unwrap();
    let stamped = empty_folder();
    std::fs::write(stamped.path().join("layout.json"), r#"{"version": 1}"#).unwrap();
    // (source, a word its remedy says).
    let cases: Vec<(PluginSource, &str)> = vec![
        (managed(stamped.path()), "Reinstall Hole"),
        (
            PluginSource::InstallDir {
                exe: BridgeExe::At(exe.clone()),
            },
            "Reinstall Hole",
        ),
        (PluginSource::build_dir(BridgeExe::At(exe)), "cargo xtask stage"),
        (
            PluginSource::Explicit {
                dir: empty.path().to_path_buf(),
            },
            "--plugin-dir",
        ),
        #[cfg(unix)]
        (explicit_stamped(stamped.path()), "--plugin-dir"),
    ];
    for (source, remedy) in cases {
        let err = source.resolve("v2ray-plugin").unwrap_err();

        assert!(
            matches!(&err, PluginResolveError::BinaryMissing { plugin, .. } if plugin == "v2ray-plugin"),
            "{err:?}"
        );
        assert!(err.to_string().contains(remedy), "{err}");
    }
}

#[skuld::test]
fn only_the_managed_source_has_a_runtime_directory() {
    let folder = plugin_folder(Some(r#"{"version": 1}"#));
    let exe = BridgeExe::At(PathBuf::from("/x/hole"));
    let none = [
        PluginSource::InstallDir { exe: exe.clone() },
        PluginSource::build_dir(exe),
        PluginSource::Explicit {
            dir: folder.path().to_path_buf(),
        },
        #[cfg(unix)]
        explicit_stamped(folder.path()),
    ];

    assert_eq!(
        managed(folder.path()).runtime_dir(),
        Some(folder.path().join("run").as_path())
    );
    for source in none {
        assert_eq!(source.runtime_dir(), None, "{source:?}");
    }
}

#[skuld::test]
fn an_unbundled_name_is_refused_by_every_source_before_any_folder_is_read() {
    let folder = plugin_folder(Some("not json"));
    std::fs::write(folder.path().join("kcptun"), b"fake").unwrap();
    let sources = [
        managed(folder.path()),
        #[cfg(unix)]
        explicit_stamped(folder.path()),
        PluginSource::Explicit {
            dir: folder.path().to_path_buf(),
        },
        PluginSource::InstallDir {
            exe: BridgeExe::Unknown,
        },
        PluginSource::build_dir(BridgeExe::Unknown),
    ];

    for source in sources {
        let err = source.resolve("kcptun").unwrap_err();

        assert!(
            matches!(err, PluginResolveError::NotBundled { .. }),
            "{source:?}: {err:?}"
        );
    }
}

#[skuld::test]
fn a_plugin_dir_is_made_absolute_and_must_be_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();

    let absolute = absolute_plugin_dir(PathBuf::from(".")).unwrap();

    assert!(absolute.is_absolute());
    assert_eq!(
        absolute.canonicalize().unwrap(),
        std::env::current_dir().unwrap().canonicalize().unwrap()
    );
    assert_eq!(
        absolute_plugin_dir(file).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        absolute_plugin_dir(dir.path().join("absent")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[skuld::test]
fn a_plugin_dir_that_is_a_link_keeps_the_links_name() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    util::dir::testing::plant_link(&real, &link);

    assert_eq!(absolute_plugin_dir(link.clone()).unwrap(), link);
}

// Policy lives on the type --------------------------------------------------------------------------------------------

/// The variants of [`PluginSource`], spelled as a path: the only text that can name one.
const VARIANTS: &[&str] = &[
    "PluginSource::Managed",
    "PluginSource::InstallDir",
    "PluginSource::BuildDir",
    "PluginSource::ExplicitStamped",
    "PluginSource::Explicit",
];

/// The production files that may name a variant: the type itself and the per-platform constructors.
const MAY_NAME_A_VARIANT: &[&str] = &[
    "crates/bridge/src/proxy/plugin_source.rs",
    "crates/bridge/src/platform/macos.rs",
    "crates/bridge/src/platform/windows.rs",
];

fn production_rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            production_rust_sources(&path, found);
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            found.push(path);
        }
    }
}

/// Production lines outside [`MAY_NAME_A_VARIANT`] that name a variant of `PluginSource`.
fn lines_naming_a_variant(files: &[(String, String)]) -> Vec<String> {
    let mut hits = Vec::new();
    for (relative, text) in files {
        if MAY_NAME_A_VARIANT.contains(&relative.as_str()) {
            continue;
        }
        for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
            if VARIANTS.iter().any(|v| line.contains(v)) {
                hits.push(format!("{relative}: {}", line.trim()));
            }
        }
    }
    hits
}

#[skuld::test]
fn plugin_source_policy_lives_on_the_type_not_at_call_sites() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut files = Vec::new();
    for krate in ["bridge", "hole"] {
        let mut sources = Vec::new();
        production_rust_sources(&root.join("crates").join(krate).join("src"), &mut sources);
        for path in sources {
            let relative = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            files.push((relative, std::fs::read_to_string(&path).unwrap()));
        }
    }

    let hits = lines_naming_a_variant(&files);

    assert!(
        hits.is_empty(),
        "decide per-variant behaviour in a method of PluginSource, not here:\n{}",
        hits.join("\n")
    );
}

#[skuld::test]
fn the_variant_scan_sees_a_match_arm_and_a_constructor_outside_the_allowed_files() {
    let files = vec![
        (
            "crates/bridge/src/ipc.rs".to_owned(),
            "match source { PluginSource::Managed { .. } => 1, _ => 2 }".to_owned(),
        ),
        (
            "crates/hole/src/cli.rs".to_owned(),
            "let s = PluginSource::ExplicitStamped { layout };".to_owned(),
        ),
        (
            "crates/bridge/src/platform/macos.rs".to_owned(),
            "PluginSource::Managed { layout, runtime_dir }".to_owned(),
        ),
        (
            "crates/bridge/src/ipc.rs".to_owned(),
            "// PluginSource::Managed in a comment".to_owned(),
        ),
    ];

    assert_eq!(lines_naming_a_variant(&files).len(), 2);
}
