use skuld::env;
use std::path::{Path, PathBuf};

use xtask_lib::version::Group;

use crate::bindir::{cache_sidecar_path, FileKind};
use crate::manifest::{Arch, Manifest, Os, Platform};
use crate::stage_release::{
    check_installer_override, check_probe_output, ensure_built, hardening_failure, payload_executable_paths,
    payload_root, plan, resolve_installer, run_probes, shipped, single_dmg, verify_hardened, Asset, AssetKind,
    Executable, Lane, PlatformAssets, Probe, Shipment, UpdateArchive, UpdateArchiveSource,
};
use crate::test_child::PROBE_TARGET_ARG;

const WIN: Platform = Platform {
    os: Os::Windows,
    arch: Arch::Amd64,
};
const MAC: Platform = Platform {
    os: Os::Darwin,
    arch: Arch::Arm64,
};
const LINUX: Platform = Platform {
    os: Os::Linux,
    arch: Arch::Amd64,
};

fn names(group: Group, lane: Lane, platform: Platform) -> Vec<String> {
    plan(group, lane, "1.2.3", platform, Path::new("repo"), || {
        Ok(PathBuf::from("the-installer"))
    })
    .unwrap()
    .files
    .into_iter()
    .map(|Asset { name, .. }| name)
    .collect()
}

#[skuld::test]
fn release_asset_names_follow_product_version_os_arch() {
    assert_eq!(names(Group::Hole, Lane::Msi, WIN), ["hole-1.2.3-windows-amd64.msi"]);
    assert_eq!(names(Group::Hole, Lane::Dmg, MAC), ["hole-1.2.3-darwin-arm64.dmg"]);
    assert_eq!(
        names(Group::Galoshes, Lane::Plugins, WIN),
        ["galoshes-1.2.3-windows-amd64.exe"]
    );
    assert_eq!(names(Group::Garter, Lane::Plugins, LINUX), ["garter-1.2.3-linux-amd64"]);
    assert_eq!(names(Group::ExRay, Lane::Plugins, MAC), ["ex-ray-1.2.3-darwin-arm64"]);
}

#[skuld::test]
fn a_lane_stages_nothing_for_a_group_it_does_not_ship() {
    assert!(names(Group::Hole, Lane::Plugins, WIN).is_empty());
    assert!(names(Group::Galoshes, Lane::Msi, WIN).is_empty());
    assert!(names(Group::ExRay, Lane::Dmg, MAC).is_empty());
}

fn shipment(group: Group, lane: Lane, platform: Platform) -> Shipment {
    plan(group, lane, "1.2.3", platform, Path::new("repo"), || {
        Ok(PathBuf::from("the-installer"))
    })
    .unwrap()
}

#[skuld::test]
fn the_garter_cli_is_probed_for_the_tags_version_and_help() {
    let probes = shipment(Group::Garter, Lane::Plugins, LINUX).files.remove(0).probes;
    assert_eq!(
        probes,
        [
            Probe {
                args: &["--version"],
                prints: Some("garter 1.2.3".into())
            },
            Probe {
                args: &["--help"],
                prints: None
            },
        ]
    );
}

fn payload(group: Group, lane: Lane, platform: Platform) -> UpdateArchive {
    shipment(group, lane, platform).update_archive.unwrap()
}

fn exe(name: &str, kind: FileKind, probes: Vec<Probe>) -> Executable {
    Executable {
        name: name.into(),
        kind,
        probes,
    }
}

/// The MSI's stage dir holds six files and the three executables among them are payload executables, whatever builds
/// them; `wintun.dll` and the notice file are not. `hole` alone is probed, for the tag's version.
#[skuld::test]
fn the_msi_payload_executables_are_the_exes_of_the_bindir() {
    assert_eq!(
        payload(Group::Hole, Lane::Msi, WIN).executables,
        [
            exe(
                "hole.exe",
                FileKind::RustExecutable,
                vec![Probe {
                    args: &["version"],
                    prints: Some("hole 1.2.3".into())
                }]
            ),
            exe("ex-ray.exe", FileKind::ForeignExecutable, Vec::new()),
            exe("galoshes.exe", FileKind::RustExecutable, Vec::new()),
        ]
    );
}

/// The app holds `hole` alone as an executable: the plugins are embedded in it, and checked as the files it embeds.
#[skuld::test]
fn the_dmg_payload_executable_is_hole_and_its_embedded_plugins_are_checked_too() {
    let dmg = payload(Group::Hole, Lane::Dmg, MAC);
    assert_eq!(dmg.executables, [exe("hole", FileKind::RustExecutable, Vec::new())]);
    assert_eq!(
        dmg.embedded,
        [
            exe("ex-ray", FileKind::ForeignExecutable, Vec::new()),
            exe("galoshes", FileKind::RustExecutable, Vec::new())
        ]
    );
    // Windows ships the plugins as files of the stage dir, so it embeds none.
    assert!(payload(Group::Hole, Lane::Msi, WIN).embedded.is_empty());
}

#[skuld::test]
fn only_hole_ships_a_payload() {
    for (group, lane, platform) in [
        (Group::Galoshes, Lane::Plugins, WIN),
        (Group::Garter, Lane::Plugins, LINUX),
        (Group::ExRay, Lane::Plugins, MAC),
    ] {
        assert!(shipment(group, lane, platform).update_archive.is_none());
    }
}

/// What each shipped file is: the installers are not binaries, ex-ray is built by Go, the rest by cargo. The
/// executables' kinds are the BINDIR's own, on every OS.
#[skuld::test]
fn a_shipped_file_knows_what_built_it() {
    let kinds = |group, lane, platform| -> Vec<AssetKind> {
        shipment(group, lane, platform).files.iter().map(|a| a.kind).collect()
    };
    let rust = AssetKind::Executable(FileKind::RustExecutable);
    let foreign = AssetKind::Executable(FileKind::ForeignExecutable);
    assert_eq!(kinds(Group::Galoshes, Lane::Plugins, WIN), [rust]);
    assert_eq!(kinds(Group::Galoshes, Lane::Plugins, LINUX), [rust]);
    assert_eq!(kinds(Group::Garter, Lane::Plugins, LINUX), [rust]);
    assert_eq!(kinds(Group::ExRay, Lane::Plugins, MAC), [foreign]);
    assert_eq!(kinds(Group::ExRay, Lane::Plugins, WIN), [foreign]);
    assert_eq!(kinds(Group::Hole, Lane::Msi, WIN), [AssetKind::Installer]);
    assert_eq!(kinds(Group::Hole, Lane::Dmg, MAC), [AssetKind::Installer]);
}

/// An installer is not run by xtask and has no hardening of its own to check; an executable is checked as its kind says.
#[skuld::test]
fn only_an_executable_asset_has_a_kind_to_check() {
    assert_eq!(AssetKind::Installer.executable(), None);
    assert_eq!(
        AssetKind::Executable(FileKind::ForeignExecutable).executable(),
        Some(FileKind::ForeignExecutable)
    );
}

/// The payload's executables are found in the dir the update archive is packed from, and the ones `hole` embeds where its
/// build reads them, by the triple of the platform being staged.
#[skuld::test]
fn payload_executables_are_looked_up_in_the_archives_source() {
    let repo = tempfile::tempdir().unwrap();
    let macos = repo.path().join("target/release/bundle/macos");
    std::fs::create_dir_all(macos.join("Hole.app/Contents/MacOS")).unwrap();
    let hole = macos.join("Hole.app/Contents/MacOS/hole");
    let dmg = UpdateArchive {
        name: "hole.tar.gz".into(),
        source: UpdateArchiveSource::BuiltApp,
        executables: vec![exe("hole", FileKind::RustExecutable, Vec::new())],
        embedded: vec![exe("galoshes", FileKind::RustExecutable, Vec::new())],
    };
    let paths = |archive: &UpdateArchive| -> anyhow::Result<Vec<PathBuf>> {
        let root = payload_root(&archive.source, repo.path())?;
        let found = payload_executable_paths(archive, &root, repo.path(), MAC)?;
        Ok(found.into_iter().map(|(path, _)| path).collect())
    };

    // A file that is not there is named, not verified.
    let err = paths(&dmg).unwrap_err().to_string();
    assert!(err.contains("is not a file") && err.contains("Hole.app"), "{err}");

    std::fs::write(&hole, b"hole, with galoshes inside, built").unwrap();
    let err = paths(&dmg).unwrap_err().to_string();
    assert!(err.contains("is not a file") && err.contains("galoshes"), "{err}");

    let embedded = cache_sidecar_path(repo.path(), "galoshes", "aarch64-apple-darwin", false);
    std::fs::create_dir_all(embedded.parent().unwrap()).unwrap();
    // A `.cache` file replaced after `hole` was built is not what `hole` embeds.
    std::fs::write(&embedded, b"galoshes, rebuilt").unwrap();
    let err = paths(&dmg).unwrap_err().to_string();
    assert!(err.contains("is not what") && err.contains("rebuild `hole`"), "{err}");

    std::fs::write(&embedded, b"galoshes inside").unwrap();
    assert_eq!(paths(&dmg).unwrap(), [hole, embedded]);

    let msi = UpdateArchive {
        name: "hole.zip".into(),
        source: UpdateArchiveSource::StagedBindir(repo.path().to_path_buf()),
        executables: vec![exe("hole.exe", FileKind::RustExecutable, Vec::new())],
        embedded: Vec::new(),
    };
    std::fs::write(repo.path().join("hole.exe"), b"built").unwrap();
    assert_eq!(paths(&msi).unwrap()[0], repo.path().join("hole.exe"));

    // Two bundles: the same "exactly one .app" error the archive is packed with.
    std::fs::create_dir_all(macos.join("Other.app")).unwrap();
    let err = paths(&dmg).unwrap_err().to_string();
    assert!(err.contains("exactly one .app"), "{err}");
}

/// A file that cannot be checked says so; only a violation tells the developer how to fix the build, and the fix is the
/// one for the toolchain that built the file.
#[skuld::test]
fn only_a_violation_blames_the_build_and_names_the_right_one() {
    use libsearch_guard::{VerifyError, Violation, ViolationKind};

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("galoshes");
    std::fs::write(&file, b"not an executable").unwrap();
    let missing = dir.path().join("missing");
    for kind in [FileKind::RustExecutable, FileKind::ForeignExecutable] {
        for path in [&file, &missing] {
            let err = verify_hardened(path, kind).unwrap_err().to_string();
            assert!(err.contains(&path.display().to_string()), "{err}");
            assert!(err.contains("cannot check"), "{err}");
            assert!(!err.contains("bins()"), "{err}");
        }
    }

    let found = vec![Violation {
        kind: ViolationKind::PeRuntimeImport,
        detail: "imports VCRUNTIME140.dll".into(),
    }];
    // A violation found before the rest of the file turned unreadable is still a violation.
    let violations = || {
        [
            VerifyError::Violations(found.clone()),
            VerifyError::Unreadable {
                why: "a library path is not UTF-8".into(),
                found: found.clone(),
            },
        ]
    };
    for violation in violations() {
        let err = hardening_failure(&file, FileKind::RustExecutable, &violation).to_string();
        assert!(err.contains(&file.display().to_string()), "{err}");
        assert!(err.contains("libsearch_guard::bins()"), "{err}");
        assert!(err.contains("imports VCRUNTIME140.dll"), "{err}");
        assert!(!err.contains("cannot check"), "{err}");
    }
    // A Go build has no `bins()` to call: the message names its own build.
    for violation in violations() {
        let err = hardening_failure(&file, FileKind::ForeignExecutable, &violation).to_string();
        assert!(err.contains("imports VCRUNTIME140.dll"), "{err}");
        assert!(!err.contains("bins()"), "{err}");
        assert!(err.contains("Go build") && err.contains("ex_ray.rs"), "{err}");
    }

    let unreadable = VerifyError::Unreadable {
        why: "a library path is not UTF-8".into(),
        found: Vec::new(),
    };
    let err = hardening_failure(&file, FileKind::RustExecutable, &unreadable).to_string();
    assert!(err.contains("cannot check") && !err.contains("bins()"), "{err}");
}

#[skuld::test]
fn the_windows_update_zip_is_packed_from_the_msi_stage_dir() {
    let archive = shipment(Group::Hole, Lane::Msi, WIN).update_archive.unwrap();
    assert_eq!(archive.name, "hole-1.2.3-windows-amd64.zip");
    assert_eq!(
        archive.source,
        UpdateArchiveSource::StagedBindir(PathBuf::from("repo/target/release/installer-stage"))
    );
}

#[skuld::test]
fn the_macos_update_archive_is_packed_from_the_built_app() {
    let archive = shipment(Group::Hole, Lane::Dmg, MAC).update_archive.unwrap();
    assert_eq!(archive.name, "hole-1.2.3-darwin-arm64.tar.gz");
    assert_eq!(archive.source, UpdateArchiveSource::BuiltApp);
}

#[skuld::test]
fn a_probe_that_prints_another_version_fails() {
    let probe = Probe {
        args: &["version"],
        prints: Some("hole 1.2.3".into()),
    };
    check_probe_output(Path::new("hole"), &probe, "hole 1.2.3\n").unwrap();
    let err = check_probe_output(Path::new("hole"), &probe, "hole 1.2.3.dirty\n").unwrap_err();
    assert!(err.to_string().contains("1.2.3.dirty"), "{err}");
}

#[skuld::test]
fn a_probe_without_expected_output_accepts_any() {
    let probe = Probe {
        args: &["--help"],
        prints: None,
    };
    check_probe_output(Path::new("garter"), &probe, "whatever").unwrap();
}

fn repo_manifest() -> Manifest {
    let root = crate::repo_root().expect("repo root");
    Manifest::parse(&std::fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml")
}

fn row(os: &str, arch: &str, asset: &str, assets: &[&str]) -> PlatformAssets {
    PlatformAssets {
        os: os.into(),
        arch: arch.into(),
        asset: asset.into(),
        assets: assets.iter().map(|s| s.to_string()).collect(),
    }
}

/// The platforms are the ones build.yaml runs the lane's target on: the MSI only on windows/amd64, the DMG on both macs.
#[skuld::test]
fn hole_ships_an_installer_and_an_update_archive_on_three_platforms() {
    assert_eq!(
        shipped(Group::Hole, "1.2.3", &repo_manifest()).unwrap(),
        [
            row(
                "windows",
                "amd64",
                "hole-1.2.3-windows-amd64.msi",
                &["hole-1.2.3-windows-amd64.msi", "hole-1.2.3-windows-amd64.zip"]
            ),
            row(
                "darwin",
                "amd64",
                "hole-1.2.3-darwin-amd64.dmg",
                &["hole-1.2.3-darwin-amd64.dmg", "hole-1.2.3-darwin-amd64.tar.gz"]
            ),
            row(
                "darwin",
                "arm64",
                "hole-1.2.3-darwin-arm64.dmg",
                &["hole-1.2.3-darwin-arm64.dmg", "hole-1.2.3-darwin-arm64.tar.gz"]
            ),
        ]
    );
}

#[skuld::test]
fn a_plugin_group_ships_one_binary_on_each_of_six_platforms() {
    let rows = shipped(Group::Galoshes, "1.2.3", &repo_manifest()).unwrap();
    let mut assets: Vec<&str> = rows.iter().flat_map(|r| r.assets.iter().map(String::as_str)).collect();
    assets.sort();
    assert_eq!(
        assets,
        [
            "galoshes-1.2.3-darwin-amd64",
            "galoshes-1.2.3-darwin-arm64",
            "galoshes-1.2.3-linux-amd64",
            "galoshes-1.2.3-linux-arm64",
            "galoshes-1.2.3-windows-amd64.exe",
            "galoshes-1.2.3-windows-arm64.exe",
        ]
    );
    assert!(rows.iter().all(|r| r.assets == [r.asset.clone()]));
}

#[skuld::test]
fn an_installer_lane_refuses_the_wrong_os() {
    assert!(plan(
        Group::Hole,
        Lane::Msi,
        "1.2.3",
        MAC,
        Path::new("repo"),
        || unreachable!()
    )
    .is_err());
    assert!(plan(
        Group::Hole,
        Lane::Dmg,
        "1.2.3",
        WIN,
        Path::new("repo"),
        || unreachable!()
    )
    .is_err());
}

#[skuld::test]
fn an_installer_override_must_be_the_build_stage_release_packs_from() {
    let dir = tempfile::tempdir().unwrap();
    let built = dir.path().join("hole.msi");
    let other = dir.path().join("other.msi");
    std::fs::write(&built, b"built").unwrap();
    std::fs::write(&other, b"other").unwrap();

    let err = check_installer_override("MSI_UNDER_TEST", &other, &built).unwrap_err();
    assert!(err.to_string().contains("MSI_UNDER_TEST"), "{err}");

    check_installer_override("MSI_UNDER_TEST", &built, &built).unwrap();
    // The same file under another spelling.
    let respelled = dir
        .path()
        .join("..")
        .join(dir.path().file_name().unwrap())
        .join("hole.msi");
    check_installer_override("MSI_UNDER_TEST", &respelled, &built).unwrap();
}

#[skuld::test]
fn only_the_garter_plugins_lane_builds_before_staging() {
    assert_eq!(
        shipment(Group::Garter, Lane::Plugins, LINUX).build_first,
        Some("garter-bin")
    );
    assert_eq!(shipment(Group::Galoshes, Lane::Plugins, LINUX).build_first, None);
    assert_eq!(shipment(Group::ExRay, Lane::Plugins, LINUX).build_first, None);
    assert_eq!(shipment(Group::Hole, Lane::Msi, WIN).build_first, None);
    assert_eq!(shipment(Group::Hole, Lane::Dmg, MAC).build_first, None);
}

#[skuld::test]
fn every_build_first_names_a_build_target_for_the_platform_it_ships_on() {
    let manifest = repo_manifest();
    let mut named = 0;
    for group in Group::all() {
        for lane in [Lane::Msi, Lane::Dmg, Lane::Plugins] {
            for os in [Os::Windows, Os::Linux, Os::Darwin] {
                for arch in [Arch::Amd64, Arch::Arm64] {
                    let platform = Platform { os, arch };
                    let planned = plan(*group, lane, "1.2.3", platform, Path::new("repo"), || {
                        Ok(PathBuf::from("the-installer"))
                    });
                    // The hole installer lanes refuse the other OSes; no other pairing errors.
                    if *group == Group::Hole
                        && matches!(
                            (lane, os),
                            (Lane::Msi, Os::Linux | Os::Darwin) | (Lane::Dmg, Os::Linux | Os::Windows)
                        )
                    {
                        assert!(planned.is_err(), "{group} {lane:?} on {platform} should refuse");
                        continue;
                    }
                    let shipment = planned.unwrap();
                    let Some(target) = shipment.build_first else { continue };
                    named += 1;
                    let found = manifest
                        .get(target)
                        .unwrap_or_else(|| panic!("{group} {lane:?} on {platform}: no build.yaml target {target:?}"));
                    assert!(
                        found.applies_to(platform),
                        "{group} {lane:?}: target {target:?} does not build on {platform}"
                    );
                }
            }
        }
    }
    assert!(named > 0, "no shipment names a build_first target");
}

#[skuld::test]
fn the_build_runs_before_the_files_are_required_to_exist() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let garter = plan(Group::Garter, Lane::Plugins, "1.2.3", LINUX, repo, || unreachable!()).unwrap();
    let binary = garter.files[0].src.clone();
    assert!(!binary.exists());

    let mut built = Vec::new();
    ensure_built(&garter, |target| {
        built.push(target.to_owned());
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"built").unwrap();
        Ok(())
    })
    .unwrap();
    assert_eq!(built, ["garter-bin"]);

    // A build that produces nothing leaves the file missing, and that is an error.
    std::fs::remove_file(&binary).unwrap();
    let err = ensure_built(&garter, |_| Ok(())).unwrap_err();
    assert!(err.to_string().contains("is not a file"), "{err}");

    // A failed build's error is returned as is, and the file check does not run after it.
    let err = ensure_built(&garter, |_| anyhow::bail!("cargo failed")).unwrap_err();
    assert_eq!(format!("{err:#}"), "cargo failed");
}

#[skuld::test]
fn a_shipment_without_build_first_only_checks_its_files() {
    let dir = tempfile::tempdir().unwrap();
    let galoshes = plan(
        Group::Galoshes,
        Lane::Plugins,
        "1.2.3",
        LINUX,
        dir.path(),
        || unreachable!(),
    )
    .unwrap();
    let err = ensure_built(&galoshes, |_| unreachable!("nothing to build")).unwrap_err();
    assert!(err.to_string().contains("is not a file"), "{err}");
}

/// A repo root holding `target/release/hole.msi`.
fn repo_with_msi() -> (tempfile::TempDir, PathBuf) {
    let repo = tempfile::tempdir().unwrap();
    let release = repo.path().join("target").join("release");
    std::fs::create_dir_all(&release).unwrap();
    let msi = release.join("hole.msi");
    std::fs::write(&msi, b"built").unwrap();
    (repo, msi)
}

#[skuld::test]
fn a_relative_installer_override_is_from_the_repo_root(#[fixture] env: &skuld::EnvGuard) {
    let (repo, msi) = repo_with_msi();
    std::fs::write(repo.path().join("target/release/other.msi"), b"other").unwrap();

    env.set("MSI_UNDER_TEST", "target/release/hole.msi");
    assert_eq!(resolve_installer(Lane::Msi, repo.path()).unwrap(), msi);

    env.set("MSI_UNDER_TEST", "target/release/other.msi");
    let err = resolve_installer(Lane::Msi, repo.path()).unwrap_err();
    assert!(err.to_string().contains("MSI_UNDER_TEST"), "{err}");
}

#[skuld::test]
fn an_empty_installer_override_is_unset(#[fixture] env: &skuld::EnvGuard) {
    let (repo, msi) = repo_with_msi();
    env.set("MSI_UNDER_TEST", "");
    assert_eq!(resolve_installer(Lane::Msi, repo.path()).unwrap(), msi);
    env.remove("MSI_UNDER_TEST");
    assert_eq!(resolve_installer(Lane::Msi, repo.path()).unwrap(), msi);
}

#[skuld::test]
fn the_dmg_lane_resolves_the_one_built_dmg_and_checks_its_override(#[fixture] env: &skuld::EnvGuard) {
    let repo = tempfile::tempdir().unwrap();
    let dmg_dir = repo.path().join("target/release/bundle/dmg");
    std::fs::create_dir_all(&dmg_dir).unwrap();
    let dmg = dmg_dir.join("Hole_1.2.3_aarch64.dmg");
    std::fs::write(&dmg, b"built").unwrap();

    env.remove("DMG_UNDER_TEST");
    assert_eq!(resolve_installer(Lane::Dmg, repo.path()).unwrap(), dmg);
    env.set("DMG_UNDER_TEST", "target/release/bundle/dmg/Hole_1.2.3_aarch64.dmg");
    assert_eq!(resolve_installer(Lane::Dmg, repo.path()).unwrap(), dmg);
    env.set("DMG_UNDER_TEST", "target/release/bundle/dmg/missing.dmg");
    assert!(resolve_installer(Lane::Dmg, repo.path()).is_err());
}

#[skuld::test]
fn the_plugins_lane_has_no_installer() {
    let (repo, _) = repo_with_msi();
    assert!(resolve_installer(Lane::Plugins, repo.path()).is_err());
}

#[skuld::test]
fn single_dmg_wants_exactly_one_dmg_and_ignores_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let err = single_dmg(dir.path()).unwrap_err();
    assert!(err.to_string().contains("found 0"), "{err}");

    std::fs::write(dir.path().join("rw.Hole.dmg.log"), b"not a dmg").unwrap();
    std::fs::write(dir.path().join("Hole.dmg"), b"one").unwrap();
    assert_eq!(single_dmg(dir.path()).unwrap(), dir.path().join("Hole.dmg"));

    std::fs::write(dir.path().join("Stale.dmg"), b"two").unwrap();
    let err = single_dmg(dir.path()).unwrap_err();
    assert!(err.to_string().contains("found 2"), "{err}");
}

/// A probe that runs this test binary as the shipped executable (see `test_child::probe_target`).
fn probe(args: &'static [&'static str], prints: Option<&str>) -> Probe {
    Probe {
        args,
        prints: prints.map(str::to_owned),
    }
}

#[skuld::test]
fn a_probe_that_exits_0_and_prints_the_expected_version_passes() {
    let exe = std::env::current_exe().unwrap();
    run_probes(
        &exe,
        &[
            probe(&[PROBE_TARGET_ARG, "print", "hole 1.2.3"], Some("hole 1.2.3")),
            probe(&[PROBE_TARGET_ARG, "print", "anything"], None),
        ],
    )
    .unwrap();
}

#[skuld::test]
fn a_probe_that_exits_non_zero_fails() {
    let exe = std::env::current_exe().unwrap();
    let err = run_probes(&exe, &[probe(&[PROBE_TARGET_ARG, "exit", "3"], None)]).unwrap_err();
    assert!(err.to_string().contains("failed"), "{err}");
}

#[skuld::test]
fn a_probe_whose_stdout_is_another_version_fails() {
    let exe = std::env::current_exe().unwrap();
    let err = run_probes(
        &exe,
        &[probe(
            &[PROBE_TARGET_ARG, "print", "hole 1.2.3.dirty"],
            Some("hole 1.2.3"),
        )],
    )
    .unwrap_err();
    assert!(err.to_string().contains("1.2.3.dirty"), "{err}");
}

/// `generate-release-notes.py` reads `os`, `arch` and `asset` of each platform and `check-release-assets` reads
/// `assets` (`jq '.[].assets[]'`): the serialised keys are their contract.
#[skuld::test]
fn the_release_assets_json_has_the_keys_its_consumers_read() {
    let platforms = shipped(Group::Hole, "1.2.3", &repo_manifest()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&platforms).unwrap()).unwrap();
    assert_eq!(
        json[0],
        serde_json::json!({
            "os": "windows",
            "arch": "amd64",
            "asset": "hole-1.2.3-windows-amd64.msi",
            "assets": ["hole-1.2.3-windows-amd64.msi", "hole-1.2.3-windows-amd64.zip"],
        })
    );
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let mut keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["arch", "asset", "assets", "os"]);
    }
}
