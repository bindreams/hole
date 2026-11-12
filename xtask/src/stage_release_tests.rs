use skuld::env;
use std::path::{Path, PathBuf};

use xtask_lib::version::Group;

use crate::manifest::{Arch, Manifest, Os, Platform};
use crate::stage_release::{
    check_installer_override, check_probe_output, ensure_built, plan, resolve_installer, run_probes, shipped,
    single_dmg, Asset, Lane, PlatformAssets, Probe, Shipment, UpdateArchiveSource,
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

#[skuld::test]
fn the_msi_payload_binary_is_probed_for_the_tags_version() {
    let exe = shipment(Group::Hole, Lane::Msi, WIN).payload_binary.unwrap();
    assert_eq!(exe.path, Path::new("repo/target/release/installer-stage/hole.exe"));
    assert_eq!(
        exe.probes,
        [Probe {
            args: &["version"],
            prints: Some("hole 1.2.3".into())
        }]
    );
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
        let keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["arch", "asset", "assets", "os"]);
    }
}
