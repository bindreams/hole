use std::path::{Path, PathBuf};

use xtask_lib::version::Group;

use crate::manifest::{Arch, Manifest, Os, Platform};
use crate::stage_release::{
    check_installer_override, check_probe_output, plan, shipped, Asset, Lane, PlatformAssets, Probe, Shipment,
    UpdateArchiveSource,
};

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
