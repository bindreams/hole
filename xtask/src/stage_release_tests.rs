use std::path::{Path, PathBuf};

use xtask_lib::version::Group;

use crate::manifest::{Arch, Os, Platform};
use crate::stage_release::{plan, Asset, Lane};

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

#[skuld::test]
fn only_the_garter_cli_is_built_by_the_stage() {
    let build = |group| {
        plan(
            group,
            Lane::Plugins,
            "1.2.3",
            LINUX,
            Path::new("repo"),
            || unreachable!(),
        )
        .unwrap()
        .build_target
    };
    assert_eq!(build(Group::Garter), Some("garter-bin"));
    assert_eq!(build(Group::Galoshes), None);
    assert_eq!(build(Group::ExRay), None);
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
