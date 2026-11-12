use crate::manifest::{Arch, Os, Platform};
use crate::target::target_triple;

/// Every platform `build.yaml` ships or tests on has one triple, the one Tauri and the sidecar builders name files by.
#[skuld::test]
fn every_platform_has_its_rust_target_triple() {
    let triple = |os, arch| target_triple(Platform { os, arch });
    assert_eq!(triple(Os::Windows, Arch::Amd64), "x86_64-pc-windows-msvc");
    assert_eq!(triple(Os::Windows, Arch::Arm64), "aarch64-pc-windows-msvc");
    assert_eq!(triple(Os::Darwin, Arch::Amd64), "x86_64-apple-darwin");
    assert_eq!(triple(Os::Darwin, Arch::Arm64), "aarch64-apple-darwin");
    assert_eq!(triple(Os::Linux, Arch::Amd64), "x86_64-unknown-linux-gnu");
    assert_eq!(triple(Os::Linux, Arch::Arm64), "aarch64-unknown-linux-gnu");
}
