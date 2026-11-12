//! Target-triple resolution, shared by the sidecar builders.
//!
//! Tauri's bundler and the ex-ray/galoshes sidecar layouts both name files
//! `<stem>-<target-triple>{.exe}`, so the triple lives in one place.

use crate::manifest::{Arch, Os, Platform};

/// The Rust target triple of `platform` (e.g. `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`). Covers every
/// platform in the workspace CI matrix (Hole's Windows/macOS release set plus the standalone-plugin Linux /
/// Windows-arm64 test matrix).
pub fn target_triple(platform: Platform) -> &'static str {
    match (platform.os, platform.arch) {
        (Os::Windows, Arch::Amd64) => "x86_64-pc-windows-msvc",
        (Os::Windows, Arch::Arm64) => "aarch64-pc-windows-msvc",
        (Os::Darwin, Arch::Amd64) => "x86_64-apple-darwin",
        (Os::Darwin, Arch::Arm64) => "aarch64-apple-darwin",
        (Os::Linux, Arch::Amd64) => "x86_64-unknown-linux-gnu",
        (Os::Linux, Arch::Arm64) => "aarch64-unknown-linux-gnu",
    }
}

/// The Rust target triple for the host platform.
pub fn host_target_triple() -> &'static str {
    target_triple(Platform::host().expect("unsupported platform for host target triple"))
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod target_tests;
