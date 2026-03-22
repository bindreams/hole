#!/usr/bin/env cargo
//! Prepare installer staging directory for `cargo wix`.
//!
//! This script is called as the `before` hook by cargo-wix. It:
//! 1. Runs `cargo build --release --workspace` (which triggers build.rs to
//!    build v2ray-plugin from Go source and download wintun.dll)
//! 2. Copies the built binaries into a staging directory for WiX

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() {
    let target_dir = env_path("WIX_TARGET_DIR");
    let release_dir = target_dir.join("release");
    let stage = release_dir.join("installer-stage");

    // Build =====

    eprintln!("==> Building release binaries...");
    let status = Command::new("cargo")
        .args(["build", "--release", "--workspace"])
        .status()
        .expect("failed to run cargo build");
    if !status.success() {
        eprintln!("cargo build failed");
        std::process::exit(1);
    }

    // Stage =====

    fs::create_dir_all(&stage).expect("failed to create staging directory");
    eprintln!("==> Staging installer files to {}", stage.display());

    // hole.exe — main binary
    hardlink_or_copy(&release_dir.join("hole.exe"), &stage.join("hole.exe"));

    // v2ray-plugin.exe — built by crates/gui/build.rs into .cache/gui/v2ray-plugin/
    let v2ray_src = find_single_file(
        &PathBuf::from(".cache/gui/v2ray-plugin"),
        "v2ray-plugin-",
        ".exe",
    );
    hardlink_or_copy(&v2ray_src, &stage.join("v2ray-plugin.exe"));

    // wintun.dll — downloaded by crates/gui/build.rs into .cache/gui/wintun/
    hardlink_or_copy(
        &PathBuf::from(".cache/gui/wintun/wintun.dll"),
        &stage.join("wintun.dll"),
    );

    eprintln!("==> Staging complete");
}

fn env_path(var: &str) -> PathBuf {
    PathBuf::from(env::var(var).unwrap_or_else(|_| panic!("{var} not set")))
}

/// Find the single file in `dir` matching `prefix*suffix`.
fn find_single_file(dir: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(prefix) && n.ends_with(suffix))
                    .unwrap_or(false)
        })
        .collect();

    match entries.len() {
        0 => panic!("no file matching {prefix}*{suffix} in {}", dir.display()),
        1 => entries.into_iter().next().unwrap(),
        n => panic!(
            "expected 1 file matching {prefix}*{suffix} in {}, found {n}",
            dir.display()
        ),
    }
}

/// Try to hardlink, fall back to copy.
fn hardlink_or_copy(src: &Path, dst: &Path) {
    let _ = fs::remove_file(dst);

    if fs::hard_link(src, dst).is_ok() {
        eprintln!(
            "  {} (hardlinked)",
            dst.file_name().unwrap().to_string_lossy()
        );
    } else {
        fs::copy(src, dst).unwrap_or_else(|e| {
            panic!(
                "failed to copy {} -> {}: {e}",
                src.display(),
                dst.display()
            )
        });
        eprintln!("  {} (copied)", dst.file_name().unwrap().to_string_lossy());
    }
}
