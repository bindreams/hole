use crate::bindir::*;
use crate::Profile;
use std::fs;

/// Build a fake repo layout in a tempdir that satisfies `bindir_files()` so we
/// can call it without depending on the real `target/` and `.cache/`.
fn fake_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // target/{debug,release}/hole{.exe}
    for profile in ["debug", "release"] {
        let target = root.join("target").join(profile);
        fs::create_dir_all(&target).unwrap();
        let name = if cfg!(windows) { "hole.exe" } else { "hole" };
        fs::write(target.join(name), b"fake hole binary").unwrap();
    }

    // .cache/v2ray-plugin/v2ray-plugin-<triple>{.exe} — exactly one match
    let v2ray = root.join(".cache").join("v2ray-plugin");
    fs::create_dir_all(&v2ray).unwrap();
    let v2ray_name = if cfg!(windows) {
        "v2ray-plugin-x86_64-pc-windows-msvc.exe"
    } else if cfg!(target_arch = "aarch64") {
        "v2ray-plugin-aarch64-apple-darwin"
    } else {
        "v2ray-plugin-x86_64-apple-darwin"
    };
    fs::write(v2ray.join(v2ray_name), b"fake v2ray-plugin").unwrap();

    // target/release/galoshes{.exe} (unified workspace target dir)
    let galoshes = root.join("target").join("release");
    fs::create_dir_all(&galoshes).unwrap();
    let galoshes_name = if cfg!(windows) { "galoshes.exe" } else { "galoshes" };
    fs::write(galoshes.join(galoshes_name), b"fake galoshes").unwrap();

    // .cache/wintun/wintun.dll — Windows only
    #[cfg(target_os = "windows")]
    {
        let wintun = root.join(".cache").join("wintun");
        fs::create_dir_all(&wintun).unwrap();
        fs::write(wintun.join("wintun.dll"), b"fake wintun").unwrap();
    }

    dir
}

#[skuld::test]
fn bindir_contains_expected_files() {
    let repo = fake_repo();
    let files = bindir_files(Profile::Debug, repo.path()).unwrap();
    let names: Vec<&str> = files.iter().map(|f| f.dest_name.as_str()).collect();

    // Exact-equality assertion is intentional. Adding a new file to
    // bindir_files() will fail this test, forcing the change to be
    // acknowledged here. That is the whole point of the regression test —
    // see issue #143.
    #[cfg(target_os = "windows")]
    assert_eq!(
        names,
        vec!["hole.exe", "v2ray-plugin.exe", "galoshes.exe", "wintun.dll"]
    );

    #[cfg(target_os = "macos")]
    assert_eq!(names, vec!["hole", "v2ray-plugin", "galoshes"]);

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    assert_eq!(names, vec!["hole", "v2ray-plugin", "galoshes"]);
}

#[skuld::test]
fn bindir_uses_correct_profile_dir() {
    let repo = fake_repo();
    let debug_files = bindir_files(Profile::Debug, repo.path()).unwrap();
    let release_files = bindir_files(Profile::Release, repo.path()).unwrap();

    // hole binary path differs between profiles
    let debug_hole = &debug_files[0];
    let release_hole = &release_files[0];
    assert!(
        debug_hole.source.to_string_lossy().contains("debug"),
        "expected debug profile path, got {}",
        debug_hole.source.display()
    );
    assert!(
        release_hole.source.to_string_lossy().contains("release"),
        "expected release profile path, got {}",
        release_hole.source.display()
    );

    // Sidecar paths are profile-independent (they live in .cache/, not target/)
    let debug_sidecar = &debug_files[1];
    let release_sidecar = &release_files[1];
    assert_eq!(debug_sidecar.source, release_sidecar.source);
}

#[skuld::test]
fn bindir_errors_when_v2ray_glob_has_zero_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Set up only the hole binary, no v2ray-plugin glob match.
    let target = root.join("target").join("debug");
    fs::create_dir_all(&target).unwrap();
    let name = if cfg!(windows) { "hole.exe" } else { "hole" };
    fs::write(target.join(name), b"x").unwrap();

    let err = bindir_files(Profile::Debug, root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no files matched") && msg.contains("v2ray-plugin"),
        "expected v2ray-plugin glob error, got: {msg}"
    );
}

#[skuld::test]
fn bindir_errors_when_v2ray_glob_has_multiple_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let target = root.join("target").join("debug");
    fs::create_dir_all(&target).unwrap();
    let name = if cfg!(windows) { "hole.exe" } else { "hole" };
    fs::write(target.join(name), b"x").unwrap();

    let v2ray = root.join(".cache").join("v2ray-plugin");
    fs::create_dir_all(&v2ray).unwrap();
    // Two matches — should error.
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    fs::write(v2ray.join(format!("v2ray-plugin-a{suffix}")), b"x").unwrap();
    fs::write(v2ray.join(format!("v2ray-plugin-b{suffix}")), b"x").unwrap();

    let err = bindir_files(Profile::Debug, root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expected exactly 1 file") && msg.contains("v2ray-plugin"),
        "expected multiple-match error, got: {msg}"
    );
}
