use crate::bindir::*;
use crate::manifest::Os;
use crate::Profile;
use std::fs;

// The exact per-OS name set + the sidecar subset are asserted in
// `xtask-lib/src/bindir_tests.rs` (their definitions moved there). This file
// keeps the disk-resolving `bindir_files` + CLI-emission tests.

#[skuld::test]
fn bindir_names_command_emits_json_for_os() {
    let json = crate::render_bindir_names(Os::Windows);
    let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
    assert!(parsed.contains(&"galoshes.exe".to_string()));
    assert_eq!(parsed, bindir_dest_names(Os::Windows));
}

/// Build a fake repo layout in a tempdir that satisfies `bindir_files()` so we
/// can call it without depending on the real `target/` and `.cache/`.
fn fake_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // target/{debug,release}/hole{.exe} (+ debug symbols per platform).
    // The PDB / dSYM is staged so panic backtraces resolve. See
    // bindreams/hole#393.
    for profile in ["debug", "release"] {
        let target = root.join("target").join(profile);
        fs::create_dir_all(&target).unwrap();
        let name = if cfg!(windows) { "hole.exe" } else { "hole" };
        fs::write(target.join(name), b"fake hole binary").unwrap();

        #[cfg(target_os = "windows")]
        fs::write(target.join("hole.pdb"), b"fake pdb").unwrap();
        #[cfg(target_os = "macos")]
        {
            let dsym = target.join("hole.dSYM").join("Contents");
            fs::create_dir_all(&dsym).unwrap();
            fs::write(dsym.join("Info.plist"), b"<plist/>").unwrap();
        }
    }

    // .cache/ex-ray/ex-ray-<host triple>{.exe}, the name `xtask ex-ray` writes.
    let ex_ray = root.join(".cache").join("ex-ray");
    fs::create_dir_all(&ex_ray).unwrap();
    fs::write(ex_ray.join(crate::ex_ray::output_name()), b"fake ex-ray").unwrap();

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

    // NOTICES.md — Apache-2.0 attribution shipped alongside the binary.
    fs::write(root.join("NOTICES.md"), b"fake notices").unwrap();

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
        vec![
            "hole.exe",
            "hole.pdb",
            "ex-ray.exe",
            "galoshes.exe",
            "wintun.dll",
            "NOTICES.md"
        ]
    );

    #[cfg(target_os = "macos")]
    assert_eq!(names, vec!["hole", "hole.dSYM", "ex-ray", "galoshes", "NOTICES.md"]);

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    assert_eq!(names, vec!["hole", "ex-ray", "galoshes", "NOTICES.md"]);
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
        debug_hole.source.path().to_string_lossy().contains("debug"),
        "expected debug profile path, got {}",
        debug_hole.source.path().display()
    );
    assert!(
        release_hole.source.path().to_string_lossy().contains("release"),
        "expected release profile path, got {}",
        release_hole.source.path().display()
    );

    // Sidecar paths are profile-independent (they live in .cache/, not target/).
    // Look up by name rather than index because debug symbols (added in #393)
    // shift the ex-ray slot off index 1 on Windows/macOS.
    let debug_sidecar = debug_files.iter().find(|f| f.dest_name.starts_with("ex-ray")).unwrap();
    let release_sidecar = release_files
        .iter()
        .find(|f| f.dest_name.starts_with("ex-ray"))
        .unwrap();
    assert_eq!(debug_sidecar.source, release_sidecar.source);
}

#[skuld::test]
fn bindir_errors_when_ex_ray_host_binary_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Only the hole binary: no ex-ray in the cache.
    let target = root.join("target").join("debug");
    fs::create_dir_all(&target).unwrap();
    let name = if cfg!(windows) { "hole.exe" } else { "hole" };
    fs::write(target.join(name), b"x").unwrap();

    let err = bindir_files(Profile::Debug, root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ex-ray") && msg.contains(&crate::ex_ray::output_name()) && msg.contains("cargo xtask deps"),
        "expected a missing host ex-ray error naming the file, got: {msg}"
    );
}

/// A cross-target build leaves another target's empty stub in the cache
/// (`crates/hole/build.rs` stubs each sidecar for the build's `TARGET`). Only
/// the host's binary is the staging source.
#[skuld::test]
fn bindir_picks_the_host_ex_ray_among_other_targets_stubs() {
    let repo = fake_repo();
    let ex_ray = repo.path().join(".cache").join("ex-ray");
    // One stub with the host's extension convention, one with the opposite.
    fs::write(ex_ray.join("ex-ray-sparc64-unknown-linux-gnu"), b"").unwrap();
    fs::write(ex_ray.join("ex-ray-sparc64-pc-windows-msvc.exe"), b"").unwrap();

    let files = bindir_files(Profile::Debug, repo.path()).unwrap();
    let sidecar = files.iter().find(|f| f.dest_name.starts_with("ex-ray")).unwrap();
    assert_eq!(sidecar.source.path(), ex_ray.join(crate::ex_ray::output_name()));
}
