use crate::bindir::*;
use crate::manifest::Os;
use crate::Profile;
use std::fs;

#[skuld::test]
fn dest_names_per_os_are_exact() {
    // Exact-equality is intentional: adding a BINDIR file forces an update
    // here AND in every installer manifest (caught by the conformance tests).
    assert_eq!(
        bindir_dest_names(Os::Windows),
        vec![
            "hole.exe",
            "hole.pdb",
            "ex-ray.exe",
            "galoshes.exe",
            "wintun.dll",
            "NOTICES.md"
        ]
    );
    assert_eq!(
        bindir_dest_names(Os::Darwin),
        vec!["hole", "hole.dSYM", "ex-ray", "galoshes", "NOTICES.md"]
    );
    assert_eq!(
        bindir_dest_names(Os::Linux),
        vec!["hole", "ex-ray", "galoshes", "NOTICES.md"]
    );
}

#[skuld::test]
fn plugin_sidecars_are_ex_ray_and_galoshes() {
    assert_eq!(plugin_sidecar_names(), &["ex-ray", "galoshes"]);
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

    // .cache/ex-ray/ex-ray-<triple>{.exe} — exactly one match
    let ex_ray = root.join(".cache").join("ex-ray");
    fs::create_dir_all(&ex_ray).unwrap();
    let ex_ray_name = if cfg!(windows) {
        "ex-ray-x86_64-pc-windows-msvc.exe"
    } else if cfg!(target_arch = "aarch64") {
        "ex-ray-aarch64-apple-darwin"
    } else {
        "ex-ray-x86_64-apple-darwin"
    };
    fs::write(ex_ray.join(ex_ray_name), b"fake ex-ray").unwrap();

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
fn bindir_errors_when_ex_ray_glob_has_zero_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Set up only the hole binary, no ex-ray glob match.
    let target = root.join("target").join("debug");
    fs::create_dir_all(&target).unwrap();
    let name = if cfg!(windows) { "hole.exe" } else { "hole" };
    fs::write(target.join(name), b"x").unwrap();

    let err = bindir_files(Profile::Debug, root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no files matched") && msg.contains("ex-ray"),
        "expected ex-ray glob error, got: {msg}"
    );
}

#[skuld::test]
fn bindir_errors_when_ex_ray_glob_has_multiple_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let target = root.join("target").join("debug");
    fs::create_dir_all(&target).unwrap();
    let name = if cfg!(windows) { "hole.exe" } else { "hole" };
    fs::write(target.join(name), b"x").unwrap();

    let ex_ray = root.join(".cache").join("ex-ray");
    fs::create_dir_all(&ex_ray).unwrap();
    // Two matches — should error.
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    fs::write(ex_ray.join(format!("ex-ray-a{suffix}")), b"x").unwrap();
    fs::write(ex_ray.join(format!("ex-ray-b{suffix}")), b"x").unwrap();

    let err = bindir_files(Profile::Debug, root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expected exactly 1 file") && msg.contains("ex-ray"),
        "expected multiple-match error, got: {msg}"
    );
}
