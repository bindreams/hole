use crate::bindir::*;
use crate::manifest::Os;
use crate::Profile;
use std::fs;

// The exact per-OS name set + the sidecar subset are asserted in
// `xtask-lib/src/bindir_tests.rs` (their definitions moved there). This file
// keeps the disk-resolving `bindir_files` + CLI-emission tests.

#[skuld::test]
fn bindir_names_command_emits_json_for_os() {
    let json = crate::render_bindir_names(Os::Windows, false);
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
    // The PDB / dSYM is staged so panic backtraces resolve.
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

    // The generated notices of the host platform, where `cargo xtask notices` leaves them.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let notices = root.join(crate::notices::HOST_OUTPUT);
        fs::create_dir_all(notices.parent().unwrap()).unwrap();
        fs::write(notices, b"fake notices").unwrap();
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
    // acknowledged here. That is the whole point of the regression test.
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
    assert_eq!(names, vec!["hole", "ex-ray", "galoshes"]);
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
    // Look up by name rather than index because debug symbols
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

/// With `cargo xtask deps` not run, `crates/hole/build.rs` leaves an empty file under the host's
/// own name; staging it would put a 0-byte sidecar in BINDIR.
#[skuld::test]
fn bindir_errors_when_the_host_ex_ray_is_an_empty_stub() {
    let repo = fake_repo();
    let ex_ray = repo
        .path()
        .join(".cache")
        .join("ex-ray")
        .join(crate::ex_ray::output_name());
    fs::write(&ex_ray, b"").unwrap();

    let err = bindir_files(Profile::Debug, repo.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&crate::ex_ray::output_name()) && msg.contains("cargo xtask deps"),
        "expected the deps-did-not-run error for an empty host stub, got: {msg}"
    );
}

#[skuld::test]
fn bindir_names_bundle_flag_prints_the_bundle_set() {
    let bundle: Vec<String> = serde_json::from_str(&crate::render_bindir_names(Os::Darwin, true)).unwrap();
    let full: Vec<String> = serde_json::from_str(&crate::render_bindir_names(Os::Darwin, false)).unwrap();

    assert_eq!(bundle, bundle_payload_names(Os::Darwin));
    assert!(full.contains(&"ex-ray".to_string()) && !bundle.contains(&"ex-ray".to_string()));
    assert!(full.contains(&"galoshes".to_string()) && !bundle.contains(&"galoshes".to_string()));
}

/// `NOTICES.md` ships from the file a bare `cargo xtask notices` generated for the host platform, at its one fixed path,
/// not from a file kept in the repository.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test]
fn notices_md_is_the_generated_file_of_the_host_platform() {
    let repo = fake_repo();
    let files = bindir_files(Profile::Release, repo.path()).unwrap();
    let notices = files.iter().find(|f| f.dest_name == "NOTICES.md").unwrap();
    assert_eq!(notices.source.path(), repo.path().join(".cache/notices/NOTICES.md"));
}

/// A repository where `cargo xtask notices` has not run has no notices to stage; the error names the command.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test]
fn bindir_errors_when_the_notices_were_not_generated() {
    let repo = fake_repo();
    fs::remove_file(repo.path().join(crate::notices::HOST_OUTPUT)).unwrap();

    let err = bindir_files(Profile::Debug, repo.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("NOTICES.md") && msg.contains("cargo xtask notices"),
        "expected an error naming the notices command, got: {msg}"
    );
}

#[skuld::test]
fn every_upstream_library_of_the_bindir_has_the_path_it_is_provisioned_at() {
    let mut checked = 0;
    for os in [Os::Windows, Os::Darwin, Os::Linux] {
        for entry in bindir_entries(os) {
            if entry.kind.needs_a_declared_entry() {
                checked += 1;
                let path = upstream_library_path(&entry.name)
                    .unwrap_or_else(|| panic!("{os}: `{}` has no provisioned path", entry.name));
                assert!(path.ends_with(&format!("/{}", entry.name)), "{path}");
            }
        }
    }
    assert!(checked > 0, "the Windows BINDIR ships wintun.dll as it came");
}
