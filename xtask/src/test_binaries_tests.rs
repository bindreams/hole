use std::collections::HashSet;
use std::path::PathBuf;

use tempfile::TempDir;

use crate::test_binaries::{
    assign_dest_names, bindir_files_for_artifact, exe_suffix, extract_test_artifacts, stale_files_to_remove,
    TestArtifact,
};

fn art(name: &str, kind: &str, exe: &str) -> TestArtifact {
    TestArtifact {
        target_name: name.to_string(),
        target_kind: kind.to_string(),
        executable: PathBuf::from(exe),
    }
}

// extract_test_artifacts ==============================================================================================

/// Build a canned JSON message stream containing: a test binary artifact (keep),
/// a non-test build-script artifact (drop), a test-profile non-binary artifact
/// (drop — no executable), a non-artifact "build-finished" message (drop).
fn canned_json_stream() -> Vec<u8> {
    let test_bin = r#"{"reason":"compiler-artifact","package_id":"path+file:///a#hole-bridge@0.1.0","manifest_path":"/a/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"hole_bridge","src_path":"/a/src/lib.rs","edition":"2021","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"0","debuginfo":2,"debug_assertions":true,"overflow_checks":true,"test":true},"features":[],"filenames":["/a/target/debug/deps/libhole_bridge.rlib"],"executable":"/a/target/debug/deps/hole_bridge-abc.exe","fresh":false}"#;
    let build_script = r#"{"reason":"compiler-artifact","package_id":"path+file:///a#hole-bridge@0.1.0","manifest_path":"/a/Cargo.toml","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build","src_path":"/a/build.rs","edition":"2021","doc":false,"doctest":false,"test":false},"profile":{"opt_level":"0","debuginfo":0,"debug_assertions":true,"overflow_checks":true,"test":false},"features":[],"filenames":["/a/target/debug/build/script.exe"],"executable":null,"fresh":true}"#;
    let rlib_only = r#"{"reason":"compiler-artifact","package_id":"path+file:///a#hole-common@0.1.0","manifest_path":"/a/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"hole_common","src_path":"/a/src/lib.rs","edition":"2021","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"0","debuginfo":2,"debug_assertions":true,"overflow_checks":true,"test":true},"features":[],"filenames":["/a/target/debug/libhole_common.rlib"],"executable":null,"fresh":false}"#;
    let build_finished = r#"{"reason":"build-finished","success":true}"#;

    [test_bin, build_script, rlib_only, build_finished]
        .join("\n")
        .into_bytes()
}

#[skuld::test]
fn extract_keeps_test_binary_and_drops_non_test_and_null_exe() {
    let stream = canned_json_stream();
    let out = extract_test_artifacts(std::io::Cursor::new(stream)).unwrap();
    assert_eq!(out.len(), 1, "expected 1 test binary, got {out:?}");
    assert_eq!(out[0].target_name, "hole_bridge");
    assert_eq!(out[0].target_kind, "lib");
    assert_eq!(
        out[0].executable,
        PathBuf::from("/a/target/debug/deps/hole_bridge-abc.exe")
    );
}

// assign_dest_names ===================================================================================================

#[skuld::test]
fn assign_dest_names_empty() {
    let out = assign_dest_names(Vec::new()).unwrap();
    assert!(out.is_empty());
}

#[skuld::test]
fn assign_dest_names_no_collision_uses_default_form() {
    let ext = exe_suffix();
    let input = vec![
        art("hole_bridge", "lib", "/t/hole_bridge-abc"),
        art("hole", "lib", "/t/hole-def"),
        art("hole_common", "lib", "/t/hole_common-ghi"),
    ];
    let out = assign_dest_names(input).unwrap();
    let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
    // Sorted alphabetically by the impl.
    assert_eq!(
        names,
        vec![
            format!("hole.test{ext}").as_str(),
            format!("hole_bridge.test{ext}").as_str(),
            format!("hole_common.test{ext}").as_str(),
        ]
    );
}

#[skuld::test]
fn assign_dest_names_collision_disambiguates_by_kind() {
    let ext = exe_suffix();
    // Same target_name "hole_bridge" — one lib unit test, one integration test.
    let input = vec![
        art("hole_bridge", "lib", "/t/hole_bridge-abc"),
        art("hole_bridge", "test", "/t/hole_bridge-def"),
    ];
    let out = assign_dest_names(input).unwrap();
    let names: Vec<_> = out.iter().map(|(n, _)| n.clone()).collect();
    assert_eq!(
        names,
        vec![
            format!("hole_bridge-lib.test{ext}"),
            format!("hole_bridge-test.test{ext}"),
        ]
    );
}

#[skuld::test]
fn assign_dest_names_unresolvable_collision_errors() {
    // Two artifacts with the same target_name AND same kind. Even after
    // disambiguation they'd collide. Must error, not silently overwrite.
    let input = vec![art("hole_bridge", "lib", "/t/a"), art("hole_bridge", "lib", "/t/b")];
    let err = assign_dest_names(input).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("collision") || msg.contains("Collision"),
        "expected collision error, got: {msg}"
    );
}

// bindir_files_for_artifact ===========================================================================================

#[skuld::test]
fn bindir_files_exe_only_when_no_pdb() {
    let tmp = TempDir::new().unwrap();
    let exe = tmp.path().join("hole_bridge-abc.exe");
    std::fs::write(&exe, b"").unwrap();
    // No .pdb alongside — only the exe should be emitted.
    let a = art("hole_bridge", "lib", exe.to_str().unwrap());
    let files = bindir_files_for_artifact("hole_bridge.test.exe", &a);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].dest_name, "hole_bridge.test.exe");
    assert_eq!(files[0].source, exe);
}

#[cfg(windows)]
#[skuld::test]
fn bindir_files_includes_pdb_when_present() {
    let tmp = TempDir::new().unwrap();
    let exe = tmp.path().join("hole_bridge-abc.exe");
    let pdb = tmp.path().join("hole_bridge-abc.pdb");
    std::fs::write(&exe, b"").unwrap();
    std::fs::write(&pdb, b"").unwrap();

    let a = art("hole_bridge", "lib", exe.to_str().unwrap());
    let files = bindir_files_for_artifact("hole_bridge.test.exe", &a);
    assert_eq!(files.len(), 2);
    let names: HashSet<&str> = files.iter().map(|f| f.dest_name.as_str()).collect();
    assert!(names.contains("hole_bridge.test.exe"));
    assert!(names.contains("hole_bridge.test.pdb"));
}

// stale_files_to_remove ===============================================================================================

#[skuld::test]
fn stale_files_nonexistent_dir_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("does_not_exist");
    let keep = HashSet::new();
    let stale = stale_files_to_remove(&missing, &keep).unwrap();
    assert!(stale.is_empty());
}

#[skuld::test]
fn stale_files_identifies_staged_artifacts_not_in_keep() {
    let ext = exe_suffix();
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Staged that we want to keep.
    let keep_name = format!("hole_bridge.test{ext}");
    std::fs::write(dir.join(&keep_name), b"").unwrap();

    // Staged that is now stale.
    let stale_name = format!("gone_crate.test{ext}");
    std::fs::write(dir.join(&stale_name), b"").unwrap();

    // Unrelated file, must be left alone.
    std::fs::write(dir.join("README.md"), b"").unwrap();

    let mut keep = HashSet::new();
    keep.insert(keep_name.clone());

    let stale = stale_files_to_remove(dir, &keep).unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].file_name().unwrap(), stale_name.as_str());
}

#[cfg(windows)]
#[skuld::test]
fn stale_files_preserves_current_build_pdbs() {
    // Regression guard: the stale sweep's `keep` set must include PDB names
    // produced by `bindir_files_for_artifact` — otherwise the current build's
    // PDBs would be swept on every run. This mirrors the caller's contract.
    let tmp = TempDir::new().unwrap();
    let stage_dir = tmp.path();

    // Simulate the caller: stage hole_bridge.test.exe + .pdb alongside.
    let exe_dest = "hole_bridge.test.exe";
    let pdb_dest = "hole_bridge.test.pdb";
    std::fs::write(stage_dir.join(exe_dest), b"").unwrap();
    std::fs::write(stage_dir.join(pdb_dest), b"").unwrap();

    // Build the `keep` set the way `stage_test_binaries` does.
    let mut keep = HashSet::new();
    keep.insert(exe_dest.to_string());
    keep.insert(pdb_dest.to_string());

    let stale = stale_files_to_remove(stage_dir, &keep).unwrap();
    assert!(
        stale.is_empty(),
        "current-build exe+pdb must survive stale sweep, got {stale:?}"
    );
}

#[cfg(windows)]
#[skuld::test]
fn stale_files_identifies_stale_pdbs() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Only the current exe's name is in keep; its companion pdb (not in keep)
    // would still be caught — so a real caller should include both in `keep`.
    // This test just confirms .test.pdb is considered "staged-looking".
    std::fs::write(dir.join("gone.test.exe"), b"").unwrap();
    std::fs::write(dir.join("gone.test.pdb"), b"").unwrap();
    std::fs::write(dir.join("plain.txt"), b"").unwrap();

    let keep = HashSet::new();
    let stale = stale_files_to_remove(dir, &keep).unwrap();
    let names: HashSet<_> = stale
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains("gone.test.exe"));
    assert!(names.contains("gone.test.pdb"));
    assert!(!names.contains("plain.txt"));
}
