use crate::update_archive::build_update_archive;
use crate::Profile;
#[cfg(target_os = "windows")]
use std::fs;

/// Minimal fake repo tree that satisfies `bindir_files` on the host. Windows-only
/// helper: only the Windows arm resolves a BINDIR from disk; macOS packs the
/// built `.app` and needs no fake tree.
#[cfg(target_os = "windows")]
fn fake_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let release = root.join("target/release");
    fs::create_dir_all(&release).unwrap();
    fs::write(release.join("hole.exe"), b"hole").unwrap();
    fs::write(release.join("galoshes.exe"), b"galoshes").unwrap();
    fs::write(release.join("hole.pdb"), b"pdb").unwrap();
    let wintun = root.join(".cache/wintun");
    fs::create_dir_all(&wintun).unwrap();
    fs::write(wintun.join("wintun.dll"), b"wt").unwrap();
    let exray = root.join(".cache/ex-ray");
    fs::create_dir_all(&exray).unwrap();
    fs::write(exray.join("ex-ray-x86_64-pc-windows-msvc.exe"), b"exray").unwrap();
    fs::write(root.join("NOTICES.md"), b"notices").unwrap();
    dir
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn windows_archive_entry_names_equal_bindir_dest_names() {
    let repo = fake_repo();
    let out = repo.path().join("hole.zip");
    build_update_archive(Profile::Release, repo.path(), &out).unwrap();

    let mut zip = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
    let mut names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();
    let mut expected = xtask_lib::bindir::bindir_dest_names(xtask_lib::bindir::Os::Windows);
    expected.sort();
    assert_eq!(
        names, expected,
        "zip entries must equal bindir_dest_names, incl. ex-ray.exe"
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_archive_tars_the_built_app() {
    let repo = tempfile::tempdir().unwrap();
    let macos = repo.path().join("target/release/bundle/macos/Hole.app/Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    std::fs::write(macos.join("hole"), b"MACHO").unwrap();
    let out = repo.path().join("hole.tar.gz");
    build_update_archive(Profile::Release, repo.path(), &out).unwrap();

    let dec = flate2::read::GzDecoder::new(std::fs::File::open(&out).unwrap());
    let mut tar = tar::Archive::new(dec);
    assert!(tar
        .entries()
        .unwrap()
        .any(|e| e.unwrap().path().unwrap().to_string_lossy() == "Hole.app/Contents/MacOS/hole"));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn find_built_app_errors_on_zero_or_two_bundles() {
    let repo = tempfile::tempdir().unwrap();
    let macos = repo.path().join("target/release/bundle/macos");
    std::fs::create_dir_all(macos.join("A.app")).unwrap();
    std::fs::create_dir_all(macos.join("B.app")).unwrap();
    let out = repo.path().join("hole.tar.gz");
    let err = build_update_archive(Profile::Release, repo.path(), &out).unwrap_err();
    assert!(err.to_string().contains("exactly one .app"), "got: {err}");
}
