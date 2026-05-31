use crate::bindir::{BindirFile, BindirSource};
use crate::stage::stage;
use std::fs;

#[skuld::test]
fn stage_creates_out_dir_and_links_or_copies_files() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    // Two source files. Stage them under renamed dest names.
    let src1 = src_dir.path().join("hole.exe");
    let src2 = src_dir.path().join("ex-ray-x86_64.exe");
    fs::write(&src1, b"hole content").unwrap();
    fs::write(&src2, b"plugin content").unwrap();

    let files = vec![BindirFile::new(src1, "hole.exe"), BindirFile::new(src2, "ex-ray.exe")];

    // Use a fresh subdirectory of dst_dir to verify create_dir_all is called.
    let out = dst_dir.path().join("staged");
    stage(&out, &files).unwrap();

    let staged_hole = out.join("hole.exe");
    let staged_plugin = out.join("ex-ray.exe");
    assert!(staged_hole.is_file());
    assert!(staged_plugin.is_file());
    assert_eq!(fs::read(&staged_hole).unwrap(), b"hole content");
    assert_eq!(fs::read(&staged_plugin).unwrap(), b"plugin content");
}

#[skuld::test]
fn stage_replaces_existing_dest_file() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let src = src_dir.path().join("hole.exe");
    fs::write(&src, b"new content").unwrap();

    // Pre-existing file at the destination — must be replaced.
    let dst = dst_dir.path().join("hole.exe");
    fs::write(&dst, b"old content").unwrap();

    let files = vec![BindirFile::new(src, "hole.exe")];
    stage(dst_dir.path(), &files).unwrap();

    assert_eq!(fs::read(&dst).unwrap(), b"new content");
}

#[skuld::test]
fn stage_errors_when_source_missing() {
    let dst_dir = tempfile::tempdir().unwrap();
    let files = vec![BindirFile::new(
        std::path::PathBuf::from("/definitely/not/a/real/path/hole.exe"),
        "hole.exe",
    )];
    let err = stage(dst_dir.path(), &files).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not exist") && msg.contains("hole.exe"),
        "expected missing-source error, got: {msg}"
    );
}

#[skuld::test]
fn stage_recursively_copies_directory_bundle() {
    // Directory-bundle support was added for macOS `.dSYM` in
    // bindreams/hole#393. Verify the recursion preserves nested
    // structure.
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let bundle = src_dir.path().join("hole.dSYM");
    fs::create_dir_all(bundle.join("Contents").join("Resources").join("DWARF")).unwrap();
    fs::write(bundle.join("Contents").join("Info.plist"), b"<plist/>").unwrap();
    fs::write(
        bundle.join("Contents").join("Resources").join("DWARF").join("hole"),
        b"dwarf",
    )
    .unwrap();

    let files = vec![BindirFile::directory(bundle, "hole.dSYM")];
    stage(dst_dir.path(), &files).unwrap();

    let staged = dst_dir.path().join("hole.dSYM");
    assert!(staged.is_dir());
    assert_eq!(
        fs::read(staged.join("Contents").join("Info.plist")).unwrap(),
        b"<plist/>"
    );
    assert_eq!(
        fs::read(staged.join("Contents").join("Resources").join("DWARF").join("hole")).unwrap(),
        b"dwarf"
    );
}

#[skuld::test]
fn stage_directory_replaces_existing_bundle() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let bundle = src_dir.path().join("hole.dSYM");
    fs::create_dir(&bundle).unwrap();
    fs::write(bundle.join("new.txt"), b"new").unwrap();

    // Pre-existing destination bundle with stale file — must be wiped
    // before the new tree is copied in.
    let stale = dst_dir.path().join("hole.dSYM");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("stale.txt"), b"stale").unwrap();

    let files = vec![BindirFile::directory(bundle, "hole.dSYM")];
    stage(dst_dir.path(), &files).unwrap();

    // Stale file is gone, new file is present.
    assert!(!stale.join("stale.txt").exists(), "stale file should have been removed");
    assert_eq!(fs::read(stale.join("new.txt")).unwrap(), b"new");
}

#[skuld::test]
fn stage_errors_when_directory_source_missing() {
    let dst_dir = tempfile::tempdir().unwrap();
    let files = vec![BindirFile {
        source: BindirSource::Directory(std::path::PathBuf::from("/no/such/bundle.dSYM")),
        dest_name: "bundle.dSYM".to_string(),
    }];
    let err = stage(dst_dir.path(), &files).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not exist") && msg.contains("bundle.dSYM"),
        "expected missing-directory error, got: {msg}"
    );
}

#[skuld::test]
fn stage_rejects_dest_name_with_path_separator() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("hole.exe");
    fs::write(&src, b"x").unwrap();

    let files = vec![BindirFile::new(src, "subdir/hole.exe")];
    let err = stage(dst_dir.path(), &files).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("path separators"),
        "expected path-separator rejection, got: {msg}"
    );
}
