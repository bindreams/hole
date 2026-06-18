use super::*;

/// Build a fake `.app` bundle under `parent` with the given name and
/// `CFBundleIdentifier`. Returns the bundle path.
fn make_bundle(parent: &std::path::Path, app_name: &str, bundle_id: &str) -> std::path::PathBuf {
    let app = parent.join(app_name);
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Hole</string>
	<key>CFBundleIdentifier</key>
	<string>{bundle_id}</string>
	<key>CFBundleVersion</key>
	<string>0.3.0</string>
</dict>
</plist>
"#
    );
    std::fs::write(contents.join("Info.plist"), plist).unwrap();
    std::fs::write(contents.join("MacOS").join("hole"), b"#!/bin/sh\n").unwrap();
    app
}

#[skuld::test]
fn resolve_app_dest_walks_up_from_the_inner_macho() {
    // The GUI's `current_exe` lands at `<.app>/Contents/MacOS/hole`; resolving
    // walks up three components to the bundle root.
    let exe = std::path::Path::new("/Applications/Hole.app/Contents/MacOS/hole");
    assert_eq!(
        resolve_app_dest_from_exe(exe),
        Some(std::path::PathBuf::from("/Applications/Hole.app"))
    );
}

#[skuld::test]
fn resolve_app_dest_rejects_a_non_bundle_layout() {
    // A binary not inside a `Contents/MacOS` of a `.app` has no bundle to derive.
    assert_eq!(
        resolve_app_dest_from_exe(std::path::Path::new("/usr/local/bin/hole")),
        None
    );
    assert_eq!(
        resolve_app_dest_from_exe(std::path::Path::new("/Applications/Hole.app/Contents/hole")),
        None,
        "missing the MacOS component"
    );
    assert_eq!(
        resolve_app_dest_from_exe(std::path::Path::new("/Applications/NotAnApp/Contents/MacOS/hole")),
        None,
        "the bundle root must end in .app"
    );
}

#[skuld::test]
fn validate_app_dest_accepts_a_genuine_hole_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let app = make_bundle(tmp.path(), "Hole.app", "com.hole.app");
    validate_app_dest(&app).expect("a genuine com.hole.app bundle must validate");
}

#[skuld::test]
fn validate_app_dest_rejects_a_missing_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("Hole.app");
    let err = validate_app_dest(&missing).expect_err("a missing bundle must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[skuld::test]
fn validate_app_dest_rejects_a_non_app_extension() {
    let tmp = tempfile::tempdir().unwrap();
    // A genuine-looking bundle whose name does not end in `.app`.
    let bundle = make_bundle(tmp.path(), "Hole.bundle", "com.hole.app");
    validate_app_dest(&bundle).expect_err("the destination must be a `.app`");
}

#[skuld::test]
fn validate_app_dest_rejects_a_spoofed_bundle_identity() {
    // THE security case: an attacker-controlled `Evil.app` whose inner Mach-O is
    // named `hole` but whose CFBundleIdentifier is not com.hole.app. Swapping
    // onto it would let a non-admin caller make root destroy/replace an arbitrary
    // bundle. The identity, not the path, is the trust anchor.
    let tmp = tempfile::tempdir().unwrap();
    let evil = make_bundle(tmp.path(), "Evil.app", "com.evil.app");
    let err = validate_app_dest(&evil).expect_err("a foreign bundle identity must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[skuld::test]
fn validate_app_dest_rejects_a_translocation_path() {
    // App Translocation runs a quarantined copy from a randomized
    // `/private/var/folders/...` path; a swap target there is never the canonical
    // install and is a tell of a relocated/quarantined attacker copy.
    let dest = std::path::Path::new("/private/var/folders/ab/cd/T/AppTranslocation/XYZ/d/Hole.app");
    let err = validate_app_dest(dest).expect_err("a translocation path must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[skuld::test]
fn validate_app_dest_rejects_a_bundle_without_info_plist() {
    let tmp = tempfile::tempdir().unwrap();
    let app = tmp.path().join("Hole.app");
    std::fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
    validate_app_dest(&app).expect_err("a bundle missing Info.plist cannot be identity-checked");
}
