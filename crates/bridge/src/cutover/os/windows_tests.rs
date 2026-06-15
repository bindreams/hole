use super::*;

#[skuld::test]
fn old_name_appends_dotold_version_keeping_dir() {
    let installed = Path::new(r"C:\Program Files\hole\hole.exe");
    let old = old_name(installed, "0.3.0");
    assert_eq!(old, Path::new(r"C:\Program Files\hole\hole.exe.old-0.3.0"));
}

#[skuld::test]
fn old_name_handles_extensionless_binary() {
    let installed = Path::new(r"C:\Program Files\hole\galoshes");
    let old = old_name(installed, "0.3.0");
    assert_eq!(old, Path::new(r"C:\Program Files\hole\galoshes.old-0.3.0"));
}

/// Build a temp image: write `installed` with `old_bytes` and `staged` (a sibling
/// of `installed`, same volume) with `new_bytes`. Returns the `ImageMove`.
#[cfg(test)]
fn temp_image(dir: &Path, stem: &str, old_bytes: &[u8], new_bytes: &[u8]) -> ImageMove {
    let installed = dir.join(stem);
    let staged = dir.join(format!("{stem}.staged"));
    std::fs::write(&installed, old_bytes).unwrap();
    std::fs::write(&staged, new_bytes).unwrap();
    ImageMove { installed, staged }
}

#[skuld::test]
fn swap_images_is_all_or_nothing_on_mid_loop_failure() {
    let dir = tempfile::tempdir().unwrap();

    // Three images; image index 1 (the second) will fail its move-in because its
    // staged source is removed before the swap, so `rename(staged -> installed)`
    // hits ENOENT after `rename(installed -> old)` already moved the live binary
    // aside. A correct all-or-nothing swap must restore image 0 AND image 1 to
    // their prior consistent state and error — never leave a mixed old/new set.
    let img0 = temp_image(dir.path(), "hole.exe", b"old0", b"new0");
    let img1 = temp_image(dir.path(), "galoshes", b"old1", b"new1");
    let img2 = temp_image(dir.path(), "wintun.dll", b"old2", b"new2");

    // Inject the failure on image 1: delete its staged source.
    std::fs::remove_file(&img1.staged).unwrap();

    let mut os = WindowsCutoverOs {
        images: vec![img0.clone(), img1.clone(), img2.clone()],
        target_version: "0.3.0".into(),
    };
    let err = os
        .swap_images()
        .expect_err("a mid-loop failure must error, not silently mix");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

    // Every canonical path must hold its ORIGINAL bytes (no mixed set).
    assert_eq!(std::fs::read(&img0.installed).unwrap(), b"old0", "image 0 restored");
    assert_eq!(
        std::fs::read(&img1.installed).unwrap(),
        b"old1",
        "failed image restored"
    );
    assert_eq!(
        std::fs::read(&img2.installed).unwrap(),
        b"old2",
        "untouched image intact"
    );

    // The staged new bytes must be restored to their staging paths (image 0 only;
    // image 1's staging was the injected-missing source). No `.old-*` survivors.
    assert_eq!(std::fs::read(&img0.staged).unwrap(), b"new0", "image 0 staged restored");
    assert!(
        !old_name(&img0.installed, "0.3.0").exists(),
        "no leftover .old-* after rollback"
    );
    assert!(!old_name(&img1.installed, "0.3.0").exists());
}

#[skuld::test]
fn swap_images_succeeds_when_all_present() {
    let dir = tempfile::tempdir().unwrap();
    let img0 = temp_image(dir.path(), "hole.exe", b"old0", b"new0");
    let img1 = temp_image(dir.path(), "galoshes", b"old1", b"new1");

    let mut os = WindowsCutoverOs {
        images: vec![img0.clone(), img1.clone()],
        target_version: "0.3.0".into(),
    };
    os.swap_images().unwrap();

    assert_eq!(std::fs::read(&img0.installed).unwrap(), b"new0");
    assert_eq!(std::fs::read(&img1.installed).unwrap(), b"new1");
    // On full success the swapped-out old binaries are best-effort removed.
    assert!(!old_name(&img0.installed, "0.3.0").exists());
    assert!(!old_name(&img1.installed, "0.3.0").exists());
}
