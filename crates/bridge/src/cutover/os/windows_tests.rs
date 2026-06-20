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

// All-or-nothing orchestration, mirroring the macOS `swap_tests` recording fake:
// a failure at EACH step (rename-away, move-in, a later image) must roll the
// committed swaps back to the prior consistent set and defer the destructive
// `.old-*` delete until the WHOLE set commits. Driven through the pure
// orchestrator with a path-only recording fake (no filesystem, no privilege).

use std::cell::RefCell;

/// Which step the fake fails, identified by image index.
#[derive(Default)]
struct RecordingOps {
    log: RefCell<Vec<String>>,
    fail_rename_away_on: Option<usize>,
    fail_move_in_on: Option<usize>,
}

impl WindowsSwapStep for RecordingOps {
    fn rename_away(&self, index: usize, installed: &Path, old: &Path) -> std::io::Result<()> {
        if self.fail_rename_away_on == Some(index) {
            self.log.borrow_mut().push(format!("rename-away-FAIL[{index}]"));
            return Err(std::io::Error::other("injected rename-away failure"));
        }
        self.log
            .borrow_mut()
            .push(format!("rename-away[{index}] {installed:?}->{old:?}"));
        Ok(())
    }
    fn move_in(&self, index: usize, staged: &Path, installed: &Path) -> std::io::Result<()> {
        if self.fail_move_in_on == Some(index) {
            self.log.borrow_mut().push(format!("move-in-FAIL[{index}]"));
            return Err(std::io::Error::other("injected move-in failure"));
        }
        self.log
            .borrow_mut()
            .push(format!("move-in[{index}] {staged:?}->{installed:?}"));
        Ok(())
    }
    fn restore_half_swapped(&self, index: usize, old: &Path, installed: &Path) {
        self.log
            .borrow_mut()
            .push(format!("restore-half[{index}] {old:?}->{installed:?}"));
    }
    fn undo(&self, index: usize, installed: &Path, staged: &Path, old: &Path) {
        self.log.borrow_mut().push(format!(
            "undo[{index}] {installed:?}->{staged:?},{old:?}->{installed:?}"
        ));
    }
    fn remove_old(&self, index: usize, old: &Path) {
        self.log.borrow_mut().push(format!("remove-old[{index}] {old:?}"));
    }
}

fn sample_images() -> Vec<ImageMove> {
    vec![
        ImageMove {
            installed: PathBuf::from(r"C:\hole\hole.exe"),
            staged: PathBuf::from(r"C:\hole\.staging\hole.exe"),
        },
        ImageMove {
            installed: PathBuf::from(r"C:\hole\galoshes"),
            staged: PathBuf::from(r"C:\hole\.staging\galoshes"),
        },
        ImageMove {
            installed: PathBuf::from(r"C:\hole\wintun.dll"),
            staged: PathBuf::from(r"C:\hole\.staging\wintun.dll"),
        },
    ]
}

#[skuld::test]
fn execute_swaps_rename_away_failure_on_first_image_touches_nothing() {
    let images = sample_images();
    let ops = RecordingOps {
        fail_rename_away_on: Some(0),
        ..Default::default()
    };
    let err = execute_image_swaps(&images, "0.3.0", &ops).expect_err("a rename-away failure must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    // Nothing committed -> nothing to undo and no destructive delete.
    assert_eq!(*ops.log.borrow(), vec!["rename-away-FAIL[0]".to_string()]);
}

#[skuld::test]
fn execute_swaps_move_in_failure_restores_the_half_swapped_then_undoes_earlier() {
    let images = sample_images();
    let ops = RecordingOps {
        // Image 1's move-in fails AFTER image 0 fully committed and image 1's
        // rename-away already moved the live binary aside.
        fail_move_in_on: Some(1),
        ..Default::default()
    };
    let err = execute_image_swaps(&images, "0.3.0", &ops).expect_err("a move-in failure must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    let log = ops.log.borrow();
    assert_eq!(
        *log,
        vec![
            "rename-away[0] \"C:\\\\hole\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe.old-0.3.0\"".to_string(),
            "move-in[0] \"C:\\\\hole\\\\.staging\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe\"".to_string(),
            "rename-away[1] \"C:\\\\hole\\\\galoshes\"->\"C:\\\\hole\\\\galoshes.old-0.3.0\"".to_string(),
            "move-in-FAIL[1]".to_string(),
            // The half-swapped image 1 gets its old binary restored first, then
            // the committed image 0 is undone. NO destructive remove-old anywhere.
            "restore-half[1] \"C:\\\\hole\\\\galoshes.old-0.3.0\"->\"C:\\\\hole\\\\galoshes\"".to_string(),
            "undo[0] \"C:\\\\hole\\\\hole.exe\"->\"C:\\\\hole\\\\.staging\\\\hole.exe\",\"C:\\\\hole\\\\hole.exe.old-0.3.0\"->\"C:\\\\hole\\\\hole.exe\"".to_string(),
        ],
        "a move-in failure must restore the half-swapped image and undo earlier ones, deleting nothing"
    );
}

#[skuld::test]
fn execute_swaps_later_image_rename_away_failure_undoes_all_prior() {
    let images = sample_images();
    let ops = RecordingOps {
        // Image 2's rename-away fails after images 0 and 1 fully committed.
        fail_rename_away_on: Some(2),
        ..Default::default()
    };
    let err = execute_image_swaps(&images, "0.3.0", &ops).expect_err("a later-image failure must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    let log = ops.log.borrow();
    assert_eq!(
        *log,
        vec![
            "rename-away[0] \"C:\\\\hole\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe.old-0.3.0\"".to_string(),
            "move-in[0] \"C:\\\\hole\\\\.staging\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe\"".to_string(),
            "rename-away[1] \"C:\\\\hole\\\\galoshes\"->\"C:\\\\hole\\\\galoshes.old-0.3.0\"".to_string(),
            "move-in[1] \"C:\\\\hole\\\\.staging\\\\galoshes\"->\"C:\\\\hole\\\\galoshes\"".to_string(),
            "rename-away-FAIL[2]".to_string(),
            // Image 2's rename-away never touched the disk, so only the committed
            // images unwind, in reverse. No destructive remove-old.
            "undo[1] \"C:\\\\hole\\\\galoshes\"->\"C:\\\\hole\\\\.staging\\\\galoshes\",\"C:\\\\hole\\\\galoshes.old-0.3.0\"->\"C:\\\\hole\\\\galoshes\"".to_string(),
            "undo[0] \"C:\\\\hole\\\\hole.exe\"->\"C:\\\\hole\\\\.staging\\\\hole.exe\",\"C:\\\\hole\\\\hole.exe.old-0.3.0\"->\"C:\\\\hole\\\\hole.exe\"".to_string(),
        ],
        "a later-image failure must undo every committed swap in reverse, deleting nothing"
    );
}

#[skuld::test]
fn execute_swaps_full_success_defers_remove_old_until_the_whole_set_commits() {
    let images = sample_images();
    let ops = RecordingOps::default();
    execute_image_swaps(&images, "0.3.0", &ops).unwrap();

    let log = ops.log.borrow();
    // Every image swaps FIRST; only then are the swapped-out old binaries removed
    // (the delete must not interleave with the swaps, else a rollback after a
    // delete is impossible).
    assert_eq!(
        *log,
        vec![
            "rename-away[0] \"C:\\\\hole\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe.old-0.3.0\"".to_string(),
            "move-in[0] \"C:\\\\hole\\\\.staging\\\\hole.exe\"->\"C:\\\\hole\\\\hole.exe\"".to_string(),
            "rename-away[1] \"C:\\\\hole\\\\galoshes\"->\"C:\\\\hole\\\\galoshes.old-0.3.0\"".to_string(),
            "move-in[1] \"C:\\\\hole\\\\.staging\\\\galoshes\"->\"C:\\\\hole\\\\galoshes\"".to_string(),
            "rename-away[2] \"C:\\\\hole\\\\wintun.dll\"->\"C:\\\\hole\\\\wintun.dll.old-0.3.0\"".to_string(),
            "move-in[2] \"C:\\\\hole\\\\.staging\\\\wintun.dll\"->\"C:\\\\hole\\\\wintun.dll\"".to_string(),
            "remove-old[0] \"C:\\\\hole\\\\hole.exe.old-0.3.0\"".to_string(),
            "remove-old[1] \"C:\\\\hole\\\\galoshes.old-0.3.0\"".to_string(),
            "remove-old[2] \"C:\\\\hole\\\\wintun.dll.old-0.3.0\"".to_string(),
        ]
    );
}
