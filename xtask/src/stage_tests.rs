use crate::bindir::{BindirFile, BindirSource};
use crate::stage::stage;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};

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

// Concurrency and atomicity (#1082) ===================================================================================

/// `dest` must never be written through: when it is already a hard link of
/// `src` (what a concurrent stager leaves behind), copying onto it would
/// truncate `src` itself.
#[skuld::test]
fn stage_leaves_src_intact_when_dest_is_a_hard_link_of_src() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let src = src_dir.path().join("hole");
    fs::write(&src, b"hole content").unwrap();
    let dest = dst_dir.path().join("hole");
    fs::hard_link(&src, &dest).unwrap();

    stage(dst_dir.path(), &[BindirFile::new(src.clone(), "hole")]).unwrap();

    assert_eq!(fs::read(&src).unwrap(), b"hole content");
    assert_eq!(fs::read(&dest).unwrap(), b"hole content");
}

#[skuld::test]
fn stage_leaves_only_the_staged_entries_in_out_dir() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let src = src_dir.path().join("hole");
    fs::write(&src, b"hole content").unwrap();
    let bundle = src_dir.path().join("hole.dSYM");
    fs::create_dir(&bundle).unwrap();
    fs::write(bundle.join("a"), b"a").unwrap();

    let files = vec![BindirFile::new(src, "hole"), BindirFile::directory(bundle, "hole.dSYM")];
    // Twice: the second pass replaces both entries.
    stage(dst_dir.path(), &files).unwrap();
    stage(dst_dir.path(), &files).unwrap();

    let mut names: Vec<_> = fs::read_dir(dst_dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["hole", "hole.dSYM"]);
}

const STAGERS: usize = 4;
const STAGES_PER_STAGER: usize = 150;

/// Several stagers race on one `dest` while a reader polls it until they all
/// finish. Every `stage` must return `Ok` with `dest` complete, `src` must stay
/// whole, and the reader must never find `dest` missing or short: the old
/// remove-then-link left a window with no file (ENOENT) and a copy-onto-a-link
/// fallback that truncated `src`.
#[skuld::test]
fn concurrent_file_staging_never_hides_or_corrupts_dest() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let content = vec![0xAB_u8; 64 * 1024];
    let src = src_dir.path().join("hole");
    fs::write(&src, &content).unwrap();
    let dest = dst_dir.path().join("hole");
    let files = vec![BindirFile::new(src.clone(), "hole")];
    // The reader starts from a present dest, as in a test run that staged first.
    stage(dst_dir.path(), &files).unwrap();

    let done = AtomicBool::new(false);
    let reader_violations = std::sync::Mutex::new(Vec::<String>::new());
    let stage_failures = std::sync::Mutex::new(Vec::<String>::new());

    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            // `done` is a real signal set after every stager has joined, not a deadline.
            while !done.load(Ordering::Acquire) {
                match fs::read(&dest) {
                    Ok(bytes) if bytes == content => {}
                    Ok(bytes) => reader_violations.lock().unwrap().push(format!(
                        "dest read back {} bytes, expected {}",
                        bytes.len(),
                        content.len()
                    )),
                    Err(e) => reader_violations.lock().unwrap().push(format!("dest unreadable: {e}")),
                }
            }
        });

        let stagers: Vec<_> = (0..STAGERS)
            .map(|_| {
                scope.spawn(|| {
                    for i in 0..STAGES_PER_STAGER {
                        if let Err(e) = stage(dst_dir.path(), &files) {
                            stage_failures.lock().unwrap().push(format!("stage #{i}: {e:#}"));
                        }
                        let src_len = fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
                        if src_len != content.len() as u64 {
                            stage_failures
                                .lock()
                                .unwrap()
                                .push(format!("stage #{i}: src is {src_len} bytes after staging"));
                        }
                    }
                })
            })
            .collect();
        for s in stagers {
            s.join().unwrap();
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap();
    });

    let stage_failures = stage_failures.into_inner().unwrap();
    let reader_violations = reader_violations.into_inner().unwrap();
    assert!(
        stage_failures.is_empty() && reader_violations.is_empty(),
        "{} stage failures, first: {:#?}\n{} reader violations, first: {:#?}",
        stage_failures.len(),
        &stage_failures[..stage_failures.len().min(5)],
        reader_violations.len(),
        &reader_violations[..reader_violations.len().min(5)]
    );
    assert_eq!(fs::read(&dest).unwrap(), content);
}

/// Directory bundles take the same path: concurrent stagers all succeed and the
/// bundle ends complete. Unix only: bundles are macOS `.dSYM`s, never staged on Windows, whose
/// directory renames answer a concurrent move of the same directory with `ACCESS_DENIED`.
#[cfg(unix)]
#[skuld::test]
fn concurrent_directory_staging_leaves_a_complete_bundle() {
    let src_dir = tempfile::tempdir().unwrap();
    let dst_dir = tempfile::tempdir().unwrap();

    let bundle = src_dir.path().join("hole.dSYM");
    fs::create_dir_all(bundle.join("Contents")).unwrap();
    fs::write(bundle.join("Contents").join("Info.plist"), b"<plist/>").unwrap();
    let files = vec![BindirFile::directory(bundle, "hole.dSYM")];

    let failures = std::sync::Mutex::new(Vec::<String>::new());
    std::thread::scope(|scope| {
        for _ in 0..STAGERS {
            scope.spawn(|| {
                for i in 0..STAGES_PER_STAGER {
                    if let Err(e) = stage(dst_dir.path(), &files) {
                        failures.lock().unwrap().push(format!("stage #{i}: {e:#}"));
                    }
                }
            });
        }
    });

    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} stage failures, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(5)]
    );
    assert_eq!(
        fs::read(dst_dir.path().join("hole.dSYM").join("Contents").join("Info.plist")).unwrap(),
        b"<plist/>"
    );
}
