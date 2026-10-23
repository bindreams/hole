use super::DirRotate;
use skuld::temp_dir;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use util::dir::testing::plant_link;
use util::dir::Dir;

fn writer(dir: &Path, limit: usize) -> DirRotate {
    DirRotate::new(Dir::open(dir, false, None).unwrap(), "bridge.log".as_ref(), limit, None)
}

/// A byte stream in which every position is told apart from its neighbours, so a lost or reordered span shows.
fn stream(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 23) as u8).collect()
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    found
}

#[skuld::test]
fn writes_append_to_the_named_file_and_a_new_writer_continues_it(#[fixture(temp_dir)] dir: &Path) {
    let mut first = writer(dir, 1024);
    first.write_all(b"one\n").unwrap();
    first.flush().unwrap();
    drop(first);

    let mut second = writer(dir, 1024);
    second.write_all(b"two\n").unwrap();
    second.flush().unwrap();

    assert_eq!(read(dir, "bridge.log"), b"one\ntwo\n");
    assert_eq!(names(dir), ["bridge.log"]);
}

/// 3000 bytes through a 1024-byte file keep exactly the active file and one rotated copy, and between them the
/// last bytes written, in order, with nothing lost or repeated.
#[skuld::test]
fn a_full_file_rotates_to_dot_one_and_one_rotated_file_is_kept(#[fixture(temp_dir)] dir: &Path) {
    let bytes = stream(3000);
    let mut w = writer(dir, 1024);
    for chunk in bytes.chunks(100) {
        w.write_all(chunk).unwrap();
    }
    w.flush().unwrap();
    drop(w);

    assert_eq!(names(dir), ["bridge.log", "bridge.log.1"]);
    let (rotated, active) = (read(dir, "bridge.log.1"), read(dir, "bridge.log"));
    assert_eq!((rotated.len(), active.len()), (1024, 3000 - 2 * 1024));
    assert_eq!([rotated, active].concat(), bytes[3000 - 1024 - 952..]);
}

#[skuld::test]
fn a_writer_counts_the_bytes_already_in_the_file(#[fixture(temp_dir)] dir: &Path) {
    let bytes = stream(120);
    let mut first = writer(dir, 100);
    first.write_all(&bytes[..60]).unwrap();
    drop(first);

    let mut second = writer(dir, 100);
    second.write_all(&bytes[60..]).unwrap();
    drop(second);

    assert_eq!(read(dir, "bridge.log.1"), bytes[..100]);
    assert_eq!(read(dir, "bridge.log"), bytes[100..]);
}

#[skuld::test]
fn a_symlink_at_the_log_name_is_not_written_through(#[fixture(temp_dir)] dir: &Path) {
    let outside = dir.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let state = dir.join("logs");
    std::fs::create_dir(&state).unwrap();
    plant_link(&outside, &state.join("bridge.log"));

    // A line that cannot be written is dropped, as it is when the file cannot be opened at all.
    let mut w = writer(&state, 1024);
    w.write_all(b"line\n").unwrap();
    w.flush().unwrap();
    drop(w);

    assert!(names(&outside).is_empty());
}

#[cfg(unix)]
#[skuld::test]
fn a_rotation_after_the_directory_is_swapped_stays_in_the_opened_directory(#[fixture(temp_dir)] dir: &Path) {
    let state = dir.join("logs");
    let outside = dir.join("outside");
    std::fs::create_dir(&state).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let mut w = writer(&state, 100);
    w.write_all(&stream(60)).unwrap();

    std::fs::rename(&state, dir.join("moved")).unwrap();
    plant_link(&outside, &state);
    w.write_all(&stream(60)).unwrap();
    w.flush().unwrap();
    drop(w);

    assert!(names(&outside).is_empty(), "the rotation followed the new link");
    assert_eq!(names(&dir.join("moved")), ["bridge.log", "bridge.log.1"]);
}

#[cfg(unix)]
#[skuld::test]
fn the_active_file_goes_to_the_owner_when_opened_and_after_each_rotation(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::MetadataExt;

    let me = dir.metadata().unwrap().uid();
    let foreign = me + 2;
    // Whether the OS lets this process give a file away: only root does.
    let scratch = dir.join("scratch");
    std::fs::write(&scratch, b"").unwrap();
    let allowed = std::os::unix::fs::chown(&scratch, Some(foreign), None).is_ok();
    let owner_of = |name: &str| dir.join(name).metadata().unwrap().uid();

    let mut w = DirRotate::new(
        Dir::open(dir, false, None).unwrap(),
        "bridge.log".as_ref(),
        64,
        Some((foreign, foreign)),
    );
    assert_eq!(owner_of("bridge.log") == foreign, allowed, "at open");

    w.write_all(&stream(100)).unwrap();
    w.flush().unwrap();
    assert_eq!(owner_of("bridge.log") == foreign, allowed, "after the rotation");
    assert!(dir.join("bridge.log.1").exists());
}

#[skuld::test]
fn a_file_already_over_the_limit_is_rotated_before_the_next_byte(#[fixture(temp_dir)] dir: &Path) {
    // A run with a larger limit left it so; the smaller limit must not wrap around.
    let old = stream(300);
    std::fs::write(dir.join("bridge.log"), &old).unwrap();

    let mut w = writer(dir, 100);
    w.write_all(b"next").unwrap();
    drop(w);

    assert_eq!(read(dir, "bridge.log.1"), old);
    assert_eq!(read(dir, "bridge.log"), b"next");
}

// A name the log cannot use ===========================================================================================

/// A directory at `name`, so that opening it as the log fails and renaming the log over it fails, until it is removed.
fn block(dir: &Path, name: &str) {
    std::fs::create_dir(dir.join(name)).unwrap();
    std::fs::write(dir.join(name).join("keep"), b"").unwrap();
}

fn unblock(dir: &Path, name: &str) {
    std::fs::remove_dir_all(dir.join(name)).unwrap();
}

/// A writer whose notices are collected.
fn noticing_writer(dir: &Path, limit: usize) -> (DirRotate, Arc<Mutex<Vec<String>>>) {
    let notices = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&notices);
    let w = DirRotate::with_notice(
        Dir::open(dir, false, None).unwrap(),
        "bridge.log".as_ref(),
        limit,
        None,
        move |err| sink.lock().unwrap().push(err.to_string()),
    );
    (w, notices)
}

/// A stream through a 100-byte log whose `.1` is a directory the log cannot be renamed over: the active file never
/// holds more than the limit, and the file that would have been `.1` is kept under the fallback name instead.
#[skuld::test]
fn a_directory_at_the_rotated_name_keeps_the_active_file_bounded_and_one_fallback(#[fixture(temp_dir)] dir: &Path) {
    block(dir, "bridge.log.1");
    let bytes = stream(1000);
    let mut w = writer(dir, 100);
    for chunk in bytes.chunks(10) {
        w.write_all(chunk).unwrap();
        w.flush().unwrap();
        assert!(
            read(dir, "bridge.log").len() <= 100,
            "the active file outgrew the limit"
        );
    }
    drop(w);

    assert_eq!(names(dir), ["bridge.log", "bridge.log.1", "bridge.log.1.fallback"]);
    assert_eq!(read(dir, "bridge.log.1.fallback"), bytes[800..900]);
    assert_eq!(read(dir, "bridge.log"), bytes[900..]);
}

/// Once `.1` can take the file again the rotation goes there, and the fallback, which holds older lines than it,
/// is not kept beside it.
#[skuld::test]
fn a_rotation_that_reaches_the_rotated_name_again_removes_the_fallback(#[fixture(temp_dir)] dir: &Path) {
    block(dir, "bridge.log.1");
    let bytes = stream(300);
    let mut w = writer(dir, 100);
    w.write_all(&bytes[..150]).unwrap();
    assert_eq!(names(dir), ["bridge.log", "bridge.log.1", "bridge.log.1.fallback"]);

    unblock(dir, "bridge.log.1");
    w.write_all(&bytes[150..]).unwrap();
    drop(w);

    assert_eq!(names(dir), ["bridge.log", "bridge.log.1"]);
    assert_eq!(read(dir, "bridge.log.1"), bytes[100..200]);
    assert_eq!(read(dir, "bridge.log"), bytes[200..]);
}

/// A name the rotation can take the file to, and a fallback that is a directory too: nothing can take the full file, so
/// it stays at the limit and the lines are dropped (as when the file cannot be opened), until a name is free.
#[skuld::test]
fn a_file_no_name_can_take_stays_at_the_limit_and_rotates_when_a_name_frees(#[fixture(temp_dir)] dir: &Path) {
    let bytes = stream(260);
    let mut w = writer(dir, 100);
    w.write_all(&bytes[..60]).unwrap();
    block(dir, "bridge.log.1");
    block(dir, "bridge.log.1.fallback");

    w.write_all(&bytes[60..200]).unwrap();
    w.flush().unwrap();
    assert_eq!(read(dir, "bridge.log"), bytes[..100]);

    unblock(dir, "bridge.log.1");
    w.write_all(&bytes[200..]).unwrap();
    drop(w);

    assert_eq!(read(dir, "bridge.log.1"), bytes[..100]);
    assert_eq!(read(dir, "bridge.log"), bytes[200..]);
}

#[skuld::test]
fn a_write_that_took_bytes_never_fails_when_the_rotation_does(#[fixture(temp_dir)] dir: &Path) {
    let bytes = stream(120);
    let mut w = writer(dir, 100);
    w.write_all(&bytes[..60]).unwrap();
    block(dir, "bridge.log.1");
    block(dir, "bridge.log.1.fallback");

    let mut rest = &bytes[60..];
    while !rest.is_empty() {
        let n = w.write(rest).expect("an Err after bytes went out is lost to write_all");
        assert!(n > 0, "a write of a non-empty buffer that takes nothing");
        rest = &rest[n..];
    }
    drop(w);

    assert_eq!(read(dir, "bridge.log"), bytes[..100]);
}

/// A reader that holds the active file without sharing delete: on Windows nothing can rename it, whatever the name.
#[cfg(windows)]
#[skuld::test]
fn a_file_held_without_delete_sharing_stays_at_the_limit(#[fixture(temp_dir)] dir: &Path) {
    use std::os::windows::fs::OpenOptionsExt;

    const SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    let bytes = stream(200);
    let mut w = writer(dir, 100);
    w.write_all(&bytes[..100]).unwrap();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .open(dir.join("bridge.log"))
        .unwrap();

    w.write_all(&bytes[100..]).unwrap();
    w.flush().unwrap();
    assert_eq!(read(dir, "bridge.log"), bytes[..100]);
    assert_eq!(names(dir), ["bridge.log"]);

    drop(holder);
    w.write_all(b"next").unwrap();
    drop(w);
    assert_eq!(read(dir, "bridge.log.1"), bytes[..100]);
    assert_eq!(read(dir, "bridge.log"), b"next");
}

#[skuld::test]
fn a_file_that_could_not_be_opened_is_opened_again_at_the_next_write(#[fixture(temp_dir)] dir: &Path) {
    block(dir, "bridge.log");
    let mut w = writer(dir, 100);
    // Far more than the limit, none of it written: none of it may count toward a rotation.
    w.write_all(&stream(250)).unwrap();
    unblock(dir, "bridge.log");

    w.write_all(b"next").unwrap();
    drop(w);

    assert_eq!(names(dir), ["bridge.log"]);
    assert_eq!(read(dir, "bridge.log"), b"next");
}

#[skuld::test]
fn a_file_that_cannot_be_opened_is_said_once_and_without_a_path(#[fixture(temp_dir)] dir: &Path) {
    block(dir, "bridge.log");
    let (mut w, notices) = noticing_writer(dir, 100);
    for _ in 0..3 {
        w.write_all(b"line\n").unwrap();
    }
    let said = notices.lock().unwrap().clone();

    assert_eq!(said.len(), 1, "{said:?}");
    assert!(!said[0].contains(dir.to_string_lossy().as_ref()), "{said:?}");
}

#[skuld::test]
fn a_file_that_opens_is_not_spoken_of(#[fixture(temp_dir)] dir: &Path) {
    let (mut w, notices) = noticing_writer(dir, 100);
    w.write_all(&stream(250)).unwrap();

    assert!(notices.lock().unwrap().is_empty());
}
