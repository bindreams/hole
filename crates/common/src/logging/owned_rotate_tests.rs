#![cfg(target_os = "macos")]

use super::UserOwnedRotate;
use skuld::temp_dir;
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn rotate(path: &Path) -> file_rotate::FileRotate<file_rotate::suffix::AppendCount> {
    file_rotate::FileRotate::new(
        path,
        file_rotate::suffix::AppendCount::new(1),
        file_rotate::ContentLimit::Bytes(64),
        file_rotate::compression::Compression::None,
        None,
    )
}

#[skuld::test]
fn chowns_active_file_initially_and_after_rotation(#[fixture(temp_dir)] dir: &Path) {
    let active = dir.join("bridge.log");
    let calls: Rc<RefCell<Vec<PathBuf>>> = Rc::new(RefCell::new(Vec::new()));
    let spy = {
        let calls = calls.clone();
        move |p: &Path, _u: u32, _g: u32| {
            calls.borrow_mut().push(p.to_path_buf());
            Ok(())
        }
    };
    let mut w = UserOwnedRotate::new(rotate(&active), active.clone(), Some((501, 20)), spy);
    w.write_all(&[b'a'; 32]).unwrap();
    w.flush().unwrap();
    w.write_all(&[b'b'; 64]).unwrap();
    w.flush().unwrap();
    assert!(
        calls.borrow().len() >= 2,
        "initial + post-rotation, got {}",
        calls.borrow().len()
    );
    assert!(calls.borrow().iter().all(|p| *p == active));
}

#[skuld::test]
fn owner_none_is_passthrough(#[fixture(temp_dir)] dir: &Path) {
    let active = dir.join("bridge.log");
    let calls = Rc::new(RefCell::new(0usize));
    let spy = {
        let calls = calls.clone();
        move |_p: &Path, _u: u32, _g: u32| {
            *calls.borrow_mut() += 1;
            Ok(())
        }
    };
    let mut w = UserOwnedRotate::new(rotate(&active), active, None, spy);
    w.write_all(&[b'a'; 200]).unwrap();
    w.flush().unwrap();
    assert_eq!(*calls.borrow(), 0);
}
