//! A directory opened for reading has no way to write in it.

use std::path::Path;
use util::dir::ReadDir;

fn main() {
    let dir = ReadDir::open(Path::new(".")).unwrap();
    let _ = dir.write_atomic("a".as_ref(), b"x", None, |_| Ok(()));
    let _ = dir.unlink("a".as_ref());
    let _ = dir.rename("a".as_ref(), "b".as_ref());
    let _ = dir.link("a".as_ref(), "b".as_ref());
    let _ = dir.open_file("a".as_ref(), util::dir::OpenFile::Existing);
    let _ = dir.stage("a".as_ref(), b"x", None, |_| Ok(()));
}
