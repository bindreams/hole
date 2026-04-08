use std::path::Path;

use super::*;

#[skuld::test]
fn part_path_appends_suffix() {
    let dest = Path::new("/tmp/hole-update/hole.msi");
    let part = part_file_path(dest);
    assert_eq!(part, Path::new("/tmp/hole-update/hole.msi.part"));
}
