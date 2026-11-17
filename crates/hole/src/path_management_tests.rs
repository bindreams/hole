use super::*;
use std::path::{Path, PathBuf};

const LINK: &str = "/usr/local/bin/hole";
const EXE: &str = "/Applications/Hole.app/Contents/MacOS/hole";

fn link(target: &str) -> Entry {
    Entry::Link(PathBuf::from(target))
}

fn add_plan(entry: &Entry) -> AddPlan {
    decide_add(Path::new(LINK), entry, Path::new(EXE))
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn exe_dir_resolves() {
    let dir = exe_dir().expect("should resolve exe directory");
    assert!(dir.exists(), "exe directory should exist: {dir:?}");
    assert!(dir.is_dir(), "exe directory should be a directory: {dir:?}");
}

// decide_add ----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn path_management_add_creates_when_nothing_is_there() {
    assert_eq!(add_plan(&Entry::Absent), AddPlan::Create);
}

#[skuld::test]
fn path_management_add_is_done_when_the_link_points_to_this_binary() {
    assert_eq!(add_plan(&link(EXE)), AddPlan::AlreadyDone);
}

#[skuld::test]
fn path_management_add_replaces_a_link_to_another_hole_binary() {
    assert_eq!(
        add_plan(&link("/Users/old/Hole.app/Contents/MacOS/hole")),
        AddPlan::Replace
    );
}

#[skuld::test]
fn path_management_add_refuses_a_regular_file() {
    let AddPlan::Refuse(msg) = add_plan(&Entry::File) else {
        panic!("a regular file must be refused");
    };
    assert!(msg.contains(LINK), "message must name the path: {msg}");
    assert!(msg.contains("file"), "message must say what is there: {msg}");
}

#[skuld::test]
fn path_management_add_refuses_a_directory() {
    let AddPlan::Refuse(msg) = add_plan(&Entry::Directory) else {
        panic!("a directory must be refused");
    };
    assert!(msg.contains(LINK), "message must name the path: {msg}");
    assert!(msg.contains("directory"), "message must say what is there: {msg}");
}

#[skuld::test]
fn path_management_add_refuses_another_programs_link_and_names_its_target() {
    let AddPlan::Refuse(msg) = add_plan(&link("/opt/homebrew/bin/other-tool")) else {
        panic!("another program's link must be refused");
    };
    assert!(msg.contains(LINK), "message must name the path: {msg}");
    assert!(
        msg.contains("/opt/homebrew/bin/other-tool"),
        "message must name the link's target: {msg}"
    );
}

// decide_remove -------------------------------------------------------------------------------------------------------

#[skuld::test]
fn path_management_remove_removes_a_hole_link() {
    assert_eq!(decide_remove(Path::new(LINK), &link(EXE)), RemovePlan::Remove);
}

#[skuld::test]
fn path_management_remove_removes_a_link_to_hole_exe() {
    assert_eq!(decide_remove(Path::new(LINK), &link("/x/hole.exe")), RemovePlan::Remove);
}

#[skuld::test]
fn path_management_remove_leaves_alone_what_is_not_a_link() {
    for entry in [Entry::Absent, Entry::File, Entry::Directory] {
        assert_eq!(decide_remove(Path::new(LINK), &entry), RemovePlan::NothingToRemove);
    }
}

#[skuld::test]
fn path_management_remove_refuses_another_programs_link_and_names_its_target() {
    let RemovePlan::Refuse(msg) = decide_remove(Path::new(LINK), &link("/opt/homebrew/bin/other-tool")) else {
        panic!("another program's link must be refused");
    };
    assert!(msg.contains(LINK), "message must name the path: {msg}");
    assert!(msg.contains("/opt/homebrew/bin/other-tool"), "{msg}");
}
