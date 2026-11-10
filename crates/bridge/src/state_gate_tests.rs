use std::path::{Path, PathBuf};

use super::*;

fn blocked(paths: &[&str]) -> StateBlocked {
    StateBlocked {
        paths: paths.iter().map(PathBuf::from).collect(),
    }
}

#[skuld::test]
fn the_files_are_the_file_names_in_order() {
    let err = blocked(&["/state/a.json", "/other/b.json"]);
    assert_eq!(err.files(), ["a.json", "b.json"]);
}

/// `Display` reaches the bridge log and `last_error`: it names each file and no directory.
#[skuld::test]
fn the_text_names_the_files_and_no_directory() {
    let text = blocked(&["/Users/someone/state/a.json", "/Users/someone/state/b.json"]).to_string();

    assert!(text.contains("a.json") && text.contains("b.json"), "{text}");
    assert!(!text.contains("someone") && !text.contains("state/"), "{text}");
}

/// `Debug` reaches logs through `{:?}` of the error and of `ProxyError`: files only, like `Display`.
#[skuld::test]
fn debug_names_the_files_and_no_directory() {
    let err = blocked(&["/Users/someone/state/a.json"]);
    let own = format!("{err:?}");
    let wrapped = format!("{:?}", crate::proxy::ProxyError::from(err));

    for text in [own, wrapped] {
        assert!(text.contains("a.json"), "{text}");
        assert!(!text.contains("someone") && !text.contains("state/"), "{text}");
    }
}

// The state directory's own sources ===================================================================================

fn plant(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[skuld::test]
fn a_clean_state_directory_does_not_block() {
    let dir = tempfile::tempdir().unwrap();
    assert!(check(dir.path()).is_ok());
}

#[skuld::test]
fn an_unreadable_route_record_and_plugin_record_each_block() {
    let dir = tempfile::tempdir().unwrap();
    let routes = plant(dir.path(), tun_engine::routing::state::STATE_FILE_NAME, b"not json");
    assert_eq!(
        check(dir.path()).expect_err("the gate must refuse").paths(),
        std::slice::from_ref(&routes)
    );

    let plugins = plant(
        dir.path(),
        crate::plugin_state::STATE_FILE_NAME,
        br#"{"version":99,"plugins":[]}"#,
    );
    let mut paths = check(dir.path()).expect_err("the gate must refuse").paths().to_vec();
    paths.sort();
    let mut want = vec![routes, plugins];
    want.sort();
    assert_eq!(paths, want);
}

/// A decision file this release cannot read is backed up and replaced by its own writer: it is no reason to refuse.
#[skuld::test]
fn an_unreadable_decision_file_does_not_block() {
    let dir = tempfile::tempdir().unwrap();
    plant(dir.path(), crate::target::STATE_FILE_NAME, b"not json");
    assert!(check(dir.path()).is_ok());
}
