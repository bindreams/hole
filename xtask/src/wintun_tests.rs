use std::io::Write;

use std::os::windows::fs::OpenOptionsExt;

use super::wintun::{cache_state, extract, extract_license, CacheState, WINTUN_ZIP_SHA256};
use crate::download::sha256_hex;

/// A zip holding `entries`, as `wintun.net` lays its release out.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, body) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(body).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[skuld::test]
fn the_licence_is_kept_beside_the_dll() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_of(&[
        ("wintun/LICENSE.txt", b"Prebuilt Binaries License"),
        ("wintun/bin/amd64/wintun.dll", b"amd64 dll"),
        ("wintun/bin/arm64/wintun.dll", b"arm64 dll"),
    ]);
    let dll = extract(&zip, dir.path()).unwrap();
    assert_eq!(dll, dir.path().join("wintun.dll"));
    assert_eq!(std::fs::read(&dll).unwrap(), b"amd64 dll");
    assert_eq!(
        std::fs::read(dir.path().join("LICENSE.txt")).unwrap(),
        b"Prebuilt Binaries License"
    );
}

#[skuld::test]
fn a_zip_without_the_licence_fails_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let err = extract(&zip_of(&[("wintun/bin/amd64/wintun.dll", b"dll")]), dir.path()).unwrap_err();
    assert!(format!("{err:#}").contains("wintun/LICENSE.txt"), "{err:#}");
}

/// A cache folder holding `files` (each the text `x`) and, when given, a sentinel.
fn cache(files: &[&str], sentinel: Option<String>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in files {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    if let Some(sentinel) = sentinel {
        std::fs::write(dir.path().join("wintun.dll.verified"), sentinel).unwrap();
    }
    dir
}

/// A sentinel of the pinned zip that certifies a licence file holding `licence`.
fn sentinel_for(licence: &[u8]) -> String {
    format!("{WINTUN_ZIP_SHA256}\n{}\n", sha256_hex(licence))
}

#[skuld::test]
fn a_cache_that_lacks_only_the_licence_is_told_apart_from_one_to_refill() {
    let both = ["wintun.dll", "LICENSE.txt"];
    assert_eq!(
        cache_state(cache(&both, Some(sentinel_for(b"x"))).path()),
        CacheState::Complete
    );
    assert_eq!(
        cache_state(cache(&["wintun.dll"], Some(sentinel_for(b"x"))).path()),
        CacheState::LacksOnlyTheLicence
    );
    // No DLL, or a DLL nobody verified against the pinned zip: everything is refilled.
    assert_eq!(
        cache_state(cache(&["LICENSE.txt"], Some(sentinel_for(b"x"))).path()),
        CacheState::Refill
    );
    assert_eq!(cache_state(cache(&both, None).path()), CacheState::Refill);
    assert_eq!(cache_state(cache(&["wintun.dll"], None).path()), CacheState::Refill);
    assert_eq!(
        cache_state(cache(&both, Some(format!("another zip\n{}\n", sha256_hex(b"x")))).path()),
        CacheState::Refill
    );
}

#[skuld::test]
fn a_licence_the_sentinel_does_not_certify_is_written_again_and_the_dll_is_left_alone() {
    // A licence cut short (its text is not the certified one), and a sentinel from before it certified the licence.
    let cut_short = cache(&["wintun.dll", "LICENSE.txt"], Some(sentinel_for(b"the whole licence")));
    assert_eq!(cache_state(cut_short.path()), CacheState::LacksOnlyTheLicence);
    let old_sentinel = cache(&["wintun.dll", "LICENSE.txt"], Some(WINTUN_ZIP_SHA256.to_owned()));
    assert_eq!(cache_state(old_sentinel.path()), CacheState::LacksOnlyTheLicence);
}

#[skuld::test]
fn the_sentinel_is_written_after_the_files_and_certifies_both() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_of(&[
        ("wintun/LICENSE.txt", b"Prebuilt Binaries License"),
        ("wintun/bin/amd64/wintun.dll", b"amd64 dll"),
    ]);
    extract(&zip, dir.path()).unwrap();
    assert_eq!(cache_state(dir.path()), CacheState::Complete);

    // The licence is cut short: the cache is no longer complete, and writing the licence alone completes it.
    std::fs::write(dir.path().join("LICENSE.txt"), b"Prebuilt Bin").unwrap();
    assert_eq!(cache_state(dir.path()), CacheState::LacksOnlyTheLicence);
    extract_license(&zip, dir.path()).unwrap();
    assert_eq!(cache_state(dir.path()), CacheState::Complete);
    assert_eq!(
        std::fs::read(dir.path().join("LICENSE.txt")).unwrap(),
        b"Prebuilt Binaries License"
    );
}

#[skuld::test]
fn the_licence_is_added_without_rewriting_a_dll_that_a_process_has_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let dll = dir.path().join("wintun.dll");
    std::fs::write(&dll, b"the verified dll").unwrap();
    // A running bridge holds its DLL open with no sharing: a write to it fails with a sharing violation.
    let _loaded = std::fs::OpenOptions::new().read(true).share_mode(0).open(&dll).unwrap();
    let zip = zip_of(&[
        ("wintun/LICENSE.txt", b"Prebuilt Binaries License"),
        ("wintun/bin/amd64/wintun.dll", b"amd64 dll"),
    ]);

    extract_license(&zip, dir.path()).unwrap();

    assert_eq!(
        std::fs::read(dir.path().join("LICENSE.txt")).unwrap(),
        b"Prebuilt Binaries License"
    );
    drop(_loaded);
    assert_eq!(std::fs::read(&dll).unwrap(), b"the verified dll");
}

#[skuld::test]
fn extracting_again_does_not_change_a_dll_linked_to_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let zip_with = |dll: &[u8]| zip_of(&[("wintun/LICENSE.txt", b"licence"), ("wintun/bin/amd64/wintun.dll", dll)]);
    let dll = extract(&zip_with(b"first dll"), dir.path()).unwrap();
    // What `stage` leaves in a staged folder: a hard link of the cached DLL.
    let staged = dir.path().join("staged-wintun.dll");
    std::fs::hard_link(&dll, &staged).unwrap();

    extract(&zip_with(b"second dll"), dir.path()).unwrap();

    assert_eq!(std::fs::read(&staged).unwrap(), b"first dll");
    assert_eq!(std::fs::read(&dll).unwrap(), b"second dll");
}

#[skuld::test]
fn writing_the_licence_again_does_not_change_a_file_linked_to_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let zip_with = |licence: &[u8]| zip_of(&[("wintun/LICENSE.txt", licence), ("wintun/bin/amd64/wintun.dll", b"dll")]);
    extract(&zip_with(b"first licence"), dir.path()).unwrap();
    let staged = dir.path().join("staged-LICENSE.txt");
    std::fs::hard_link(dir.path().join("LICENSE.txt"), &staged).unwrap();

    extract_license(&zip_with(b"second licence"), dir.path()).unwrap();

    assert_eq!(std::fs::read(&staged).unwrap(), b"first licence");
    assert_eq!(
        std::fs::read(dir.path().join("LICENSE.txt")).unwrap(),
        b"second licence"
    );
}
