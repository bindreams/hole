//! Tripwire: a `FWPM_FILTER_FLAG_BOOTTIME` filter may not be installed
//! without its key being classified `KeyLifetime::BootTime`.
//!
//! Scope is the `failclosed/` **platform** sources, recursively, minus their
//! `*_tests.rs` siblings — not `failclosed.rs` itself, which defines
//! `KeyLifetime` and its fold and therefore names `BootTime` in code by
//! construction. Nothing in that file can install a WFP filter; FWPM lives
//! only under `failclosed/`.

use std::path::{Path, PathBuf};

/// The failclosed platform sources on disk, sorted.
fn production_sources_under(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .map(|e| e.expect("walk the failclosed sources"))
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| is_production_source(p))
        .collect();
    found.sort();
    found
}

/// A Rust source that ships, as opposed to one that tests it. The exclusion is
/// load-bearing: `windows_tests.rs` and this very module name both boot-time
/// symbols, so a scan that took the whole tree would read an install out of
/// test code.
fn is_production_source(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".rs") && !name.ends_with("_tests.rs")
}

/// `(installs_boot_time, classifies_boot_time)` across the given sources.
///
/// Comments are stripped first: the failclosed modules' docs discuss the
/// boot-time flag by name, and a guard that counted prose would fire on
/// documentation alone — the fastest way to get a tripwire deleted rather
/// than obeyed.
fn boot_time_halves(sources: &[PathBuf]) -> (bool, bool) {
    let code = sources
        .iter()
        .map(|p| {
            let text = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            text.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n");
    (
        code.contains("FWPM_FILTER_FLAG_BOOTTIME"),
        code.contains("KeyLifetime::BootTime"),
    )
}

fn failclosed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routing/failclosed")
}

/// Relative, slash-normalised names, for readable fixture assertions.
fn relative(dir: &Path, found: Vec<PathBuf>) -> Vec<String> {
    let mut names: Vec<String> = found
        .into_iter()
        .map(|p| {
            p.strip_prefix(dir)
                .expect("under the fixture root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    names.sort();
    names
}

#[skuld::test]
fn a_boot_time_flag_cannot_be_introduced_without_classifying_its_key() {
    // A tripwire, deliberately, and not a proof — the fact it guards spans a
    // runtime `FilterSpec` (what `add_filter` stamps) and a static sweep array
    // (what `release_all` classifies), and no type in this module holds both.
    //
    // What it catches is the one mistake that is silent AND harmful: adding a
    // `FWPM_FILTER_FLAG_BOOTTIME` filter (bindreams/hole#998, #1010) while
    // leaving its key tagged `KeyLifetime::Persistent`. `release_all` would
    // then report proof it does not have, and the MSI would delete `hole.exe`
    // on the strength of it (bindreams/hole#1003). Both halves are absent
    // today; whoever adds the first must add the other.
    //
    // The scan is the source tree, not one hardcoded file: an add that landed
    // in a new submodule (`failclosed/windows/boottime.rs`) would leave both
    // halves false, the equality holding, and the mis-tag shipping.
    let dir = failclosed_dir();
    let sources = production_sources_under(&dir);
    assert!(
        sources.iter().any(|p| p.ends_with("windows.rs")),
        "the scan found no failclosed/windows.rs under {}; a tripwire that reads nothing \
         passes forever: {sources:?}",
        dir.display()
    );

    let (installs_boot_time, classifies_boot_time) = boot_time_halves(&sources);
    assert_eq!(
        installs_boot_time, classifies_boot_time,
        "the failclosed sources install boot-time filters ({installs_boot_time}) but classify \
         boot-time keys ({classifies_boot_time}); a sweep that deletes a boot-time key while \
         calling it Persistent reports a proof of removal it never observed"
    );
}

#[skuld::test]
fn the_scan_reaches_a_nested_source_and_never_a_test_file() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    for name in [
        "windows.rs",
        "macos.rs",
        "windows/boottime.rs",
        "windows_tests.rs",
        "windows/boottime_privileged_tests.rs",
        "notes.md",
    ] {
        std::fs::write(dir.join(name), "").expect("write");
    }

    assert_eq!(
        relative(dir, production_sources_under(dir)),
        vec!["macos.rs", "windows.rs", "windows/boottime.rs"]
    );
}

#[skuld::test]
fn the_tripwire_fires_on_a_flag_added_in_a_new_submodule() {
    // The #1010 shape, landed one directory deeper than #1010 lands it.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    std::fs::write(dir.join("windows.rs"), "let l = KeyLifetime::Persistent;").expect("write");
    std::fs::write(dir.join("windows/boottime.rs"), "flags |= FWPM_FILTER_FLAG_BOOTTIME.0;").expect("write");
    // The trap: classifying it in a test is not classifying it.
    std::fs::write(
        dir.join("windows_tests.rs"),
        "assert_eq!(k.lifetime, KeyLifetime::BootTime);",
    )
    .expect("write");

    assert_eq!(boot_time_halves(&production_sources_under(dir)), (true, false));
}

#[skuld::test]
fn a_boot_time_symbol_named_only_in_prose_does_not_fire_the_tripwire() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "//! A `FWPM_FILTER_FLAG_BOOTTIME` key answers FWP_E_FILTER_NOT_FOUND.\n\
         /// See [`KeyLifetime::BootTime`].\n\
         fn f() {}\n",
    )
    .expect("write");

    assert_eq!(boot_time_halves(&production_sources_under(dir)), (false, false));
}
