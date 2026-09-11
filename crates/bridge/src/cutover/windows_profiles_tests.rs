use super::*;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

/// A subscriber capped exactly where the bridge's own default filter is — a
/// global `info`. Anything a profile entry logs below that is invisible in the
/// uninstall's output, which is what every assertion below turns on.
fn capture() -> (WaitableWriter, tracing::subscriber::DefaultGuard) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let guard = set_default_in_current_thread(subscriber);
    (writer, guard)
}

/// The identity expander: what `get_string` alone amounts to.
fn verbatim(raw: &str) -> std::io::Result<String> {
    Ok(raw.to_owned())
}

#[skuld::test]
fn a_profile_path_is_expanded_before_it_becomes_a_directory() {
    // `windows-registry`'s `get_string` accepts REG_EXPAND_SZ and hands the
    // bytes back verbatim — it expands nothing. All three service SIDs store
    // `ProfileImagePath` unexpanded, so without this step the SYSTEM profile
    // resolves to a literal `%systemroot%\...` that is on no disk.
    let real = tempfile::tempdir().expect("tempdir");
    let root = real.path().to_str().expect("utf-8 tempdir").to_owned();

    let entry = resolve_entry(Ok("%systemroot%".into()), |raw| Ok(raw.replace("%systemroot%", &root)));

    assert_eq!(entry, ProfileEntry::Present(real.path().to_path_buf()));
}

#[skuld::test]
fn a_profile_dir_that_is_not_on_disk_is_reported_not_dropped() {
    let (log, _g) = capture();

    // The exact value `S-1-5-18` stores, unexpanded. The caller's
    // `!peer.exists()` guard sends it down a skip branch that emits nothing,
    // so a bridge holding a SYSTEM-profile lock disappears from the peer set
    // and the release proceeds over a live bridge (bindreams/hole#1003).
    let entry = resolve_entry(Ok(r"%systemroot%\system32\config\systemprofile".into()), verbatim);

    assert!(
        matches!(entry, ProfileEntry::Absent(_)),
        "a path that survives expansion but is on no disk is Absent, not Present: {entry:?}"
    );
    assert!(
        entry.into_dir("S-1-5-18").is_some(),
        "an unresolvable profile is handed to the caller, never silently dropped"
    );
    let out = log.snapshot();
    assert!(
        out.contains("WARN"),
        "a profile the probe cannot resolve must warn at a level an operator reading an uninstall \
         sees, not debug: {out}"
    );
    assert!(out.contains("S-1-5-18"), "the warning names the profile it lost: {out}");
}

#[skuld::test]
fn an_unreadable_profile_entry_warns_where_an_operator_will_see_it() {
    let (log, _g) = capture();

    let entry = resolve_entry(Err("ERROR_ACCESS_DENIED".into()), verbatim);

    assert_eq!(entry.into_dir("S-1-5-21-7"), None, "an unreadable entry yields no dir");
    let out = log.snapshot();
    assert!(
        out.contains("WARN"),
        "an entry excluded from the peer set must warn, not debug: {out}"
    );
    assert!(
        out.contains("ERROR_ACCESS_DENIED"),
        "the warning carries the cause: {out}"
    );
    assert!(
        out.contains("S-1-5-21-7"),
        "the warning names the profile it lost: {out}"
    );
}

#[skuld::test]
fn an_expansion_failure_is_an_unreadable_entry_never_a_path() {
    // A failed expansion says nothing about where the profile is; inventing a
    // PathBuf from the unexpanded bytes would put a literal `%systemroot%` in
    // the peer set and call it a profile.
    let entry = resolve_entry(Ok("%systemroot%".into()), |_| Err(std::io::Error::other("boom")));

    assert!(
        matches!(entry, ProfileEntry::Unreadable(_)),
        "expansion failure is Unreadable: {entry:?}"
    );
}

// The Win32 binding itself — only the Windows leg compiles it, and it is the
// one piece the injected expander above cannot stand in for.

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_real_expander_resolves_the_system_profile() {
    let raw = r"%systemroot%\system32\config\systemprofile";
    let expanded = expand_env_string(raw).expect("expand");
    assert!(!expanded.contains('%'), "no reference left standing: {expanded}");
    assert!(
        std::path::Path::new(&expanded).is_dir(),
        "the SYSTEM profile `default_state_dir()` resolves against is on disk: {expanded}"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_real_expander_handles_a_reference_that_is_not_the_prefix() {
    // Why `ExpandEnvironmentStringsW` and not a `%VAR%`-prefix rewrite.
    let expanded = expand_env_string(r"prefix\%systemroot%\suffix").expect("expand");
    assert!(expanded.starts_with(r"prefix\"), "{expanded}");
    assert!(expanded.ends_with(r"\suffix"), "{expanded}");
    assert!(!expanded.contains('%'), "{expanded}");
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_real_expander_leaves_an_unset_reference_standing() {
    // Documented, and load-bearing: the caller classifies by what is on disk,
    // so an unset variable comes back as an Absent profile that warns rather
    // than as an entry that disappeared.
    let expanded = expand_env_string(r"%hole_no_such_variable_1003%\x").expect("expand");
    assert_eq!(expanded, r"%hole_no_such_variable_1003%\x");
}
