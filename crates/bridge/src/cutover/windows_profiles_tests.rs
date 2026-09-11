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

// Subkey enumeration --------------------------------------------------------------------------------------------------

/// A reader that answers from a scripted list, ignoring the buffer size.
fn scripted(answers: Vec<EnumAnswer>) -> impl FnMut(u32, usize) -> EnumAnswer {
    let mut answers = answers.into_iter();
    move |_index, _capacity| answers.next().expect("the driver read past the script")
}

#[skuld::test]
fn a_status_that_is_not_end_of_list_is_never_read_as_end_of_list() {
    // The `windows-registry` `KeyIterator` defect this enumeration replaces:
    // any non-zero `RegEnumKeyExW` status ends its iteration as if it were a
    // normal end-of-list, behind a `debug_assert_eq!` that ships compiled out.
    // Every one of these truncates the peer set, and the release then clears
    // machine-wide WFP filters out from under whatever bridge was past the cut.
    for status in [
        234,  // ERROR_MORE_DATA — a SID longer than the sampled maximum
        1018, // ERROR_KEY_DELETED
        5,    // ERROR_ACCESS_DENIED
        6,    // ERROR_INVALID_HANDLE
        1726, // RPC_S_CALL_FAILED
    ] {
        let answer = enum_answer(status, || "S-1-5-21-1".into(), || format!("status {status}"));
        assert!(
            matches!(answer, EnumAnswer::TooLong | EnumAnswer::Failed(_)),
            "status {status} must not read as end-of-list: {answer:?}"
        );
    }
}

#[skuld::test]
fn each_enum_status_maps_to_its_own_cause() {
    assert_eq!(
        enum_answer(ERROR_SUCCESS, || "S-1-5-18".into(), || "unused".into()),
        EnumAnswer::Name("S-1-5-18".into())
    );
    assert_eq!(
        enum_answer(ERROR_MORE_DATA, || unreachable!(), || "unused".into()),
        EnumAnswer::TooLong
    );
    assert_eq!(
        enum_answer(ERROR_NO_MORE_ITEMS, || unreachable!(), || "unused".into()),
        EnumAnswer::End
    );
    assert_eq!(
        enum_answer(5, || unreachable!(), || "denied".into()),
        EnumAnswer::Failed("denied".into())
    );
}

#[skuld::test]
fn a_complete_pass_keeps_every_name_and_says_nothing() {
    let (log, _g) = capture();

    let names = enumerate_subkeys(
        2,
        8,
        scripted(vec![
            EnumAnswer::Name("S-1-5-18".into()),
            EnumAnswer::Name("S-1-5-19".into()),
            EnumAnswer::End,
        ]),
    );

    assert_eq!(names, vec!["S-1-5-18".to_owned(), "S-1-5-19".to_owned()]);
    assert!(
        !log.snapshot().contains("WARN"),
        "a pass that lost nothing must not cry wolf: {}",
        log.snapshot()
    );
}

#[skuld::test]
fn a_pass_that_stops_on_an_error_warns_and_keeps_what_it_read() {
    let (log, _g) = capture();

    let names = enumerate_subkeys(
        9,
        8,
        scripted(vec![
            EnumAnswer::Name("S-1-5-18".into()),
            EnumAnswer::Failed("ERROR_KEY_DELETED".into()),
        ]),
    );

    // Kept, not discarded: the caller turns an `Err` into an EMPTY peer set,
    // so a short list still sees more live bridges than no list at all.
    assert_eq!(names, vec!["S-1-5-18".to_owned()]);
    let out = log.snapshot();
    assert!(
        out.contains("WARN"),
        "a pass that stopped early must warn where an operator reading an uninstall sees it: {out}"
    );
    assert!(
        out.contains("ERROR_KEY_DELETED"),
        "the warning carries the cause: {out}"
    );
    assert!(
        out.contains("index=1"),
        "the warning names the index it stopped at: {out}"
    );
}

#[skuld::test]
fn a_name_that_does_not_fit_is_reread_against_a_bigger_buffer() {
    // `RegEnumKeyExW` leaves the required size undefined on ERROR_MORE_DATA,
    // so the only way forward is a larger buffer against the SAME index —
    // never a skip, which is what the shipped iterator does with it.
    let (log, _g) = capture();
    let mut seen: Vec<(u32, usize)> = Vec::new();

    let names = enumerate_subkeys(1, 4, |index, capacity| {
        seen.push((index, capacity));
        if capacity < 16 {
            EnumAnswer::TooLong
        } else if index == 0 {
            EnumAnswer::Name("S-1-12-1-a-very-long-entra-id-sid".into())
        } else {
            EnumAnswer::End
        }
    });

    assert_eq!(names, vec!["S-1-12-1-a-very-long-entra-id-sid".to_owned()]);
    assert_eq!(
        seen.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        vec![0, 0, 0, 1],
        "the oversized name is re-read at its own index, not skipped: {seen:?}"
    );
    assert!(!log.snapshot().contains("WARN"), "growing a buffer is not a loss");
}

#[skuld::test]
fn a_pass_that_outgrows_its_sampled_count_is_not_cut_short() {
    // The `KeyIterator` shape that loses a first-time Entra-ID logon: it caps
    // the pass at the `cSubKeys` it sampled before starting, so a subkey the
    // Profile Service adds mid-pass is never read at all. The count is a
    // shortfall detector here, never a bound.
    let (log, _g) = capture();

    let names = enumerate_subkeys(
        1,
        8,
        scripted(vec![
            EnumAnswer::Name("S-1-5-18".into()),
            EnumAnswer::Name("S-1-12-1-new".into()),
            EnumAnswer::End,
        ]),
    );

    assert_eq!(names.len(), 2, "the pass runs to end-of-list, not to the sampled count");
    assert!(!log.snapshot().contains("WARN"), "a list that grew lost nothing");
}

#[skuld::test]
fn a_pass_that_came_back_short_warns() {
    // `RegEnumKeyExW` addresses subkeys by index: a subkey deleted mid-pass
    // shifts its successors down and carries one of them past the reader.
    // Nothing in the pass itself notices — the count taken before it does.
    let (log, _g) = capture();

    let names = enumerate_subkeys(
        3,
        8,
        scripted(vec![EnumAnswer::Name("S-1-5-18".into()), EnumAnswer::End]),
    );

    assert_eq!(names, vec!["S-1-5-18".to_owned()]);
    let out = log.snapshot();
    assert!(
        out.contains("WARN"),
        "a pass that came back short must not be silent — that is the whole defect: {out}"
    );
    assert!(
        out.contains("at_start=3") && out.contains("yielded=1"),
        "the warning names both what the key held when the pass began and what came back: {out}"
    );
}

// The Win32 binding itself — only the Windows leg compiles it, and it is the
// one piece the injected expander above cannot stand in for.

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_enum_status_constants_are_the_win32_ones() {
    // The classification above is spelled in numbers so it compiles off
    // Windows. This is what keeps those numbers honest.
    use windows::Win32::Foundation;

    assert_eq!(ERROR_SUCCESS, Foundation::ERROR_SUCCESS.0);
    assert_eq!(ERROR_MORE_DATA, Foundation::ERROR_MORE_DATA.0);
    assert_eq!(ERROR_NO_MORE_ITEMS, Foundation::ERROR_NO_MORE_ITEMS.0);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_real_enumeration_finds_the_service_profiles() {
    // End-to-end against the live registry: the three service SIDs are the
    // profiles `default_state_dir()` resolves to under a SYSTEM token, and a
    // pass that loses them loses the release's own account.
    let dirs = profile_dirs().expect("enumerate ProfileList");
    let system = expand_env_string(r"%systemroot%\system32\config\systemprofile").expect("expand");

    assert!(
        dirs.iter().any(|d| d == std::path::Path::new(&system)),
        "the SYSTEM profile is in the peer set: {dirs:?}"
    );
}

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
