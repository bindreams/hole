use super::super::ownership_double::Recording;
use super::super::release_epoch::{begin_release, watch_releases, ReleaseWatch};
use super::*;

fn sample() -> LockdownPfState {
    LockdownPfState {
        version: SCHEMA_VERSION,
        pf_token: "12345678901234567890".into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
        nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
        main_snapshot_captured: true,
        releasing: false,
    }
}

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()), Some(sample()));
}

#[skuld::test]
fn roundtrip_preserves_nat_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()).unwrap().nat_snapshot, sample().nat_snapshot);
}

#[skuld::test]
fn load_absent_is_none() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut st = sample();
    st.version = SCHEMA_VERSION + 1;
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn load_rejects_unknown_field() {
    // `deny_unknown_fields` guards against a half-written/foreign file silently
    // round-tripping as a valid state.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":1,"pf_token":"x","main_snapshot":"","nat_snapshot":"","stray":true}"#,
    )
    .unwrap();
    assert_eq!(load(tmp.path()), None, "unknown field must be rejected");
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    remove_file(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    remove_file(tmp.path()).unwrap(); // second clear is a no-op, not an error
}

// main_snapshot_captured ==============================================================================================

#[skuld::test]
fn state_roundtrips_the_captured_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let mut st = sample();
    st.main_snapshot_captured = false;
    st.main_snapshot = String::new();
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

#[skuld::test]
fn a_file_without_the_flag_reads_as_captured() {
    // The upgrade path. A v1 file carries a real captured baseline, so a
    // missing field must read `true`. Bumping SCHEMA_VERSION instead would make
    // every existing file Unusable, collapse `load` to None, early-return
    // `disengage_lockdown` Ok over a still-blocked host, and drop both escapes
    // (`hole bridge unlock` and the tray's Unblock item) on the ordinary macOS
    // upgrade.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":1,"pf_token":"x","main_snapshot":"pass out all\n","nat_snapshot":""}"#,
    )
    .unwrap();
    let st = load(tmp.path()).expect("a v1 file must still parse");
    assert!(
        st.main_snapshot_captured,
        "a file written before the flag existed carries the captured baseline it was"
    );
    assert_eq!(st.main_snapshot, "pass out all\n");
}

/// `main_snapshot` is a captured `pfctl -sr` ruleset, so whenever the ruleset
/// it captured was Hole's own cover it contains the server IP in a permit
/// rule — and `serde_json::Error`'s `Display` quotes the offending bytes
/// back. Same class as `routing::state`'s two arms.
#[skuld::test]
fn a_corrupt_pf_state_never_echoes_its_contents_into_the_log() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    const SECRET_ADDR: &str = "203.0.113.42";

    let json = serde_json::to_string(&sample())
        .unwrap()
        .replace(r#""version":1"#, &format!(r#""version":"{SECRET_ADDR}""#));
    assert!(json.contains(SECRET_ADDR), "the fixture must carry the address: {json}");

    // Guard: without it this passes against a serde_json that stopped echoing.
    let raw = serde_json::from_str::<LockdownPfState>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_ADDR), "guard: serde_json echoes the value: {raw}");

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(state_file(tmp.path()), &json).unwrap();

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let loaded = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        load(tmp.path())
    };
    let logs = writer.snapshot();

    assert_eq!(loaded, None, "a corrupt record must not be acted on");
    assert!(!logs.contains(SECRET_ADDR), "the address reached bridge.log: {logs}");
    assert!(
        logs.contains("line 1"),
        "position must survive so the warning stays actionable: {logs}"
    );
}

// Concurrent release: swap / clear_if_token / holds ===================================================================

fn with_token(token: &str) -> LockdownPfState {
    LockdownPfState {
        pf_token: token.into(),
        ..sample()
    }
}

fn watch(dir: &Path) -> ReleaseWatch {
    watch_releases(dir).expect("no release is in flight")
}

#[skuld::test]
fn swap_applies_over_an_absent_record_when_absence_was_expected() {
    let tmp = tempfile::tempdir().unwrap();
    let swap = swap(
        tmp.path(),
        &StateFile::Absent,
        &with_token("1"),
        None,
        &watch(tmp.path()),
    )
    .unwrap();
    assert_eq!(swap, Swap::Applied);
    assert_eq!(load(tmp.path()), Some(with_token("1")));
}

#[skuld::test]
fn swap_is_superseded_by_a_changed_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("old"), None).unwrap();
    let expected = load_presence(tmp.path());
    // A release cleared the record and a later engage wrote another one.
    save(tmp.path(), &with_token("newer"), None).unwrap();

    let swap = swap(tmp.path(), &expected, &with_token("mine"), None, &watch(tmp.path())).unwrap();

    assert_eq!(swap, Swap::Superseded);
    assert_eq!(
        load(tmp.path()),
        Some(with_token("newer")),
        "a superseded swap writes nothing"
    );
}

#[skuld::test]
fn swap_is_superseded_when_the_expected_record_was_cleared() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("old"), None).unwrap();
    let expected = load_presence(tmp.path());
    clear_if_token(tmp.path(), Some("old")).unwrap();

    let swap = swap(tmp.path(), &expected, &with_token("mine"), None, &watch(tmp.path())).unwrap();

    assert_eq!(swap, Swap::Superseded);
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "a release that cleared the record is not undone"
    );
}

#[skuld::test]
fn swap_is_superseded_when_a_record_appeared_where_none_was_expected() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("appeared"), None).unwrap();
    let swap = swap(
        tmp.path(),
        &StateFile::Absent,
        &with_token("mine"),
        None,
        &watch(tmp.path()),
    )
    .unwrap();
    assert_eq!(swap, Swap::Superseded);
    assert_eq!(load(tmp.path()), Some(with_token("appeared")));
}

#[skuld::test]
fn swap_applies_over_an_equal_unusable_file() {
    // The engage's expectation for an `Unusable` record is what `load_presence`
    // read, not `None`: collapsing it to "no record" would compare unequal to
    // the very file it read.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":99,"pf_token":"salvaged","main_snapshot":"","nat_snapshot":""}"#,
    )
    .unwrap();
    let expected = load_presence(tmp.path());
    assert!(matches!(&expected, StateFile::Unusable { pf_token: Some(t) } if t == "salvaged"));

    assert_eq!(
        swap(tmp.path(), &expected, &with_token("mine"), None, &watch(tmp.path())).unwrap(),
        Swap::Applied
    );
    assert_eq!(load(tmp.path()), Some(with_token("mine")));
}

#[skuld::test]
fn swap_holds_the_record_lock_while_comparing_and_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut held_inside = false;
    swap_with(
        tmp.path(),
        &StateFile::Absent,
        &with_token("1"),
        None,
        &watch(tmp.path()),
        || {
            held_inside = LOCK.try_acquire().is_none();
        },
    )
    .unwrap();
    assert!(held_inside, "the compare and the write must be one critical section");
}

#[skuld::test]
fn swap_is_superseded_once_a_release_began_even_when_the_record_reads_as_expected() {
    // A release that claims a record only rewrites it when it is a live one. Over a
    // tombstone or an unusable file it writes nothing, so the record still equals the
    // engage's view; the epoch is what says a release is settling it.
    for seeded in [Some(true), Some(false), None] {
        let tmp = tempfile::tempdir().unwrap();
        match seeded {
            Some(releasing) => save(tmp.path(), &with_token("old").with_releasing(releasing), None).unwrap(),
            None => {
                std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
            }
        }
        let expected = load_presence(tmp.path());
        let engage_watch = watch(tmp.path());
        let _release = begin_release(tmp.path());

        let swap = swap(tmp.path(), &expected, &with_token("mine"), None, &engage_watch).unwrap();

        assert_eq!(swap, Swap::Superseded, "seeded {seeded:?}");
        assert_eq!(load_presence(tmp.path()), expected, "and nothing is written");
    }
}

#[skuld::test]
fn swap_is_superseded_by_a_release_that_has_already_ended() {
    let tmp = tempfile::tempdir().unwrap();
    let engage_watch = watch(tmp.path());
    drop(begin_release(tmp.path()));

    let swap = swap(tmp.path(), &StateFile::Absent, &with_token("mine"), None, &engage_watch).unwrap();

    assert_eq!(swap, Swap::Superseded);
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn swap_checks_the_watch_without_taking_a_second_lock() {
    // The check runs under the record lock; a lock taken under it would break the
    // leaf rule. A release beginning inside the section is seen at once.
    let tmp = tempfile::tempdir().unwrap();
    let engage_watch = watch(tmp.path());
    let swap = swap_with(
        tmp.path(),
        &StateFile::Absent,
        &with_token("mine"),
        None,
        &engage_watch,
        || {
            std::mem::forget(begin_release(tmp.path()));
        },
    )
    .unwrap();
    assert_eq!(swap, Swap::Superseded);
}

#[skuld::test]
fn clear_if_token_clears_the_record_that_carries_the_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("7"), None).unwrap();
    clear_if_token(tmp.path(), Some("7")).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());

    // An unusable record that still names the token is the same record.
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":99,"pf_token":"7","main_snapshot":"","nat_snapshot":""}"#,
    )
    .unwrap();
    clear_if_token(tmp.path(), Some("7")).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());

    // Absence is not an error.
    clear_if_token(tmp.path(), Some("7")).unwrap();
}

#[skuld::test]
fn clear_if_token_leaves_a_newer_record() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("newer"), None).unwrap();
    clear_if_token(tmp.path(), Some("old")).unwrap();
    assert_eq!(load(tmp.path()), Some(with_token("newer")));
}

#[skuld::test]
fn clear_if_token_none_clears_only_a_record_that_names_no_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("7"), None).unwrap();
    clear_if_token(tmp.path(), None).unwrap();
    assert_eq!(
        load(tmp.path()),
        Some(with_token("7")),
        "a record that names a token is not token-less"
    );

    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    clear_if_token(tmp.path(), None).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn holds_tells_a_release_from_an_unreadable_record() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        holds(tmp.path(), "1"),
        Held::Released,
        "no record: a release cleared it"
    );

    save(tmp.path(), &with_token("1"), None).unwrap();
    assert_eq!(holds(tmp.path(), "1"), Held::Held);
    assert_eq!(holds(tmp.path(), "2"), Held::Released, "another engage's record");

    save(tmp.path(), &with_token("1").claimed(), None).unwrap();
    assert_eq!(holds(tmp.path(), "1"), Held::Released, "a release claimed it");

    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert_eq!(
        holds(tmp.path(), "1"),
        Held::Unreadable,
        "a record that cannot be read says nothing about a release"
    );
}

// The release claim ===================================================================================================

impl LockdownPfState {
    fn claimed(mut self) -> Self {
        self.releasing = true;
        self
    }
}

#[skuld::test]
fn an_ordinary_record_is_written_without_the_flag_and_a_tombstone_with_it() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let ordinary = std::fs::read_to_string(tmp.path().join(STATE_FILE_NAME)).unwrap();
    assert!(
        !ordinary.contains("releasing"),
        "an ordinary record reads as before: {ordinary}"
    );

    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    let tombstone = std::fs::read_to_string(tmp.path().join(STATE_FILE_NAME)).unwrap();
    assert!(tombstone.contains("\"releasing\": true"), "{tombstone}");
    assert_eq!(load(tmp.path()), Some(with_token("5").claimed()));
}

/// The record schema the previous release reads, which denies unknown fields.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct PreviousRelease {
    version: u32,
    pf_token: String,
    main_snapshot: String,
    nat_snapshot: String,
    #[serde(default)]
    main_snapshot_captured: bool,
}

#[skuld::test]
fn the_previous_release_reads_a_tombstone_as_unusable_and_still_finds_its_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let ordinary = std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap();
    assert!(serde_json::from_slice::<PreviousRelease>(&ordinary).is_ok());

    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    let tombstone = std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap();
    assert!(
        serde_json::from_slice::<PreviousRelease>(&tombstone).is_err(),
        "a downgraded bridge must not mistake a claimed record for a live one"
    );
    assert_eq!(
        StateFile::<LockdownPfState>::unusable(&tombstone),
        StateFile::Unusable {
            pf_token: Some("5".into())
        },
        "and the sweep it falls into still has the token to drop"
    );
}

#[skuld::test]
fn a_file_without_the_flag_reads_as_live() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":1,"pf_token":"5","main_snapshot":"pass out all\n","nat_snapshot":"","main_snapshot_captured":true}"#,
    )
    .unwrap();
    let st = load(tmp.path()).expect("an older file parses");
    assert!(!st.releasing);
    assert_eq!(st.pf_token, "5");
}

fn failing_write(_: &Path, _: &LockdownPfState) -> std::io::Result<()> {
    Err(std::io::Error::other("injected write failure"))
}

#[skuld::test]
fn a_release_claims_a_live_record_by_writing_its_tombstone() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();

    let claimed = claim_for_release(tmp.path(), None);

    assert_eq!(claimed, StateFile::Present(with_token("5").claimed()));
    assert_eq!(
        load(tmp.path()),
        Some(with_token("5").claimed()),
        "the tombstone is on disk"
    );
}

#[skuld::test]
fn a_claim_of_nothing_or_of_a_tombstone_or_of_an_unusable_file_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(claim_for_release(tmp.path(), None), StateFile::Absent);
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());

    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    assert_eq!(
        claim_for_release(tmp.path(), None),
        StateFile::Present(with_token("5").claimed()),
        "a second release finds the first one's claim and shares it"
    );

    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert_eq!(
        claim_for_release(tmp.path(), None),
        StateFile::Unusable { pf_token: None }
    );
    assert_eq!(std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap(), b"not json");
}

#[skuld::test]
fn a_claim_hands_the_files_owner_to_the_file_and_leaves_the_state_dirs_owner_alone() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let rec = Recording::new(Some((501, 20)));

    claim_with(tmp.path(), None, &rec, write_record);

    assert_eq!(
        rec.chowns_of(&tmp.path().join(STATE_FILE_NAME)),
        vec![Some((501, 20))],
        "the rewritten file keeps the owner of the one it replaced"
    );
    assert!(
        rec.chowns_of(tmp.path()).is_empty(),
        "a claim never hands the directory to the file's owner"
    );
}

#[skuld::test]
fn a_requested_owner_wins_the_file_in_a_claim_but_never_the_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let rec = Recording::new(Some((501, 20)));

    claim_with(tmp.path(), Some((7, 8)), &rec, write_record);

    assert_eq!(rec.chowns_of(&tmp.path().join(STATE_FILE_NAME)), vec![Some((7, 8))]);
    assert!(rec.chowns_of(tmp.path()).is_empty());
}

#[skuld::test]
fn the_files_owner_is_read_before_a_claim_replaces_it() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let before = std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap();
    let rec = Recording::new(Some((501, 20)));

    claim_with(tmp.path(), None, &rec, write_record);

    assert_eq!(rec.bytes_when_read().as_deref(), Some(before.as_slice()));
}

#[skuld::test]
fn a_claim_that_writes_nothing_chowns_nothing_and_asks_nobody() {
    let tmp = tempfile::tempdir().unwrap();
    let rec = Recording::new(Some((501, 20)));

    claim_with(tmp.path(), None, &rec, write_record);

    assert!(rec.chowns_of(&tmp.path().join(STATE_FILE_NAME)).is_empty());
    assert!(
        rec.bytes_when_read().is_none(),
        "nothing to claim, so no owner to look up"
    );
}

#[skuld::test]
fn a_claim_whose_write_fails_hands_back_the_record_unclaimed() {
    // The restore matters more than the bookkeeping: the release goes on, and
    // the record it hands back says it holds no claim.
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();

    let claimed = claim_with(tmp.path(), None, &Recording::new(None), failing_write);

    assert_eq!(claimed, StateFile::Present(with_token("5")));
    assert_eq!(load(tmp.path()), Some(with_token("5")), "the record is untouched");
}

#[skuld::test]
fn a_claim_reads_and_writes_in_one_critical_section() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("5"), None).unwrap();
    let mut held_inside = false;
    claim_with(tmp.path(), None, &Recording::new(None), |dir, record| {
        held_inside = LOCK.try_acquire().is_none();
        write_record(dir, record)
    });
    assert!(held_inside);
}

#[skuld::test]
fn a_release_clears_only_its_own_tombstone() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(clear_released(tmp.path(), Some("5")).unwrap(), Cleared::Gone);

    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    assert_eq!(clear_released(tmp.path(), Some("5")).unwrap(), Cleared::Removed);
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());

    // An engage whose restore failed put its live record over the tombstone.
    save(tmp.path(), &with_token("5"), None).unwrap();
    assert_eq!(clear_released(tmp.path(), Some("5")).unwrap(), Cleared::Replaced);
    assert_eq!(
        load(tmp.path()),
        Some(with_token("5")),
        "and the record stays for recovery"
    );

    save(tmp.path(), &with_token("6").claimed(), None).unwrap();
    assert_eq!(clear_released(tmp.path(), Some("5")).unwrap(), Cleared::Replaced);
    assert_eq!(load(tmp.path()), Some(with_token("6").claimed()));
}

#[skuld::test]
fn a_release_clears_an_unusable_record_naming_its_token() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert_eq!(clear_released(tmp.path(), None).unwrap(), Cleared::Removed);
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn clear_if_token_says_whether_it_removed_the_record() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!clear_if_token(tmp.path(), Some("5")).unwrap(), "no record");
    save(tmp.path(), &with_token("6"), None).unwrap();
    assert!(!clear_if_token(tmp.path(), Some("5")).unwrap(), "another token");
    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    assert!(
        clear_if_token(tmp.path(), Some("5")).unwrap(),
        "a tombstone naming it too"
    );
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn a_failed_back_out_puts_its_record_back_over_nothing_or_its_own_tombstone() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(
        reassert(tmp.path(), &with_token("5"), None).unwrap(),
        "the release already cleared"
    );
    assert_eq!(load(tmp.path()), Some(with_token("5")));

    save(tmp.path(), &with_token("5").claimed(), None).unwrap();
    assert!(
        reassert(tmp.path(), &with_token("5"), None).unwrap(),
        "the release is yet to clear"
    );
    assert_eq!(load(tmp.path()), Some(with_token("5")), "the tombstone is replaced");
}

#[skuld::test]
fn a_failed_back_out_leaves_a_record_that_is_not_its_own() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("6"), None).unwrap();
    assert!(!reassert(tmp.path(), &with_token("5"), None).unwrap());
    assert_eq!(load(tmp.path()), Some(with_token("6")));

    save(tmp.path(), &with_token("5"), None).unwrap();
    assert!(!reassert(tmp.path(), &with_token("5"), None).unwrap(), "already live");
}
