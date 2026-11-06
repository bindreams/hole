//! The two pf cover records through the one generic module. Platform-free: the records are files and the rules are
//! tables over what they read, so a rule proved only on the host that has `pfctl` is proved nowhere.

use std::path::{Path, PathBuf};

use util::versioned_file::UpdateOutcome;

use super::super::failclosed_state::{self, FailClosedState};
use super::super::lockdown_pf_state::{self, LockdownPfState};
use super::*;

/// What differs between the two records: the file, a sample naming a token, and its bytes at a version.
trait Case: PfRecord + std::fmt::Debug + PartialEq {
    const FILE: &'static str;

    fn sample(token: &str) -> Self;

    /// The JSON this release writes for `sample(token)`, as the previous release reads it.
    fn written(token: &str) -> serde_json::Value;

    /// A complete record at `version` naming `token`.
    fn json(version: u32, token: &str) -> String;
}

impl Case for FailClosedState {
    const FILE: &'static str = failclosed_state::STATE_FILE_NAME;

    fn sample(token: &str) -> Self {
        FailClosedState {
            pf_token: token.into(),
            pf_was_enabled: true,
        }
    }

    fn written(token: &str) -> serde_json::Value {
        serde_json::json!({"version": 1, "pf_token": token, "pf_was_enabled": true})
    }

    fn json(version: u32, token: &str) -> String {
        format!(r#"{{"version":{version},"pf_token":"{token}","pf_was_enabled":false}}"#)
    }
}

impl Case for LockdownPfState {
    const FILE: &'static str = lockdown_pf_state::STATE_FILE_NAME;

    fn sample(token: &str) -> Self {
        LockdownPfState {
            pf_token: token.into(),
            main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
            nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
            main_snapshot_captured: true,
        }
    }

    fn written(token: &str) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "pf_token": token,
            "main_snapshot": "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            "nat_snapshot": "nat-anchor \"com.apple/*\" all\n",
            "main_snapshot_captured": true,
        })
    }

    fn json(version: u32, token: &str) -> String {
        format!(
            r#"{{"version":{version},"pf_token":"{token}","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":true}}"#
        )
    }
}

fn write_raw<R: Case>(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join(R::FILE), bytes).unwrap();
}

fn backup_of<R: Case>(dir: &Path) -> PathBuf {
    dir.join(format!("{}.unreadable.bak", R::FILE))
}

/// A directory where the record's file should be: its read fails, and the name is not a file.
fn make_unreadable<R: Case>(dir: &Path) {
    std::fs::create_dir(dir.join(R::FILE)).unwrap();
}

// Both records ========================================================================================================

/// A test written once, as a generic function in `both`, that the test of the same name runs over each record.
macro_rules! over_both_records {
    ($($name:ident),* $(,)?) => {
        $( #[skuld::test] fn $name() { both::$name::<FailClosedState>(); both::$name::<LockdownPfState>(); } )*
    };
}

over_both_records!(
    swap_then_read_roundtrips,
    what_a_swap_writes_has_the_previous_releases_shape,
    read_of_no_file_is_absent,
    a_newer_pf_record_is_unusable_and_gives_up_its_token,
    a_truncated_pf_record_is_unusable_with_no_token,
    a_pf_record_with_an_unknown_field_is_still_present,
    a_pf_record_whose_read_fails_is_unreadable,
    swap_says_which_token_it_displaced,
    swap_over_a_corrupt_pf_record_keeps_a_backup,
    swap_over_a_newer_pf_record_keeps_a_backup,
    clear_if_token_clears_the_record_that_carries_the_token_and_only_that,
    clear_if_token_none_clears_only_a_record_that_names_no_token,
    a_stale_guards_clear_leaves_the_engage_that_displaced_it,
    clear_moves_a_corrupt_or_newer_pf_record_aside,
    clear_over_an_unusable_record_that_names_another_token_leaves_it,
    clear_over_a_record_whose_read_fails_keeps_it_and_reports_kept,
    clear_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder,
);

mod both {
    use super::*;

    pub fn swap_then_read_roundtrips<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();

        swap(tmp.path(), &R::sample("1234567890"), None).unwrap();

        assert_eq!(read::<R>(tmp.path()), StateFile::Present(R::sample("1234567890")));
    }

    /// The bytes a swap leaves are what the previous release reads: its `version` first and the same fields.
    pub fn what_a_swap_writes_has_the_previous_releases_shape<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        swap(tmp.path(), &R::sample("5"), None).unwrap();

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join(R::FILE)).unwrap()).unwrap();

        assert_eq!(written, R::written("5"));
    }

    pub fn read_of_no_file_is_absent<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(read::<R>(tmp.path()), StateFile::Absent);
    }

    /// A rolled-back release's sweep: the record is complete and only its version is ahead, and its token is the only
    /// copy of the `pfctl -E` ticket.
    pub fn a_newer_pf_record_is_unusable_and_gives_up_its_token<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        write_raw::<R>(tmp.path(), R::json(2, "7").as_bytes());

        let found = read::<R>(tmp.path());

        assert_eq!(
            found,
            StateFile::Unusable {
                pf_token: Some("7".into())
            }
        );
    }

    pub fn a_truncated_pf_record_is_unusable_with_no_token<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        write_raw::<R>(tmp.path(), br#"{"version":1,"pf_token":"7","cut":"#);

        assert_eq!(read::<R>(tmp.path()), StateFile::Unusable { pf_token: None });
    }

    pub fn a_pf_record_with_an_unknown_field_is_still_present<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        let with_stray = R::json(1, "7").trim_end_matches('}').to_owned() + r#","stray":true}"#;
        write_raw::<R>(tmp.path(), with_stray.as_bytes());

        assert!(matches!(read::<R>(tmp.path()), StateFile::Present(r) if r.pf_token() == "7"));
    }

    /// An I/O failure has no bytes to salvage from, and is not an absent record.
    pub fn a_pf_record_whose_read_fails_is_unreadable<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        make_unreadable::<R>(tmp.path());

        assert_eq!(read::<R>(tmp.path()), StateFile::Unreadable);
    }

    /// A release whose `pfctl -X` failed leaves its record; the engage that then overwrites it must drop that token.
    pub fn swap_says_which_token_it_displaced<R: Case>() {
        let cases: [(&str, Option<String>, Option<&str>); 5] = [
            ("no record", None, None),
            ("a live record", Some(R::json(1, "1")), Some("1")),
            ("a newer record", Some(R::json(2, "2")), Some("2")),
            ("an unusable record with no token", Some("{not json".to_owned()), None),
            ("the same token", Some(R::json(1, "9")), Some("9")),
        ];
        for (what, bytes, expected) in cases {
            let tmp = tempfile::tempdir().unwrap();
            if let Some(bytes) = &bytes {
                write_raw::<R>(tmp.path(), bytes.as_bytes());
            }

            let displaced = swap(tmp.path(), &R::sample("9"), None).unwrap();

            assert_eq!(displaced.as_deref(), expected, "{what}");
        }
    }

    pub fn swap_over_a_corrupt_pf_record_keeps_a_backup<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        write_raw::<R>(tmp.path(), b"{not json");

        swap(tmp.path(), &R::sample("9"), None).unwrap();

        assert_eq!(read::<R>(tmp.path()), StateFile::Present(R::sample("9")));
        assert_eq!(std::fs::read(backup_of::<R>(tmp.path())).unwrap(), b"{not json");
    }

    pub fn swap_over_a_newer_pf_record_keeps_a_backup<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        let newer = R::json(2, "3");
        write_raw::<R>(tmp.path(), newer.as_bytes());

        swap(tmp.path(), &R::sample("9"), None).unwrap();

        assert_eq!(read::<R>(tmp.path()), StateFile::Present(R::sample("9")));
        assert_eq!(std::fs::read(backup_of::<R>(tmp.path())).unwrap(), newer.as_bytes());
    }

    pub fn clear_if_token_clears_the_record_that_carries_the_token_and_only_that<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        swap(tmp.path(), &R::sample("5"), None).unwrap();

        assert_eq!(clear_if_token::<R>(tmp.path(), Some("6")).unwrap(), Cleared::Gone);
        assert_eq!(
            read::<R>(tmp.path()),
            StateFile::Present(R::sample("5")),
            "another token's clear"
        );

        assert_eq!(clear_if_token::<R>(tmp.path(), Some("5")).unwrap(), Cleared::Removed);
        assert!(!tmp.path().join(R::FILE).exists());

        assert_eq!(
            clear_if_token::<R>(tmp.path(), Some("5")).unwrap(),
            Cleared::Gone,
            "a second clear finds nothing"
        );
    }

    pub fn clear_if_token_none_clears_only_a_record_that_names_no_token<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        swap(tmp.path(), &R::sample("5"), None).unwrap();
        assert_eq!(clear_if_token::<R>(tmp.path(), None).unwrap(), Cleared::Gone);
        assert_eq!(read::<R>(tmp.path()), StateFile::Present(R::sample("5")));

        write_raw::<R>(tmp.path(), b"{not json");
        assert_eq!(clear_if_token::<R>(tmp.path(), None).unwrap(), Cleared::Removed);
        assert!(!tmp.path().join(R::FILE).exists());
    }

    /// Engage, engage, then the first one's guard drops with its own token: it must not take the second's record.
    pub fn a_stale_guards_clear_leaves_the_engage_that_displaced_it<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        swap(tmp.path(), &R::sample("a"), None).unwrap();
        swap(tmp.path(), &R::sample("b"), None).unwrap();

        assert_eq!(clear_if_token::<R>(tmp.path(), Some("a")).unwrap(), Cleared::Gone);

        assert_eq!(read::<R>(tmp.path()), StateFile::Present(R::sample("b")));
    }

    pub fn clear_moves_a_corrupt_or_newer_pf_record_aside<R: Case>() {
        let newer = R::json(2, "3");
        let cases: [(&str, &[u8], Option<&str>); 2] =
            [("corrupt", b"{not json", None), ("newer", newer.as_bytes(), Some("3"))];
        for (what, bytes, token) in cases {
            let tmp = tempfile::tempdir().unwrap();
            write_raw::<R>(tmp.path(), bytes);

            let cleared = clear_if_token::<R>(tmp.path(), token).unwrap();

            assert_eq!(cleared, Cleared::Removed, "{what}");
            assert!(!tmp.path().join(R::FILE).exists(), "{what}");
            assert_eq!(std::fs::read(backup_of::<R>(tmp.path())).unwrap(), bytes, "{what}");
        }
    }

    pub fn clear_over_an_unusable_record_that_names_another_token_leaves_it<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        let newer = R::json(2, "3");
        write_raw::<R>(tmp.path(), newer.as_bytes());

        assert_eq!(clear_if_token::<R>(tmp.path(), Some("9")).unwrap(), Cleared::Gone);

        assert_eq!(std::fs::read(tmp.path().join(R::FILE)).unwrap(), newer.as_bytes());
        assert!(!backup_of::<R>(tmp.path()).exists());
    }

    /// The one clear that reports it did nothing about a record that may be blocking the host.
    pub fn clear_over_a_record_whose_read_fails_keeps_it_and_reports_kept<R: Case>() {
        for token in [None, Some("1")] {
            let tmp = tempfile::tempdir().unwrap();
            make_unreadable::<R>(tmp.path());

            let cleared = clear_if_token::<R>(tmp.path(), token).unwrap();

            assert_eq!(cleared, Cleared::Kept, "token {token:?}");
            assert!(tmp.path().join(R::FILE).is_dir(), "token {token:?}");
            assert!(!backup_of::<R>(tmp.path()).exists(), "token {token:?}");
        }
    }

    pub fn clear_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder<R: Case>() {
        let tmp = tempfile::tempdir().unwrap();
        let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

        let err = clear_if_token::<R>(&state, Some("1")).unwrap_err();

        let StoreError::Io(err) = err else {
            panic!("expected an I/O refusal, got {err:?}");
        };
        assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
    }
}

// One record each =====================================================================================================

/// A file written by the previous release, whose `pf_was_enabled` was a bare `bool`, reads unchanged. Driven from
/// BYTES with the literal version `1`: the claim is about files already on disk.
#[skuld::test]
fn a_transient_record_an_older_release_wrote_reads_unchanged() {
    for written in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let older = format!(r#"{{"version":1,"pf_token":"5","pf_was_enabled":{written}}}"#);
        write_raw::<FailClosedState>(tmp.path(), older.as_bytes());

        assert_eq!(
            read::<FailClosedState>(tmp.path()),
            StateFile::Present(FailClosedState {
                pf_token: "5".into(),
                pf_was_enabled: written,
            }),
            "{older}"
        );
    }
}

#[skuld::test]
fn the_lockdown_record_roundtrips_the_nat_snapshot_and_the_captured_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let mut st = LockdownPfState::sample("1");
    swap(tmp.path(), &st, None).unwrap();
    assert_eq!(
        read::<LockdownPfState>(tmp.path()),
        StateFile::Present(st.clone()),
        "nat snapshot kept"
    );

    st.main_snapshot_captured = false;
    st.main_snapshot = String::new();
    swap(tmp.path(), &st, None).unwrap();
    assert_eq!(read::<LockdownPfState>(tmp.path()), StateFile::Present(st));
}

/// The upgrade path: a file written before the flag existed carries a real captured baseline, so a missing field
/// reads `true`. A schema bump instead would make every existing file unusable on the ordinary macOS upgrade.
#[skuld::test]
fn a_lockdown_file_without_the_flag_reads_as_captured() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw::<LockdownPfState>(
        tmp.path(),
        br#"{"version":1,"pf_token":"x","main_snapshot":"pass out all\n","nat_snapshot":""}"#,
    );

    let StateFile::Present(st) = read::<LockdownPfState>(tmp.path()) else {
        panic!("a v1 file must still parse");
    };

    assert!(st.main_snapshot_captured);
    assert_eq!(st.main_snapshot, "pass out all\n");
}

/// `main_snapshot` is a captured `pfctl -sr` ruleset, so whenever the ruleset it captured was Hole's own cover it
/// holds the server IP, and `serde_json::Error`'s `Display` quotes the offending bytes back.
#[skuld::test]
fn a_corrupt_pf_state_never_echoes_its_contents_into_the_log() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    const SECRET_ADDR: &str = "203.0.113.42";

    // The record frames, and the flag is a string where a bool belongs: the payload parse is what fails.
    let json = format!(
        r#"{{"version":1,"pf_token":"1","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":"{SECRET_ADDR}"}}"#
    );

    // Guard: without it this passes against a serde_json that stopped echoing.
    let raw = serde_json::from_str::<LockdownPfState>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_ADDR), "guard: serde_json echoes the value: {raw}");

    let tmp = tempfile::tempdir().unwrap();
    write_raw::<LockdownPfState>(tmp.path(), json.as_bytes());

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let found = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        read::<LockdownPfState>(tmp.path())
    };
    let logs = writer.snapshot();

    assert!(
        matches!(found, StateFile::Unusable { .. }),
        "a corrupt record must not be acted on as a record: {found:?}"
    );
    assert!(!logs.contains(SECRET_ADDR), "the address reached bridge.log: {logs}");
    assert!(
        logs.contains("line 1"),
        "position must survive so the warning stays actionable: {logs}"
    );
}

// The rules as tables =================================================================================================

fn absent() -> StateFile<FailClosedState> {
    StateFile::Absent
}

fn present(token: &str) -> StateFile<FailClosedState> {
    StateFile::Present(FailClosedState::sample(token))
}

fn unusable(token: Option<&str>) -> StateFile<FailClosedState> {
    StateFile::Unusable {
        pf_token: token.map(str::to_owned),
    }
}

fn unreadable() -> StateFile<FailClosedState> {
    StateFile::Unreadable
}

#[skuld::test]
fn a_record_names_a_token_in_every_state_it_can_be_in() {
    assert_eq!(present("1").pf_token(), Some("1"));
    assert_eq!(unusable(Some("2")).pf_token(), Some("2"));
    assert_eq!(unusable(None).pf_token(), None);
    assert_eq!(absent().pf_token(), None);
    assert_eq!(unreadable().pf_token(), None);
}

/// The one decision every release path reads: a token to drop (or none to drop), or the refusal for a record that could
/// not be read. An unread record never answers a token, `None` included.
#[skuld::test]
fn a_release_acts_by_the_token_a_record_names_and_is_refused_by_one_it_cannot_read() {
    assert_eq!(present("1").release_token().unwrap(), Some("1"));
    assert_eq!(unusable(Some("2")).release_token().unwrap(), Some("2"));
    assert_eq!(unusable(None).release_token().unwrap(), None);
    assert_eq!(absent().release_token().unwrap(), None);
    let refusal = unreadable().release_token().unwrap_err();
    assert_eq!(refusal.to_string(), Cleared::Kept.refusal().unwrap().to_string());
}

#[skuld::test]
fn naming_matches_any_record_with_the_token_and_an_unusable_one_with_none_but_never_an_unread_one() {
    assert!(names(&present("1"), Some("1")));
    assert!(!names(&present("1"), Some("2")));
    assert!(!names(&present("1"), None));
    assert!(names(&unusable(Some("1")), Some("1")));
    assert!(names(&unusable(None), None));
    assert!(!names(&unusable(None), Some("1")));
    assert!(!names(&absent(), Some("1")));
    assert!(!names(&absent(), None));
    assert!(!names(&unreadable(), None));
    assert!(!names(&unreadable(), Some("1")));
}

#[skuld::test]
fn a_sweep_clear_removes_what_names_the_token_and_keeps_what_it_cannot_read() {
    assert_eq!(sweep_clear(&absent(), Some("1")), Cleared::Gone);
    assert_eq!(sweep_clear(&present("1"), Some("1")), Cleared::Removed);
    assert_eq!(sweep_clear(&present("2"), Some("1")), Cleared::Gone);
    assert_eq!(sweep_clear(&unusable(Some("1")), Some("1")), Cleared::Removed);
    assert_eq!(sweep_clear(&unusable(None), None), Cleared::Removed);
    assert_eq!(sweep_clear(&unusable(None), Some("1")), Cleared::Gone);
    assert_eq!(sweep_clear(&unreadable(), Some("1")), Cleared::Kept);
    assert_eq!(sweep_clear(&unreadable(), None), Cleared::Kept);
}

/// One answer per outcome of the write a clear asked for; a clear that wrote nothing is what its decision said.
#[skuld::test]
fn a_clear_is_what_the_write_did_and_otherwise_what_was_decided() {
    use std::path::PathBuf;
    for verdict in [Cleared::Removed, Cleared::Gone, Cleared::Kept] {
        assert_eq!(Cleared::after_update(verdict, UpdateOutcome::Unchanged), verdict);
        assert_eq!(Cleared::after_update(verdict, UpdateOutcome::Stored), verdict);
    }
    assert_eq!(
        Cleared::after_update(Cleared::Removed, UpdateOutcome::Absent),
        Cleared::Gone
    );
    assert_eq!(
        Cleared::after_update(Cleared::Removed, UpdateOutcome::Removed),
        Cleared::Removed
    );
    assert_eq!(
        Cleared::after_update(Cleared::Removed, UpdateOutcome::MovedAside(PathBuf::from("x"))),
        Cleared::Removed
    );
    assert_eq!(
        Cleared::after_update(Cleared::Removed, UpdateOutcome::Kept),
        Cleared::Kept
    );
}

#[skuld::test]
fn kept_is_a_refusal_that_names_no_path() {
    assert!(Cleared::Removed.refusal().is_none());
    assert!(Cleared::Gone.refusal().is_none());
    let kept = Cleared::Kept.refusal().expect("a refusal").to_string();
    assert!(kept.contains("could not be read"), "{kept}");
    assert!(!kept.contains("bridge-"), "no file name reaches a toast: {kept}");
}
