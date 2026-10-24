//! What a release leaves behind when `pfctl` fails, and who may drop a token.
//!
//! The record is the evidence a retry acts on, so it goes only after the token
//! it names is confirmed dropped. Over the real record files, with `pfctl` doubled.

use super::*;

fn transient_left(dir: &Path) -> StateFile<state::FailClosedState> {
    state::load_presence(dir)
}

fn standing_left(dir: &Path) -> StateFile<lockdown_state::LockdownPfState> {
    lockdown_state::load_presence(dir)
}

// A failed pfctl -X ===================================================================================================

#[skuld::test]
fn a_release_whose_pfctl_x_fails_keeps_the_tombstone_and_a_retry_drops_each_token_once() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut failing = ReleasePf::new(dir.path()).fail_drops(2);

    release_over(dir.path(), &mut failing).expect("the host is restored; a refcount that would not drop is logged");

    assert!(failing.dropped.is_empty());
    assert_eq!(
        transient_left(dir.path()),
        StateFile::Present(transient_tombstone_of(OLD))
    );
    assert_eq!(
        standing_left(dir.path()),
        StateFile::Present(standing_tombstone_of(OLD))
    );

    let retried = release(dir.path());

    assert_eq!(retried, vec![OLD.to_string(), OLD.to_string()], "one drop per cover");
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_release_drops_the_token_before_it_clears_the_record() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let mut pf = ReleasePf::new(dir.path());
    pf.on_drop = Some(Box::new(|d: &Path| {
        assert_eq!(
            state::load_presence(d),
            StateFile::Present(transient_tombstone_of(OLD)),
            "the record names the token until the token is let go"
        );
    }));

    release_over(dir.path(), &mut pf).unwrap();

    assert_eq!(pf.dropped, vec![OLD.to_string()]);
}

#[skuld::test]
fn a_lockdown_disengage_whose_pfctl_x_fails_is_told_so_and_a_retry_drops_the_token_once() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let claim = lockdown_state::claim_for_release(dir.path(), None);
    let mut failing = ReleasePf::new(dir.path()).fail_drops(1);

    let result = disengage_lockdown_with(CoverPresence::Recorded, claim, &mut failing);

    assert!(
        result.is_err(),
        "the escape that was asked to let go of a refcount says it could not"
    );
    assert_eq!(
        standing_left(dir.path()),
        StateFile::Present(standing_tombstone_of(OLD))
    );

    let retry_claim = lockdown_state::claim_for_release(dir.path(), None);
    let mut pf = ReleasePf::new(dir.path());
    disengage_lockdown_with(CoverPresence::Recorded, retry_claim, &mut pf).expect("the retry succeeds");

    assert_eq!(pf.dropped, vec![OLD.to_string()]);
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_transient_disengage_whose_pfctl_x_fails_keeps_its_record_for_the_next_sweep() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let mut failing = ReleasePf::new(dir.path()).fail_drops(1);

    assert!(
        disengage_with(Some(OLD), false, &mut failing),
        "the restore was confirmed"
    );
    assert_eq!(transient_left(dir.path()), StateFile::Present(transient_record(OLD)));

    let mut pf = ReleasePf::new(dir.path());
    assert!(disengage_with(Some(OLD), false, &mut pf));
    assert_eq!(pf.dropped, vec![OLD.to_string()]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
}

// A failed restore ====================================================================================================

#[skuld::test]
fn a_release_whose_restore_fails_keeps_the_token_and_a_retry_drops_it_once() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    // The transient restore, then the standing snapshot load and its fallback.
    let mut failing = ReleasePf::new(dir.path()).fail_restores(3);

    assert!(release_over(dir.path(), &mut failing).is_err());
    assert!(
        failing.drop_attempts.is_empty(),
        "nothing was restored: no token is let go"
    );

    let retried = release(dir.path());

    assert_eq!(retried, vec![OLD.to_string(), OLD.to_string()]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_transient_disengage_whose_restore_fails_keeps_the_token_too() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let mut failing = ReleasePf::new(dir.path()).fail_restores(1);

    assert!(!disengage_with(Some(OLD), false, &mut failing));
    assert!(failing.drop_attempts.is_empty());
    assert_eq!(transient_left(dir.path()), StateFile::Present(transient_record(OLD)));
}

// One party settles a token at a time =================================================================================

#[skuld::test]
fn a_party_that_settles_a_token_while_a_release_is_dropping_it_neither_drops_nor_clears() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let other = RefCell::new(None);
    let mut pf = ReleasePf::new(dir.path());
    pf.on_drop = Some(Box::new(|d: &Path| {
        let mut second = ReleasePf::new(d);
        release_over(d, &mut second).expect("another release may not complete a drop it does not own");
        *other.borrow_mut() = Some((second.drop_attempts, record_exists(d, state::STATE_FILE_NAME)));
    }));

    release_over(dir.path(), &mut pf).unwrap();

    let (attempts, record_stood) = other.borrow_mut().take().expect("the hook ran");
    assert!(attempts.is_empty(), "{attempts:?}");
    assert!(record_stood, "the record stays until the owner has dropped the token");
    assert_eq!(pf.dropped, vec![OLD.to_string()]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
}

#[skuld::test]
fn an_engages_back_out_that_dropped_the_token_removes_the_tombstone_a_release_wrote_meanwhile() {
    // The back-out dropped the token; a release then claimed the same record.
    // The release must find nothing left to drop.
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let claimed = RefCell::new(None);
    let mut back_out = ReleasePf::new(dir.path());
    back_out.on_drop = Some(Box::new(|d: &Path| {
        *claimed.borrow_mut() = Some(state::claim_for_release(d, None));
    }));

    assert!(disengage_with(Some(OLD), false, &mut back_out));
    assert_eq!(back_out.dropped, vec![OLD.to_string()]);
    assert!(
        !record_exists(dir.path(), state::STATE_FILE_NAME),
        "no record may name a dropped token"
    );

    let mut release = ReleasePf::new(dir.path());
    release_all_with(claimed.borrow_mut().take().unwrap(), StateFile::Absent, &mut release).unwrap();
    assert!(release.drop_attempts.is_empty(), "{:?}", release.drop_attempts);
}

#[skuld::test]
fn a_release_never_drops_a_token_whose_record_somebody_else_removed_after_it_read_it() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let claim = state::claim_for_release(dir.path(), None);
    let by_other = release(dir.path());
    assert_eq!(by_other, vec![OLD.to_string()]);

    let mut pf = ReleasePf::new(dir.path());
    release_all_with(claim, StateFile::Absent, &mut pf).unwrap();

    assert!(pf.drop_attempts.is_empty(), "{:?}", pf.drop_attempts);
}

// The standing engage's back-out ======================================================================================

#[skuld::test]
fn a_standing_back_out_that_dropped_the_token_removes_the_tombstone_a_release_wrote_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let claimed = RefCell::new(None);
    let mut ops = StandingEngage::new(dir.path(), false)
        .fail_loads(1)
        .after("drop_token", |d| {
            *claimed.borrow_mut() = Some(lockdown_state::claim_for_release(d, None));
        });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_eq!(ops.dropped, vec![MINE.to_string()]);
    assert!(
        !record_exists(dir.path(), lockdown_state::STATE_FILE_NAME),
        "no record may name a dropped token"
    );
    let mut pf = ReleasePf::new(dir.path());
    release_all_with(StateFile::Absent, claimed.borrow_mut().take().unwrap(), &mut pf).unwrap();
    assert!(pf.drop_attempts.is_empty(), "{:?}", pf.drop_attempts);
}

#[skuld::test]
fn a_standing_back_out_leaves_a_token_another_party_is_settling_to_them() {
    let dir = tempfile::tempdir().unwrap();
    let _held = drop_right::take(dir.path(), pf_claim::Record::Standing, MINE).expect("free");
    let mut ops = StandingEngage::new(dir.path(), false).fail_loads(1);

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
    assert_eq!(
        lockdown_state::holds(dir.path(), MINE),
        Held::Held,
        "the record stays for the holder, who restores and clears it"
    );
}

#[skuld::test]
fn a_standing_back_out_whose_pfctl_x_fails_keeps_its_record_for_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false).fail_loads(1).fail_drops();

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_eq!(ops.dropped, vec![MINE.to_string()], "it tried");
    assert_eq!(lockdown_state::holds(dir.path(), MINE), Held::Held);
}
