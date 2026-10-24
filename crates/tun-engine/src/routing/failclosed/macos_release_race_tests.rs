//! A release landing between the steps of an engage.
//!
//! The records are real files in a temp dir and every write is the production
//! claim / `swap` / clear; only `pfctl` is doubled. A hook runs a real release
//! at a named step of the engage, so each test is one interleaving. What these
//! pin is the ownership rule in [`super::pf_claim`]: a release claims a record
//! before any pf call, a token is dropped before the record naming it is cleared
//! and by one party at a time, and an engage whose own restore failed puts its
//! record back.

use super::*;
use crate::routing::failclosed::pf_claim::{Cleared, Held};
use crate::routing::failclosed::PfRecord;
use crate::routing::CoverPresence;
use std::cell::RefCell;
use std::net::IpAddr;
use std::path::Path;

/// A step to run at an interleaving point, given the state dir.
type Hook<'a> = Box<dyn FnOnce(&Path) + 'a>;

/// A ruleset change an engage or a release made to pf, in order.
#[derive(Debug, PartialEq, Eq)]
enum PfAction {
    Load(String),
    ReloadDefault,
}

const INJECTED_LOAD_FAILURE: &str = "injected pf load failure";
const OLD: &str = "100";
const MINE: &str = "424242";

fn server() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

fn transient_record(token: &str) -> state::FailClosedState {
    state::FailClosedState {
        version: state::SCHEMA_VERSION,
        pf_token: token.into(),
        pf_was_enabled: false,
        releasing: false,
    }
}

fn standing_record(token: &str) -> lockdown_state::LockdownPfState {
    lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: token.into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
        nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
        main_snapshot_captured: true,
        releasing: false,
    }
}

fn record_exists(dir: &Path, file: &str) -> bool {
    dir.join(file).exists()
}

fn standing_tombstone_of(token: &str) -> lockdown_state::LockdownPfState {
    standing_record(token).with_releasing(true)
}

fn transient_tombstone_of(token: &str) -> state::FailClosedState {
    transient_record(token).with_releasing(true)
}

// A release ===========================================================================================================

/// [`PfOps`] over the real record files: the pf calls only log, the clears are
/// the production ones. `on_restore` runs between the release's claim and its
/// clear: the window an engage writes into.
struct ReleasePf<'a> {
    dir: &'a Path,
    /// The tokens `pfctl -X` released.
    dropped: Vec<String>,
    /// Every `pfctl -X`, the failed ones too.
    drop_attempts: Vec<String>,
    actions: Vec<PfAction>,
    /// How many restores still fail, counted from the next one.
    restores_to_fail: u32,
    /// How many `pfctl -X` still fail, counted from the next one.
    drops_to_fail: u32,
    on_restore: Option<Hook<'a>>,
    /// Runs as the release drops a token, which is when it holds the right to.
    on_drop: Option<Hook<'a>>,
    /// The record files as they read at the first pf call.
    at_first_pf_call: Option<(
        StateFile<state::FailClosedState>,
        StateFile<lockdown_state::LockdownPfState>,
    )>,
}

impl<'a> ReleasePf<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            dir,
            dropped: Vec::new(),
            drop_attempts: Vec::new(),
            actions: Vec::new(),
            restores_to_fail: 0,
            drops_to_fail: 0,
            on_restore: None,
            on_drop: None,
            at_first_pf_call: None,
        }
    }

    fn fail_restores(mut self, n: u32) -> Self {
        self.restores_to_fail = n;
        self
    }

    fn fail_drops(mut self, n: u32) -> Self {
        self.drops_to_fail = n;
        self
    }

    fn restore(&mut self, action: PfAction) -> Result<(), RoutingError> {
        self.at_first_pf_call
            .get_or_insert_with(|| (state::load_presence(self.dir), lockdown_state::load_presence(self.dir)));
        self.actions.push(action);
        if let Some(hook) = self.on_restore.take() {
            hook(self.dir);
        }
        if self.restores_to_fail > 0 {
            self.restores_to_fail -= 1;
            return Err(RoutingError::RouteSetup(INJECTED_LOAD_FAILURE.into()));
        }
        Ok(())
    }
}

impl PfOps for ReleasePf<'_> {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.restore(PfAction::ReloadDefault)
    }

    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        self.restore(PfAction::Load(text.to_owned()))
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        if let Some(hook) = self.on_drop.take() {
            hook(self.dir);
        }
        self.drop_attempts.push(token.to_owned());
        if self.drops_to_fail > 0 {
            self.drops_to_fail -= 1;
            return Err(RoutingError::RouteSetup("injected pfctl -X failure".into()));
        }
        self.dropped.push(token.to_owned());
        Ok(())
    }

    fn clear_transient(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        clear_transient_record(self.dir, token, claimed)
    }

    fn clear_standing(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        clear_standing_record(self.dir, token, claimed)
    }

    fn drop_right(&mut self, record: pf_claim::Record, token: &str) -> Option<DropRight> {
        drop_right::take(self.dir, record, token)
    }

    fn peek(&mut self, record: pf_claim::Record, token: Option<&str>, claimed: bool) -> Cleared {
        peek_record(self.dir, record, token, claimed)
    }

    fn claim_transient(&mut self) -> StateFile<state::FailClosedState> {
        state::claim_for_release(self.dir, None)
    }

    fn claim_standing(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        lockdown_state::claim_for_release(self.dir, None)
    }

    fn lockdown_label(&mut self) -> Option<bool> {
        Some(lockdown_state::load_presence(self.dir) != StateFile::Absent)
    }
}

/// `release_all` over the records as they stand, with `pf` in place of `pfctl`.
fn release_over(pf: &mut ReleasePf<'_>) -> Result<(), RoutingError> {
    release_all_over(pf)
}

/// A whole release that succeeds. Returns the tokens it dropped.
fn release(dir: &Path) -> Vec<String> {
    let mut pf = ReleasePf::new(dir);
    release_over(&mut pf).expect("the release succeeds");
    pf.dropped
}

#[skuld::test]
fn a_release_with_no_concurrent_engage_clears_both_records() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    lockdown_state::seed(dir.path(), &standing_record(OLD));

    let dropped = release(dir.path());

    assert_eq!(dropped, vec![OLD.to_string(), OLD.to_string()]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_release_claims_both_records_before_its_first_pf_call() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut pf = ReleasePf::new(dir.path());

    release_over(&mut pf).unwrap();

    let (transient, standing) = pf.at_first_pf_call.expect("the release restored something");
    assert_eq!(transient, StateFile::Present(transient_tombstone_of(OLD)));
    assert_eq!(standing, StateFile::Present(standing_tombstone_of(OLD)));
}

#[skuld::test]
fn a_release_whose_restore_fails_leaves_its_tombstone_and_its_token_for_recovery() {
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    // The transient restore, then the standing snapshot load and its fallback.
    let mut pf = ReleasePf::new(dir.path()).fail_restores(3);

    let result = release_over(&mut pf);

    assert!(result.is_err(), "a failed restore is never reported as a release");
    assert!(pf.dropped.is_empty(), "nothing was restored, so no token is let go");
    assert_eq!(
        state::load_presence(dir.path()),
        StateFile::Present(transient_tombstone_of(OLD))
    );
    assert_eq!(
        lockdown_state::load_presence(dir.path()),
        StateFile::Present(standing_tombstone_of(OLD)),
        "a tombstone is still a record naming the token: the recovery sweep acts on it"
    );
}

#[skuld::test]
fn a_record_a_release_did_not_read_is_not_its_to_clear() {
    // The release claimed `OLD`; before it clears, another engage replaces the
    // record with a live one of its own.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut pf = ReleasePf::new(dir.path());
    pf.on_restore = Some(Box::new(|d: &Path| lockdown_state::seed(d, &standing_record("newer"))));

    let result = release_over(&mut pf);

    assert!(result.is_err(), "a live record stands: the host may be blocked");
    assert!(pf.dropped.is_empty());
    assert_eq!(
        lockdown_state::load(dir.path()).map(|r| r.pf_token),
        Some("newer".to_string())
    );
}

#[skuld::test]
fn a_release_that_finds_its_record_removed_by_another_drops_nothing() {
    // Whoever removed the record owns its token, so a second party to the same
    // token must not drop it again.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let other = RefCell::new(Vec::new());
    let mut pf = ReleasePf::new(dir.path());
    pf.on_restore = Some(Box::new(|d: &Path| other.borrow_mut().extend(release(d))));

    release_over(&mut pf).expect("the record is gone, which is what a release wants");

    assert_eq!(*other.borrow(), vec![OLD.to_string()], "the second release cleared it");
    assert!(
        pf.dropped.is_empty(),
        "so the first one drops nothing: {:?}",
        pf.dropped
    );
}

#[skuld::test]
fn an_engage_that_re_asserts_over_a_release_in_flight_is_not_cleared_by_it() {
    // The release restored; an engage then loaded its cover, failed to back out
    // and put its own record over the tombstone. The release must not clear it.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut pf = ReleasePf::new(dir.path());
    pf.on_restore = Some(Box::new(|d: &Path| {
        assert!(lockdown_state::reassert(d, &standing_record(OLD), None).unwrap());
    }));

    let result = release_over(&mut pf);

    assert!(result.is_err());
    assert!(pf.dropped.is_empty());
    assert_eq!(
        lockdown_state::load_presence(dir.path()),
        StateFile::Present(standing_record(OLD)),
        "the engage's record stays for recovery"
    );
}

#[cfg(test)]
#[path = "macos_settle_tests.rs"]
mod macos_settle_tests;

// The transient engage ================================================================================================

/// [`EngageOps`] over the real transient record. The record steps are
/// production code; the pf steps log. The restore the engage backs out with is
/// the production `disengage_with` over a [`ReleasePf`], so what it drops and
/// clears is observed, not stubbed. `after` runs a hook once the named step has
/// completed.
struct TransientEngage<'a> {
    real: RealEngageOps<'a>,
    token: &'static str,
    log: Vec<&'static str>,
    dropped: Vec<String>,
    /// What the back-out did to pf and the tokens it let go.
    restore_pf: ReleasePf<'a>,
    after: Option<(&'static str, Hook<'a>)>,
    /// How many ruleset loads still fail (1: the engage's own).
    loads_to_fail: u32,
}

/// A watch on `dir`, opened now and never closed: the engage doubles hold it for the length
/// of the test process.
fn watch_of(dir: &Path) -> &'static crate::routing::failclosed::ReleaseWatch {
    Box::leak(Box::new(
        crate::routing::failclosed::watch_releases(dir).expect("no release in flight"),
    ))
}

impl<'a> TransientEngage<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            real: RealEngageOps {
                state_dir: dir,
                owner: None,
                watch: watch_of(dir),
            },
            token: MINE,
            log: Vec::new(),
            dropped: Vec::new(),
            restore_pf: ReleasePf::new(dir),
            after: None,
            loads_to_fail: 0,
        }
    }

    fn after(mut self, step: &'static str, hook: impl FnOnce(&Path) + 'a) -> Self {
        self.after = Some((step, Box::new(hook)));
        self
    }

    fn fail_loads(mut self, n: u32) -> Self {
        self.loads_to_fail = n;
        self
    }

    /// The back-out's own restore fails.
    fn fail_restore(mut self) -> Self {
        self.restore_pf = ReleasePf::new(self.real.state_dir).fail_restores(1);
        self
    }

    fn step(&mut self, name: &'static str) {
        self.log.push(name);
        if matches!(&self.after, Some((n, _)) if *n == name) {
            let (_, hook) = self.after.take().expect("just matched");
            hook(self.real.state_dir);
        }
    }

    /// Every token the engage let go, by its own drop or its back-out's.
    fn all_dropped(&self) -> Vec<String> {
        self.dropped.iter().chain(&self.restore_pf.dropped).cloned().collect()
    }
}

impl CoverRulesetOps for TransientEngage<'_> {
    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.step("load_ruleset");
        if self.loads_to_fail > 0 {
            self.loads_to_fail -= 1;
            return Err(RoutingError::RouteSetup(INJECTED_LOAD_FAILURE.into()));
        }
        Ok(())
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        self.step("flush_states");
        Ok(())
    }
}

impl EngageOps for TransientEngage<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        self.step("pf_enabled");
        Ok(false)
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        self.step("enable_capture_token");
        Ok(self.token.to_owned())
    }

    fn read_transient(&mut self) -> StateFile<state::FailClosedState> {
        let read = self.real.read_transient();
        self.step("read_transient");
        read
    }

    fn save_transient(
        &mut self,
        expected: &StateFile<state::FailClosedState>,
        st: &state::FailClosedState,
    ) -> Result<(), RoutingError> {
        let saved = self.real.save_transient(expected, st);
        self.step("save_transient");
        saved
    }

    fn transient_commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        let checked = self.real.transient_commit_check(token);
        self.step("transient_commit_check");
        checked
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.log.push("drop_token");
        self.dropped.push(token.to_owned());
        Ok(())
    }

    fn transient_restore(&mut self, token: &str) -> bool {
        self.log.push("transient_restore");
        disengage_with(Some(token), false, &mut self.restore_pf)
    }

    fn reassert_transient(&mut self, token: &str) {
        self.log.push("reassert_transient");
        let reasserted = transient_record(token);
        state::reassert(self.real.state_dir, &reasserted, None).expect("reassert");
    }
}

#[skuld::test]
fn a_transient_engage_with_no_concurrent_release_commits() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path());

    let token = engage_with(server(), None, &mut ops).expect("no release ran");

    assert_eq!(token, MINE);
    assert_eq!(state::holds(dir.path(), MINE), Held::Held);
    assert_eq!(
        ops.log,
        vec![
            "read_transient",
            "pf_enabled",
            "enable_capture_token",
            "save_transient",
            "load_ruleset",
            "flush_states",
            "transient_commit_check",
        ]
    );
}

#[skuld::test]
fn a_release_between_the_entry_read_and_the_save_makes_the_transient_engage_back_out() {
    // The engage read `OLD`; a release then clears it. The save is a
    // compare-and-set against what the engage read, so it writes nothing rather
    // than resurrecting a record for a host the release already restored.
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let mut ops = TransientEngage::new(dir.path()).after("enable_capture_token", |d| {
        release(d);
    });

    let err = engage_with(server(), None, &mut ops).expect_err("the record the engage read is gone");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert!(
        !record_exists(dir.path(), state::STATE_FILE_NAME),
        "a superseded engage writes no record"
    );
    assert_eq!(
        ops.dropped,
        vec![MINE.to_string()],
        "the refcount this engage took is dropped: no record names it, so nothing else will"
    );
    assert!(!ops.log.contains(&"load_ruleset"), "nothing loads: {:?}", ops.log);
}

#[skuld::test]
fn a_release_after_the_ruleset_load_is_caught_by_the_transient_commit_check() {
    let dir = tempfile::tempdir().unwrap();
    let released = RefCell::new(Vec::new());
    let mut ops = TransientEngage::new(dir.path()).after("flush_states", |d| released.borrow_mut().extend(release(d)));

    let err = engage_with(server(), None, &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(
        *released.borrow(),
        vec![MINE.to_string()],
        "the release read this engage's record and dropped its token"
    );
    assert_eq!(
        &ops.log[ops.log.len() - 2..],
        ["transient_commit_check", "transient_restore"],
        "and the engage undoes the block-all it just loaded over the host the release restored"
    );
    assert_eq!(
        ops.restore_pf.actions,
        vec![PfAction::ReloadDefault],
        "the transient cover's restore target is /etc/pf.conf"
    );
    assert!(
        ops.all_dropped().is_empty(),
        "the token was dropped once, by the release that removed the record: {:?}",
        ops.all_dropped()
    );
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_release_midway_through_its_restore_still_drops_the_token_once() {
    // The release has claimed the record but not yet restored or cleared when the
    // engage's commit check runs. The engage backs out and, because ITS clear
    // removes the tombstone, drops the token; the release then finds the record
    // gone and drops nothing.
    let dir = tempfile::tempdir().unwrap();
    let claimed = RefCell::new(None);
    let mut ops = TransientEngage::new(dir.path()).after("flush_states", |d| {
        *claimed.borrow_mut() = Some(state::claim_for_release(d, None));
    });

    let err = engage_with(server(), None, &mut ops).expect_err("the record is claimed");
    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    let claim = claimed.borrow_mut().take().expect("the hook ran");
    assert_eq!(claim, StateFile::Present(transient_tombstone_of(MINE)));

    // The release carries on from the record it claimed.
    let mut pf = ReleasePf::new(dir.path());
    release_all_with(claim, StateFile::Absent, &mut pf).expect("the release succeeds");

    assert_eq!(
        ops.all_dropped(),
        vec![MINE.to_string()],
        "the engage's clear removed it"
    );
    assert!(
        pf.dropped.is_empty(),
        "the release's clear found nothing to remove: {:?}",
        pf.dropped
    );
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_record_replaced_by_another_engage_is_left_alone_by_a_transient_back_out() {
    // After the load the record is no longer this engage's: a release removed it
    // and another engage wrote its own. The back-out still puts the host back to
    // /etc/pf.conf, but it neither drops the other engage's token nor clears its
    // record.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path()).after("flush_states", |d| {
        release(d);
        state::seed(d, &transient_record("newer"));
    });

    let err = engage_with(server(), None, &mut ops).expect_err("the record is another engage's");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(ops.restore_pf.actions, vec![PfAction::ReloadDefault]);
    assert_eq!(state::load(dir.path()).map(|r| r.pf_token), Some("newer".to_string()));
    assert!(ops.all_dropped().is_empty(), "{:?}", ops.all_dropped());
}

#[skuld::test]
fn a_transient_record_that_cannot_be_read_after_the_load_fails_the_engage_it_does_not_cancel_it() {
    // A read failure says nothing about a release. Reporting it as one would
    // turn a real failure into a silent, user-requested cancel.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path()).after("flush_states", |d| {
        std::fs::write(d.join(state::STATE_FILE_NAME), b"not json").unwrap();
    });

    let err = engage_with(server(), None, &mut ops).expect_err("the record cannot be read");

    assert!(!err.cancels_the_start(), "{err}");
    assert!(matches!(err, RoutingError::RouteSetup(_)), "{err}");
    assert_eq!(
        ops.restore_pf.actions,
        vec![PfAction::ReloadDefault],
        "the engage still undoes its cover"
    );
}

#[skuld::test]
fn a_failed_transient_load_restores_clears_the_record_and_drops_the_token_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path()).fail_loads(1);

    let err = engage_with(server(), None, &mut ops).expect_err("the load fails");

    assert!(
        matches!(&err, RoutingError::RouteSetup(m) if m == INJECTED_LOAD_FAILURE),
        "{err}"
    );
    assert_eq!(ops.restore_pf.actions, vec![PfAction::ReloadDefault]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
    assert_eq!(ops.all_dropped(), vec![MINE.to_string()]);
}

#[skuld::test]
fn a_release_during_a_failed_transient_load_does_not_make_the_engage_drop_the_token_again() {
    // The release removes the record, and with it the token, while the engage's
    // load is failing. The engage's own back-out must not drop that token a
    // second time: it finds its record gone, so the refcount is not its to drop.
    let dir = tempfile::tempdir().unwrap();
    let released = RefCell::new(Vec::new());
    let mut ops = TransientEngage::new(dir.path())
        .fail_loads(1)
        .after("load_ruleset", |d| released.borrow_mut().extend(release(d)));

    let err = engage_with(server(), None, &mut ops).expect_err("the load fails");

    assert!(
        matches!(&err, RoutingError::RouteSetup(m) if m == INJECTED_LOAD_FAILURE),
        "{err}"
    );
    assert_eq!(*released.borrow(), vec![MINE.to_string()]);
    assert!(
        ops.all_dropped().is_empty(),
        "dropped once in total, by the release: {:?}",
        ops.all_dropped()
    );
    assert_eq!(ops.restore_pf.actions, vec![PfAction::ReloadDefault]);
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_transient_back_out_whose_restore_fails_puts_its_record_back_over_a_cleared_one() {
    // The release restored and cleared; the engage's load then re-blocked the
    // host and its own restore failed. Without a record nothing would ever
    // restore this host.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path())
        .fail_restore()
        .after("flush_states", |d| {
            release(d);
        });

    let err = engage_with(server(), None, &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(state::load(dir.path()), Some(transient_record(MINE)));
    assert!(ops.log.contains(&"reassert_transient"), "{:?}", ops.log);
}

#[skuld::test]
fn a_transient_back_out_whose_restore_fails_replaces_the_tombstone_a_release_is_yet_to_clear() {
    let dir = tempfile::tempdir().unwrap();
    let claimed = RefCell::new(None);
    let mut ops = TransientEngage::new(dir.path())
        .fail_restore()
        .after("flush_states", |d| {
            *claimed.borrow_mut() = Some(state::claim_for_release(d, None));
        });
    engage_with(server(), None, &mut ops).expect_err("the record is claimed");
    assert_eq!(
        state::load(dir.path()),
        Some(transient_record(MINE)),
        "the tombstone is replaced"
    );

    // The release restores, then tries to clear the tombstone it claimed.
    let mut pf = ReleasePf::new(dir.path());
    let result = release_all_with(claimed.borrow_mut().take().unwrap(), StateFile::Absent, &mut pf);

    assert!(result.is_err(), "the engage's record stands: the host may be blocked");
    assert!(pf.dropped.is_empty());
    assert_eq!(state::load(dir.path()), Some(transient_record(MINE)));
}

#[skuld::test]
fn a_transient_back_out_whose_restore_fails_keeps_the_live_record_it_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path()).fail_loads(1).fail_restore();

    engage_with(server(), None, &mut ops).expect_err("the load fails");

    assert_eq!(
        state::load(dir.path()),
        Some(transient_record(MINE)),
        "kept for recovery"
    );
    assert!(
        ops.all_dropped().is_empty(),
        "and its token with it: {:?}",
        ops.all_dropped()
    );
}

// The standing engage =================================================================================================

/// [`LockdownEngageOps`] over the real standing record, as [`TransientEngage`].
struct StandingEngage<'a> {
    real: RealLockdownEngageOps<'a>,
    pf_enabled: bool,
    log: Vec<&'static str>,
    dropped: Vec<String>,
    /// What the engage did to pf, including the restore it backed out with.
    actions: Vec<PfAction>,
    /// How many `load_ruleset` calls still fail, counted after `loads_to_pass`.
    loads_to_fail: u32,
    /// How many `load_ruleset` calls succeed before the failing ones.
    loads_to_pass: u32,
    /// Whether `pfctl -X` fails.
    drops_fail: bool,
    after: Vec<(&'static str, Hook<'a>)>,
}

impl<'a> StandingEngage<'a> {
    fn new(dir: &'a Path, pf_enabled: bool) -> Self {
        Self {
            real: RealLockdownEngageOps {
                state_dir: dir,
                owner: None,
                watch: watch_of(dir),
            },
            pf_enabled,
            log: Vec::new(),
            dropped: Vec::new(),
            actions: Vec::new(),
            loads_to_fail: 0,
            loads_to_pass: 0,
            drops_fail: false,
            after: Vec::new(),
        }
    }

    fn after(mut self, step: &'static str, hook: impl FnOnce(&Path) + 'a) -> Self {
        self.after.push((step, Box::new(hook)));
        self
    }

    /// Fail the next `n` ruleset loads: 1 is the engage's own cover load, 2 also its restore.
    fn fail_loads(mut self, n: u32) -> Self {
        self.loads_to_fail = n;
        self
    }

    fn step(&mut self, name: &'static str) {
        self.log.push(name);
        while let Some(at) = self.after.iter().position(|(n, _)| *n == name) {
            let (_, hook) = self.after.remove(at);
            hook(self.real.state_dir);
        }
    }
}

impl CoverRulesetOps for StandingEngage<'_> {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        self.actions.push(PfAction::Load(text.to_owned()));
        self.step("load_ruleset");
        if self.loads_to_pass > 0 {
            self.loads_to_pass -= 1;
            return Ok(());
        }
        if self.loads_to_fail > 0 {
            self.loads_to_fail -= 1;
            return Err(RoutingError::RouteSetup(INJECTED_LOAD_FAILURE.into()));
        }
        Ok(())
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        self.step("flush_states");
        Ok(())
    }
}

impl LockdownEngageOps for StandingEngage<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        self.step("pf_enabled");
        Ok(self.pf_enabled)
    }

    fn read_record(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        let read = self.real.read_record();
        self.step("read_record");
        read
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        self.step("enable_capture_token");
        Ok(MINE.to_owned())
    }

    fn capture_and_persist(
        &mut self,
        token: &str,
        expected: &StateFile<lockdown_state::LockdownPfState>,
    ) -> Result<lockdown_state::LockdownPfState, RoutingError> {
        // The production persist, fed a clean-host capture instead of `pfctl -sr`.
        let persisted = persist_baseline(
            token,
            self.real.site(),
            expected,
            CoverPresence::Absent,
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
            "nat-anchor \"com.apple/*\" all\n".into(),
        );
        self.step("capture_and_persist");
        persisted
    }

    fn persist(
        &mut self,
        expected: &StateFile<lockdown_state::LockdownPfState>,
        fresh: &lockdown_state::LockdownPfState,
    ) -> Result<(), RoutingError> {
        let persisted = self.real.persist(expected, fresh);
        self.step("persist");
        persisted
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.dropped.push(token.to_owned());
        self.step("drop_token");
        if self.drops_fail {
            return Err(RoutingError::RouteSetup("injected pfctl -X failure".into()));
        }
        Ok(())
    }

    fn commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        let checked = self.real.commit_check(token);
        self.step("commit_check");
        checked
    }

    fn drop_right(&mut self, token: &str) -> Option<DropRight> {
        let right = self.real.drop_right(token);
        self.step("drop_right");
        right
    }

    fn names_token(&mut self, token: &str) -> bool {
        self.log.push("names_token");
        self.real.names_token(token)
    }

    fn clear_dropped(&mut self, token: &str) -> Result<(), RoutingError> {
        self.log.push("clear_dropped");
        self.real.clear_dropped(token)
    }

    fn reassert(&mut self, baseline: &lockdown_state::LockdownPfState) -> Result<bool, RoutingError> {
        self.log.push("reassert");
        self.real.reassert(baseline)
    }

    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.actions.push(PfAction::ReloadDefault);
        Ok(())
    }
}

#[skuld::test]
fn a_standing_engage_with_no_concurrent_release_commits() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false);

    let token = engage_lockdown_with(server(), "utun9", &mut ops).expect("no release ran");

    assert_eq!(token, MINE);
    assert_eq!(lockdown_state::holds(dir.path(), MINE), Held::Held);
    assert_eq!(
        ops.log,
        vec![
            "pf_enabled",
            "read_record",
            "enable_capture_token",
            "capture_and_persist",
            "load_ruleset",
            "commit_check",
        ]
    );
}

#[skuld::test]
fn a_release_between_the_entry_read_and_the_reenable_save_makes_the_standing_engage_back_out() {
    // pf is disabled (a reboot reset it) over a persisted record: `Reenable`
    // takes a fresh token and re-persists the same baseline under it. The
    // release clears the record in between.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut ops = StandingEngage::new(dir.path(), false).after("enable_capture_token", |d| {
        release(d);
    });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record the engage read is gone");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert!(
        !record_exists(dir.path(), lockdown_state::STATE_FILE_NAME),
        "a superseded engage writes no record"
    );
    assert_eq!(ops.dropped, vec![MINE.to_string()]);
    assert!(!ops.log.contains(&"load_ruleset"), "{:?}", ops.log);
}

#[skuld::test]
fn a_release_of_the_unusable_record_a_fresh_engage_expected_makes_it_back_out() {
    // The entry view is an `Unusable` record (version skew), not "no record": the
    // compare-and-set expects exactly that file, so a release that cleared it
    // supersedes the engage instead of letting it write over a restored host.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(lockdown_state::STATE_FILE_NAME),
        br#"{"version":99,"pf_token":"77","main_snapshot":"","nat_snapshot":""}"#,
    )
    .unwrap();
    let released = RefCell::new(Vec::new());
    let mut ops = StandingEngage::new(dir.path(), false)
        .after("enable_capture_token", |d| released.borrow_mut().extend(release(d)));

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record the engage read is gone");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(
        *released.borrow(),
        vec!["77".to_string()],
        "the release salvaged the token out of the unusable record"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
    assert_eq!(ops.dropped, vec![MINE.to_string()]);
}

#[skuld::test]
fn a_release_after_the_load_is_caught_by_the_commit_check_when_the_token_is_reused() {
    // `ReuseToken` writes nothing, so the commit check is its only protection.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let released = RefCell::new(Vec::new());
    let mut ops =
        StandingEngage::new(dir.path(), true).after("load_ruleset", |d| released.borrow_mut().extend(release(d)));

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(*released.borrow(), vec![OLD.to_string()]);
    assert_eq!(
        ops.log,
        vec![
            "pf_enabled",
            "read_record",
            "load_ruleset",
            "commit_check",
            "load_ruleset",
            "drop_right",
            "names_token"
        ],
        "no new refcount is taken, and the block-all just loaded is replaced by the restore"
    );
    assert!(ops.dropped.is_empty());
}

#[skuld::test]
fn a_release_after_the_load_is_caught_by_the_commit_check_on_a_fresh_engage() {
    let dir = tempfile::tempdir().unwrap();
    let released = RefCell::new(Vec::new());
    let mut ops =
        StandingEngage::new(dir.path(), false).after("load_ruleset", |d| released.borrow_mut().extend(release(d)));

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(*released.borrow(), vec![MINE.to_string()]);
    assert_eq!(
        &ops.log[ops.log.len() - 4..],
        ["commit_check", "load_ruleset", "drop_right", "names_token"],
        "the restore follows the commit check: {:?}",
        ops.log
    );
    assert!(
        ops.dropped.is_empty(),
        "the release dropped the token with the record; the engage must not drop it again"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_release_that_has_claimed_but_not_yet_restored_supersedes_the_standing_engage_which_settles_the_token() {
    // The commit check runs between the release's claim and its clear. The engage
    // backs out and, holding the right to the token its tombstone still names, drops
    // it and clears the record; the release that settles afterwards finds nothing
    // to drop. Once in total, and by whichever party got the right.
    let dir = tempfile::tempdir().unwrap();
    let claimed = RefCell::new(None);
    let mut ops = StandingEngage::new(dir.path(), false).after("load_ruleset", |d| {
        *claimed.borrow_mut() = Some(lockdown_state::claim_for_release(d, None));
    });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record is claimed");
    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(ops.dropped, vec![MINE.to_string()]);
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));

    let mut pf = ReleasePf::new(dir.path());
    release_all_with(StateFile::Absent, claimed.borrow_mut().take().unwrap(), &mut pf).expect("the release succeeds");

    assert!(pf.dropped.is_empty(), "the engage already dropped it: {:?}", pf.dropped);
}

#[skuld::test]
fn a_release_that_cannot_take_the_right_leaves_the_token_to_an_engage_that_settles_the_tombstone() {
    // The engage holds the right when the release asks for it, so the release
    // leaves the token to the engage. The engage must therefore settle a tombstone
    // naming its token, or nobody does.
    let dir = tempfile::tempdir().unwrap();
    let release_while_holding = RefCell::new(None);
    let mut ops = StandingEngage::new(dir.path(), false)
        .after("load_ruleset", |d| {
            lockdown_state::claim_for_release(d, None);
        })
        .after("drop_right", |d| {
            let mut pf = ReleasePf::new(d);
            let result = release_all_with(StateFile::Absent, lockdown_state::load_presence(d), &mut pf);
            *release_while_holding.borrow_mut() = Some((result, pf.dropped));
        });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record is claimed");

    let (result, released) = release_while_holding.borrow_mut().take().expect("the release ran");
    result.expect("a release that leaves the token to the holder succeeds");
    assert!(released.is_empty(), "it could not take the right: {released:?}");
    assert_eq!(ops.dropped, vec![MINE.to_string()], "the engage dropped it");
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

#[skuld::test]
fn a_standing_record_that_cannot_be_read_after_the_load_fails_the_engage_it_does_not_cancel_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false).after("load_ruleset", |d| {
        std::fs::write(
            d.join(lockdown_state::STATE_FILE_NAME),
            format!(r#"{{"version":99,"pf_token":"{MINE}","main_snapshot":"","nat_snapshot":""}}"#),
        )
        .unwrap();
    });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record cannot be read");

    assert!(!err.cancels_the_start(), "{err}");
    assert!(matches!(err, RoutingError::RouteSetup(_)), "{err}");
    assert_eq!(
        ops.dropped,
        vec![MINE.to_string()],
        "an unreadable record that still names the token is this engage's own to clear"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
}

// A tombstone found at entry ------------------------------------------------------------------------------------------

#[skuld::test]
fn an_engage_takes_back_a_tombstone_a_failed_release_left_and_adopts_its_cover() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_tombstone_of(OLD));
    let mut ops = StandingEngage::new(dir.path(), true);

    let token = engage_lockdown_with(server(), "utun9", &mut ops).expect("no release is running");

    assert_eq!(token, OLD, "the leftover cover is adopted as an ordinary one");
    assert_eq!(lockdown_state::holds(dir.path(), OLD), Held::Held);
    assert_eq!(
        lockdown_state::load(dir.path()),
        Some(standing_record(OLD)),
        "and the claim is gone from the record"
    );
}

#[skuld::test]
fn an_engage_never_takes_back_a_tombstone_over_a_release_that_began() {
    // A release that began after the facade's watch wrote the tombstone the
    // engage just read, or left it alone because it was one already. Taking it back
    // would steal the release's claim, and the record still reads as the engage saw it.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_tombstone_of(OLD));
    let mut ops = StandingEngage::new(dir.path(), true);
    let _release = crate::routing::failclosed::begin_release(dir.path());

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("a release began");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(
        lockdown_state::load(dir.path()),
        Some(standing_tombstone_of(OLD)),
        "the claim is untouched"
    );
    assert!(!ops.log.contains(&"load_ruleset"), "nothing was loaded: {:?}", ops.log);
}

// The back-out restores the engage's own baseline =====================================================================

/// A host baseline unlike `/etc/pf.conf`, so a restore from it cannot be mistaken for the default.
const HOST_FILTER: &str = "pass in quick on lo0 all label \"host-policy\"\n";
const HOST_NAT: &str = "nat on en0 from 10.0.0.0/8 to any -> (en0)\n";

fn host_baseline_record(token: &str, captured: bool) -> lockdown_state::LockdownPfState {
    lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: token.into(),
        main_snapshot: if captured { HOST_FILTER.into() } else { String::new() },
        nat_snapshot: HOST_NAT.into(),
        main_snapshot_captured: captured,
        releasing: false,
    }
}

/// The last ruleset change the engage made, which is the back-out when the commit check failed.
fn restored_ruleset(ops: &StandingEngage<'_>) -> String {
    match ops.actions.last() {
        Some(PfAction::Load(text)) => text.clone(),
        other => panic!("expected the engage to end by loading a ruleset, got {other:?}"),
    }
}

#[skuld::test]
fn a_release_after_the_load_leaves_the_reused_baseline_restored_not_the_default_ruleset() {
    // `ReuseToken`: the baseline is the persisted record's.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), true).after("load_ruleset", |d| {
        release(d);
    });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(
        !ops.actions.contains(&PfAction::ReloadDefault),
        "the default ruleset replaced the host's baseline: {:?}",
        ops.actions
    );
    let restored = restored_ruleset(&ops);
    assert!(
        restored.contains(HOST_FILTER) && restored.contains(HOST_NAT),
        "{restored}"
    );
}

#[skuld::test]
fn a_release_after_the_load_leaves_the_reenabled_baseline_restored_not_the_default_ruleset() {
    // `Reenable`: pf was reset, so the record is re-persisted under a fresh token
    // and the engage's baseline is the old record's.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), false).after("load_ruleset", |d| {
        release(d);
    });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(!ops.actions.contains(&PfAction::ReloadDefault), "{:?}", ops.actions);
    let restored = restored_ruleset(&ops);
    assert!(
        restored.contains(HOST_FILTER) && restored.contains(HOST_NAT),
        "{restored}"
    );
}

#[skuld::test]
fn a_release_after_a_fresh_engages_load_leaves_its_captured_baseline_restored() {
    // `FreshEnable`: the baseline is what this engage captured and persisted.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false).after("load_ruleset", |d| {
        release(d);
    });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(!ops.actions.contains(&PfAction::ReloadDefault), "{:?}", ops.actions);
    let restored = restored_ruleset(&ops);
    assert!(
        restored.contains("scrub-anchor \"com.apple/*\" all fragment reassemble")
            && restored.contains("nat-anchor \"com.apple/*\" all"),
        "{restored}"
    );
}

#[skuld::test]
fn a_release_after_the_load_reloads_the_default_when_the_engage_held_no_captured_baseline() {
    // A baseline the engage never captured has `/etc/pf.conf` as its restore
    // target: that is the baseline, not a fallback.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, false));
    let mut ops = StandingEngage::new(dir.path(), true).after("load_ruleset", |d| {
        release(d);
    });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert_eq!(ops.actions.last(), Some(&PfAction::ReloadDefault), "{:?}", ops.actions);
}

#[skuld::test]
fn a_back_out_leaves_a_record_that_is_not_the_engages_alone() {
    // Another record now stands in the release's place. It is not this engage's
    // to drop the token of or to clear, but the host still gets the engage's own
    // baseline rather than the other record's.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), true).after("load_ruleset", |d| {
        release(d);
        lockdown_state::seed(d, &standing_record("newer"));
    });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record is no longer this engage's");

    assert_eq!(
        lockdown_state::load(dir.path()).map(|r| r.pf_token),
        Some("newer".to_string())
    );
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
    let restored = restored_ruleset(&ops);
    assert!(restored.contains(HOST_FILTER), "{restored}");
}

// A failed cover load backs out the same way ==========================================================================

/// The engage's error when its own cover load failed.
fn assert_injected(err: &RoutingError) {
    assert!(
        matches!(err, RoutingError::RouteSetup(m) if m == INJECTED_LOAD_FAILURE),
        "the load's own error is returned, not a supersession: {err}"
    );
}

#[skuld::test]
fn a_failed_load_restores_the_captured_baseline_clears_the_record_and_drops_the_token() {
    // `FreshEnable`, no release: the record is still this engage's, so the back-out
    // undoes everything the engage took.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false).fail_loads(1);

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    assert!(!ops.actions.contains(&PfAction::ReloadDefault), "{:?}", ops.actions);
    assert!(restored_ruleset(&ops).contains("scrub-anchor \"com.apple/*\" all fragment reassemble"));
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
    assert_eq!(ops.dropped, vec![MINE.to_string()]);
}

#[skuld::test]
fn a_failed_load_restores_the_reused_baseline_and_drops_the_reused_token() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), true).fail_loads(1);

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    let restored = restored_ruleset(&ops);
    assert!(
        restored.contains(HOST_FILTER) && restored.contains(HOST_NAT),
        "{restored}"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
    assert_eq!(ops.dropped, vec![OLD.to_string()]);
}

#[skuld::test]
fn a_failed_load_restores_the_reenabled_baseline_and_drops_the_fresh_token() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), false).fail_loads(1);

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    let restored = restored_ruleset(&ops);
    assert!(
        restored.contains(HOST_FILTER) && restored.contains(HOST_NAT),
        "{restored}"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
    assert_eq!(ops.dropped, vec![MINE.to_string()]);
}

#[skuld::test]
fn a_failed_load_reloads_the_default_when_the_engage_held_no_captured_baseline() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, false));
    let mut ops = StandingEngage::new(dir.path(), true).fail_loads(1);

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    assert_eq!(ops.actions.last(), Some(&PfAction::ReloadDefault), "{:?}", ops.actions);
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
    assert_eq!(ops.dropped, vec![OLD.to_string()]);
}

/// A release runs as the engage's cover load fails: it restores the host, drops
/// the token with the record and clears the record. Whatever the engage held in
/// memory is then the only copy of its baseline. Returns what the engage did to
/// pf, the tokens it dropped, and whether a record is left.
fn failed_load_after_a_release(
    pf_enabled: bool,
    seeded: Option<lockdown_state::LockdownPfState>,
) -> (Vec<PfAction>, Vec<String>, bool) {
    let dir = tempfile::tempdir().unwrap();
    if let Some(record) = &seeded {
        lockdown_state::seed(dir.path(), record);
    }
    let mut ops = StandingEngage::new(dir.path(), pf_enabled)
        .fail_loads(1)
        .after("load_ruleset", |d| {
            release(d);
        });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    let record_left = record_exists(dir.path(), lockdown_state::STATE_FILE_NAME);
    (ops.actions, ops.dropped, record_left)
}

#[skuld::test]
fn a_release_during_a_failed_load_leaves_the_reused_baseline_restored_not_the_default_ruleset() {
    let (actions, dropped, record_left) = failed_load_after_a_release(true, Some(host_baseline_record(OLD, true)));

    assert!(!actions.contains(&PfAction::ReloadDefault), "{actions:?}");
    assert!(matches!(actions.last(), Some(PfAction::Load(t)) if t.contains(HOST_FILTER) && t.contains(HOST_NAT)));
    assert!(
        dropped.is_empty(),
        "the release dropped the token with the record: {dropped:?}"
    );
    assert!(!record_left);
}

#[skuld::test]
fn a_release_during_a_failed_load_leaves_the_reenabled_baseline_restored_not_the_default_ruleset() {
    let (actions, dropped, record_left) = failed_load_after_a_release(false, Some(host_baseline_record(OLD, true)));

    assert!(!actions.contains(&PfAction::ReloadDefault), "{actions:?}");
    assert!(matches!(actions.last(), Some(PfAction::Load(t)) if t.contains(HOST_FILTER) && t.contains(HOST_NAT)));
    assert!(dropped.is_empty(), "{dropped:?}");
    assert!(!record_left);
}

#[skuld::test]
fn a_release_during_a_failed_load_leaves_the_captured_baseline_restored_on_a_fresh_engage() {
    let (actions, dropped, record_left) = failed_load_after_a_release(false, None);

    assert!(!actions.contains(&PfAction::ReloadDefault), "{actions:?}");
    assert!(matches!(
        actions.last(),
        Some(PfAction::Load(t)) if t.contains("scrub-anchor \"com.apple/*\" all fragment reassemble")
    ));
    assert!(dropped.is_empty(), "{dropped:?}");
    assert!(!record_left);
}

#[skuld::test]
fn a_release_during_a_failed_load_reloads_the_default_when_the_engage_held_no_captured_baseline() {
    let (actions, dropped, record_left) = failed_load_after_a_release(true, Some(host_baseline_record(OLD, false)));

    assert_eq!(actions.last(), Some(&PfAction::ReloadDefault), "{actions:?}");
    assert!(dropped.is_empty(), "{dropped:?}");
    assert!(!record_left);
}

#[skuld::test]
fn a_failed_load_back_out_leaves_a_record_that_is_not_the_engages_alone() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), true)
        .fail_loads(1)
        .after("load_ruleset", |d| {
            release(d);
            lockdown_state::seed(d, &standing_record("newer"));
        });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    assert_eq!(
        lockdown_state::load(dir.path()).map(|r| r.pf_token),
        Some("newer".to_string())
    );
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
    assert!(restored_ruleset(&ops).contains(HOST_FILTER));
}

#[skuld::test]
fn a_back_out_whose_restore_fails_keeps_the_record_and_the_token_for_recovery() {
    // The cover's block-all may still be live and the host's rules are not back, so
    // the record that names the baseline and the refcount it was taken under stay.
    let dir = tempfile::tempdir().unwrap();
    let mut ops = StandingEngage::new(dir.path(), false).fail_loads(2);

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the load fails");

    assert_injected(&err);
    assert_eq!(lockdown_state::holds(dir.path(), MINE), Held::Held);
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
}

#[skuld::test]
fn a_back_out_whose_restore_fails_puts_its_record_back_over_a_record_a_release_cleared() {
    // The release restored and cleared; the engage's load re-blocked the host
    // and its own restore failed. The record it puts back is what a recovery
    // sweep will restore this host from.
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let mut ops = StandingEngage::new(dir.path(), true)
        .fail_after_loads(1)
        .after("load_ruleset", |d| {
            release(d);
        });

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(
        lockdown_state::load(dir.path()),
        Some(host_baseline_record(OLD, true)),
        "the engage's record is back, with its baseline"
    );
    assert!(ops.log.contains(&"reassert"), "{:?}", ops.log);
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
}

#[skuld::test]
fn a_back_out_whose_restore_fails_replaces_the_tombstone_a_release_is_yet_to_clear() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &host_baseline_record(OLD, true));
    let claimed = RefCell::new(None);
    let mut ops = StandingEngage::new(dir.path(), true)
        .fail_after_loads(1)
        .after("load_ruleset", |d| {
            *claimed.borrow_mut() = Some(lockdown_state::claim_for_release(d, None));
        });

    engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the record is claimed");

    assert_eq!(
        lockdown_state::load(dir.path()),
        Some(host_baseline_record(OLD, true)),
        "the tombstone is replaced by the engage's live record"
    );
    let mut pf = ReleasePf::new(dir.path());
    let result = release_all_with(StateFile::Absent, claimed.borrow_mut().take().unwrap(), &mut pf);
    assert!(result.is_err(), "the release must not report a clean host");
    assert!(pf.dropped.is_empty());
    assert_eq!(
        lockdown_state::load(dir.path()),
        Some(host_baseline_record(OLD, true)),
        "and it does not clear the engage's record"
    );
}

impl StandingEngage<'_> {
    /// `pfctl -X` fails.
    fn fail_drops(mut self) -> Self {
        self.drops_fail = true;
        self
    }

    /// Let the next `n` loads succeed, then fail the one after: the engage's
    /// cover load passes and its back-out restore fails.
    fn fail_after_loads(mut self, n: u32) -> Self {
        self.loads_to_pass = n;
        self.loads_to_fail = 1;
        self
    }
}
