//! A release landing between the steps of an engage.
//!
//! The records are real files in a temp dir and the writes are the production
//! `swap` / `clear_if_token` / `holds`; only `pfctl` is doubled. A hook runs a
//! real [`release_all_with`] at a named step of the engage, so each test is one
//! interleaving, not a claim about all of them: the compare-and-set at every
//! write plus the commit check at the end are what make the set of interleavings
//! closed, and the hooks sit at every boundary between those.

use super::*;
use crate::routing::CoverPresence;
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
    }
}

fn standing_record(token: &str) -> lockdown_state::LockdownPfState {
    lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: token.into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
        nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
        main_snapshot_captured: true,
    }
}

fn record_exists(dir: &Path, file: &str) -> bool {
    dir.join(file).exists()
}

// A release ===========================================================================================================

/// [`PfOps`] over the real record files: the pf calls only log, the clears are
/// the production keyed deletes. `on_reload` runs between the release's read of
/// the records and its clear — the window a concurrent engage writes into.
struct ReleasePf<'a> {
    dir: &'a Path,
    dropped: Vec<String>,
    actions: Vec<PfAction>,
    on_reload: Option<Hook<'a>>,
}

impl<'a> ReleasePf<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            dir,
            dropped: Vec::new(),
            actions: Vec::new(),
            on_reload: None,
        }
    }
}

impl PfOps for ReleasePf<'_> {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.actions.push(PfAction::ReloadDefault);
        if let Some(hook) = self.on_reload.take() {
            hook(self.dir);
        }
        Ok(())
    }

    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        self.actions.push(PfAction::Load(text.to_owned()));
        if let Some(hook) = self.on_reload.take() {
            hook(self.dir);
        }
        Ok(())
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.dropped.push(token.to_owned());
        Ok(())
    }

    fn clear_transient(&mut self, token: Option<&str>) -> Result<(), RoutingError> {
        state::clear_if_token(self.dir, token).map_err(|e| RoutingError::RouteSetup(e.to_string()))
    }

    fn clear_standing(&mut self, token: Option<&str>) -> Result<(), RoutingError> {
        lockdown_state::clear_if_token(self.dir, token).map_err(|e| RoutingError::RouteSetup(e.to_string()))
    }
}

/// `release_all` over the records as they read now. Returns the tokens it dropped.
fn release(dir: &Path) -> Vec<String> {
    let mut pf = ReleasePf::new(dir);
    release_all_with(state::load_presence(dir), lockdown_state::load_presence(dir), &mut pf)
        .expect("the release succeeds");
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
fn a_release_never_clears_a_transient_record_it_did_not_read() {
    // The release read `OLD`; before it clears, an engage replaces the record.
    let dir = tempfile::tempdir().unwrap();
    state::seed(dir.path(), &transient_record(OLD));
    let mut pf = ReleasePf::new(dir.path());
    pf.on_reload = Some(Box::new(|d: &Path| state::seed(d, &transient_record("newer"))));

    release_all_with(state::load_presence(dir.path()), StateFile::Absent, &mut pf).unwrap();

    assert_eq!(
        state::load(dir.path()).map(|r| r.pf_token),
        Some("newer".to_string()),
        "the release acted on `{OLD}`; the newer record is not its to delete"
    );
}

#[skuld::test]
fn a_release_never_clears_a_standing_record_it_did_not_read() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::seed(dir.path(), &standing_record(OLD));
    let mut pf = ReleasePf::new(dir.path());
    pf.on_reload = Some(Box::new(|d: &Path| lockdown_state::seed(d, &standing_record("newer"))));

    release_all_with(StateFile::Absent, lockdown_state::load_presence(dir.path()), &mut pf).unwrap();

    assert_eq!(
        lockdown_state::load(dir.path()).map(|r| r.pf_token),
        Some("newer".to_string())
    );
}

// The transient engage ================================================================================================

/// [`EngageOps`] over the real transient record: the record steps are
/// production code ([`RealEngageOps`] with no `pfctl` involved), the pf steps
/// log. `after` runs a hook once the named step has completed.
struct TransientEngage<'a> {
    real: RealEngageOps<'a>,
    token: &'static str,
    log: Vec<&'static str>,
    dropped: Vec<String>,
    after: Option<(&'static str, Hook<'a>)>,
}

impl<'a> TransientEngage<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            real: RealEngageOps {
                state_dir: dir,
                owner: None,
            },
            token: MINE,
            log: Vec::new(),
            dropped: Vec::new(),
            after: None,
        }
    }

    fn after(mut self, step: &'static str, hook: impl FnOnce(&Path) + 'a) -> Self {
        self.after = Some((step, Box::new(hook)));
        self
    }

    fn step(&mut self, name: &'static str) {
        self.log.push(name);
        if matches!(&self.after, Some((n, _)) if *n == name) {
            let (_, hook) = self.after.take().expect("just matched");
            hook(self.real.state_dir);
        }
    }
}

impl CoverRulesetOps for TransientEngage<'_> {
    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.step("load_ruleset");
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

    fn transient_held(&mut self, token: &str) -> bool {
        let held = self.real.transient_held(token);
        self.step("transient_held");
        held
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.log.push("drop_token");
        self.dropped.push(token.to_owned());
        Ok(())
    }

    fn transient_restore(&mut self, _token: &str) {
        self.log.push("transient_restore");
    }

    fn reload_default(&mut self) {
        self.log.push("reload_default");
    }
}

#[skuld::test]
fn a_transient_engage_with_no_concurrent_release_commits() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = TransientEngage::new(dir.path());

    let token = engage_with(server(), None, &mut ops).expect("no release ran");

    assert_eq!(token, MINE);
    assert!(state::holds(dir.path(), MINE));
    assert_eq!(
        ops.log,
        vec![
            "read_transient",
            "pf_enabled",
            "enable_capture_token",
            "save_transient",
            "load_ruleset",
            "flush_states",
            "transient_held",
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
    let released = std::cell::RefCell::new(Vec::new());
    let mut ops = TransientEngage::new(dir.path()).after("flush_states", |d| released.borrow_mut().extend(release(d)));

    let err = engage_with(server(), None, &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(
        *released.borrow(),
        vec![MINE.to_string()],
        "the release read this engage's record and dropped its token"
    );
    assert!(
        ops.dropped.is_empty(),
        "the engage must not drop the token a second time: {:?}",
        ops.dropped
    );
    assert_eq!(
        &ops.log[ops.log.len() - 2..],
        ["transient_held", "reload_default"],
        "and it undoes the block-all it just loaded over the host the release restored"
    );
    assert!(!record_exists(dir.path(), state::STATE_FILE_NAME));
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
    /// How many `load_ruleset` calls still fail, counted from the next one.
    loads_to_fail: u32,
    after: Option<(&'static str, Hook<'a>)>,
}

impl<'a> StandingEngage<'a> {
    fn new(dir: &'a Path, pf_enabled: bool) -> Self {
        Self {
            real: RealLockdownEngageOps {
                state_dir: dir,
                owner: None,
            },
            pf_enabled,
            log: Vec::new(),
            dropped: Vec::new(),
            actions: Vec::new(),
            loads_to_fail: 0,
            after: None,
        }
    }

    fn after(mut self, step: &'static str, hook: impl FnOnce(&Path) + 'a) -> Self {
        self.after = Some((step, Box::new(hook)));
        self
    }

    /// Fail the next `n` ruleset loads: 1 is the engage's own cover load, 2 also its restore.
    fn fail_loads(mut self, n: u32) -> Self {
        self.loads_to_fail = n;
        self
    }

    fn step(&mut self, name: &'static str) {
        self.log.push(name);
        if matches!(&self.after, Some((n, _)) if *n == name) {
            let (_, hook) = self.after.take().expect("just matched");
            hook(self.real.state_dir);
        }
    }
}

impl CoverRulesetOps for StandingEngage<'_> {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        self.actions.push(PfAction::Load(text.to_owned()));
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
            self.real.state_dir,
            None,
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
        self.log.push("drop_token");
        self.dropped.push(token.to_owned());
        Ok(())
    }

    fn holds(&mut self, token: &str) -> bool {
        let held = self.real.holds(token);
        self.step("holds");
        held
    }

    fn clear_if_held(&mut self, token: &str) -> Result<bool, RoutingError> {
        self.log.push("clear_if_held");
        self.real.clear_if_held(token)
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
    assert!(lockdown_state::holds(dir.path(), MINE));
    assert_eq!(
        ops.log,
        vec![
            "pf_enabled",
            "read_record",
            "enable_capture_token",
            "capture_and_persist",
            "load_ruleset",
            "holds",
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
    let released = std::cell::RefCell::new(Vec::new());
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
    let released = std::cell::RefCell::new(Vec::new());
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
            "holds",
            "load_ruleset",
            "clear_if_held"
        ],
        "no new refcount is taken, and the block-all just loaded is replaced by the restore"
    );
    assert!(ops.dropped.is_empty());
}

#[skuld::test]
fn a_release_after_the_load_is_caught_by_the_commit_check_on_a_fresh_engage() {
    let dir = tempfile::tempdir().unwrap();
    let released = std::cell::RefCell::new(Vec::new());
    let mut ops =
        StandingEngage::new(dir.path(), false).after("load_ruleset", |d| released.borrow_mut().extend(release(d)));

    let err = engage_lockdown_with(server(), "utun9", &mut ops).expect_err("the release removed the record");

    assert!(matches!(err, RoutingError::SupersededByRelease), "{err}");
    assert_eq!(*released.borrow(), vec![MINE.to_string()]);
    assert_eq!(
        &ops.log[ops.log.len() - 3..],
        ["holds", "load_ruleset", "clear_if_held"],
        "the restore follows the commit check: {:?}",
        ops.log
    );
    assert!(
        ops.dropped.is_empty(),
        "the release dropped the token with the record; the engage must not drop it again"
    );
    assert!(!record_exists(dir.path(), lockdown_state::STATE_FILE_NAME));
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
    // `ReuseToken`: the baseline is the persisted record's. The release restores
    // it and clears the record; the engage's back-out must not reload the default
    // because the record it would read is gone.
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
    assert!(lockdown_state::holds(dir.path(), MINE));
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
}
