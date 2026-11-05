//! Every ordered pair of whole operations over the two pf cover records, from every entry state of the records.
//!
//! The cover lock makes two operations a sequence, so a cell is one order of two complete operations (a transient
//! engage, `release_all`, `disengage_lockdown`), not an interleaving of their steps. The records are real files and
//! every record step is the production one (`pf_record`); only pf is modelled: which tokens it holds, which ruleset is
//! loaded, and whether `pfctl -X` works. The entry states are the ones a past run can leave behind: no record, a live
//! one, an unusable one with and without a salvageable token, one that cannot be read, and a live one whose token pf
//! no longer holds (a reboot, or a drop the record never saw). When `-X` fails it fails for the first operation only:
//! a failed drop is the case the order matters for.
//!
//! The standing engage is not a party. It shares `drop_displaced` and `pf_record` with the transient engage, which is a
//! party, so an order "standing engage, then X" differs only in which record type it writes and which `pfctl` calls it
//! makes; the first is covered by `persist_baseline` in `macos_settle_tests`, the second by the privileged macOS lanes.
//!
//! After a cell, for any order:
//!
//! - a token pf holds is dropped at most once, and one it never held is asked for at most once;
//! - every record names a token pf held, and every token pf holds is named by a record, but for the anonymous one an
//!   unusable file never named and the ones whose drop failed (an escape clears its record whatever the drop did, an
//!   engage's displaced-token drop is best-effort; both are warned);
//! - a blocked host has a record to recover it from;
//! - a release or disengage leaves no readable record behind, and returns `Ok` only over none at all.

use std::collections::BTreeSet;
use std::path::Path;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rules {
    Open,
    Transient,
    Standing,
}

/// What pf holds, and the failures it can be told to raise.
struct Pf {
    rules: Rules,
    live: BTreeSet<String>,
    /// Tokens no record could ever name: held for an unusable file with no token, or one that cannot be read.
    anonymous: BTreeSet<String>,
    /// Tokens whose `-X` failed while pf held them, so nothing drops them again.
    left_by_a_failed_drop: BTreeSet<String>,
    /// Tokens a record named at the start that pf never held; each may be asked for once.
    stale: BTreeSet<String>,
    started_stale: BTreeSet<String>,
    double_drops: Vec<String>,
    minted: u32,
    drops_fail: bool,
}

impl Pf {
    fn enable(&mut self) -> String {
        self.minted += 1;
        let token = format!("new{}", self.minted);
        self.live.insert(token.clone());
        token
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        if !self.live.contains(token) {
            if !self.stale.remove(token) {
                self.double_drops.push(token.to_owned());
            }
            return Err(RoutingError::RouteSetup("mock pfctl -X: unknown token".into()));
        }
        if self.drops_fail {
            self.left_by_a_failed_drop.insert(token.to_owned());
            return Err(RoutingError::RouteSetup("mock pfctl -X failure".into()));
        }
        self.live.remove(token);
        Ok(())
    }
}

/// The real records at `dir` and a modelled pf: the production sequencers run over this.
struct Host<'a> {
    dir: &'a Path,
    pf: &'a mut Pf,
}

impl CoverRulesetOps for Host<'_> {
    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.pf.rules = Rules::Transient;
        Ok(())
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        Ok(())
    }
}

impl EngageOps for Host<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        Ok(!self.pf.live.is_empty())
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        Ok(self.pf.enable())
    }

    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<Option<String>, RoutingError> {
        pf_record::swap(self.dir, st, None).map_err(|e| RoutingError::state_write_failed("failclosed-state", &e))
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.pf.drop_token(token)
    }

    fn transient_restore(&mut self, token: &str) {
        disengage_with(Some(token), false, self);
    }
}

impl PfOps for Host<'_> {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.pf.rules = Rules::Open;
        Ok(())
    }

    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.pf.rules = Rules::Open;
        Ok(())
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.pf.drop_token(token)
    }

    fn clear_transient(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError> {
        pf_record::clear_if_token::<state::FailClosedState>(self.dir, token)
            .map_err(|e| RoutingError::RouteSetup(format!("failclosed-state clear failed: {e}")))
    }

    fn clear_standing(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError> {
        pf_record::clear_if_token::<lockdown_state::LockdownPfState>(self.dir, token)
            .map_err(|e| RoutingError::RouteSetup(format!("lockdown-pf-state clear failed: {e}")))
    }
}

#[derive(Clone, Copy, Debug)]
enum Party {
    Engage,
    Release,
    Disengage,
}

impl Party {
    const ALL: [Party; 3] = [Party::Engage, Party::Release, Party::Disengage];

    fn run(self, host: &mut Host<'_>) -> Result<(), RoutingError> {
        let dir = host.dir;
        match self {
            Party::Engage => engage_with(v4(), None, host).map(|_| ()),
            Party::Release => {
                let transient = pf_record::read::<state::FailClosedState>(dir);
                let standing = pf_record::read::<lockdown_state::LockdownPfState>(dir);
                release_all_with(transient, standing, host).into_result().map(|_| ())
            }
            Party::Disengage => {
                let file = pf_record::read::<lockdown_state::LockdownPfState>(dir);
                let presence = fold_presence(Some(host.pf.rules == Rules::Standing), &file);
                disengage_lockdown_with(presence, file, host)
            }
        }
    }
}

/// How a record is found before the pair runs.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Absent,
    Live,
    UnusableWithToken,
    UnusableWithoutToken,
    Unreadable,
    /// A live record whose token pf does not hold: `-X` of it fails whatever else is true.
    Stale,
}

impl Entry {
    const ALL: [Entry; 6] = [
        Entry::Absent,
        Entry::Live,
        Entry::UnusableWithToken,
        Entry::UnusableWithoutToken,
        Entry::Unreadable,
        Entry::Stale,
    ];

    /// Writes the record `file` in `dir` this way and sets pf to hold what that record's past run left it holding.
    /// Returns whether pf blocks for it.
    fn seed(self, dir: &Path, file: &str, live_record: &str, token: &str, pf: &mut Pf) -> bool {
        let path = dir.join(file);
        let anonymous = format!("anonymous-{token}");
        match self {
            Entry::Absent => return false,
            Entry::Live => {
                std::fs::write(&path, live_record).unwrap();
                pf.live.insert(token.to_owned());
            }
            Entry::UnusableWithToken => {
                std::fs::write(&path, live_record.replace("\"version\":1", "\"version\":2")).unwrap();
                pf.live.insert(token.to_owned());
            }
            Entry::UnusableWithoutToken => {
                std::fs::write(&path, b"{not json").unwrap();
                pf.live.insert(anonymous.clone());
                pf.anonymous.insert(anonymous);
            }
            Entry::Unreadable => {
                std::fs::create_dir(&path).unwrap();
                pf.live.insert(anonymous.clone());
                pf.anonymous.insert(anonymous);
            }
            Entry::Stale => {
                std::fs::write(&path, live_record).unwrap();
                pf.stale.insert(token.to_owned());
                pf.started_stale.insert(token.to_owned());
                return false;
            }
        }
        true
    }
}

const TRANSIENT_LIVE: &str = r#"{"version":1,"pf_token":"t-old","pf_was_enabled":false}"#;
const STANDING_LIVE: &str =
    r#"{"version":1,"pf_token":"s-old","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":true}"#;

/// Runs one cell and returns what it broke.
fn violations_of(
    first: Party,
    second: Party,
    transient: Entry,
    standing: Entry,
    first_drops_fail: bool,
) -> Vec<String> {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut pf = Pf {
        rules: Rules::Open,
        live: BTreeSet::new(),
        anonymous: BTreeSet::new(),
        left_by_a_failed_drop: BTreeSet::new(),
        stale: BTreeSet::new(),
        started_stale: BTreeSet::new(),
        double_drops: Vec::new(),
        minted: 0,
        drops_fail: false,
    };
    for (entry, file, live_record, token) in [
        (transient, state::STATE_FILE_NAME, TRANSIENT_LIVE, "t-old"),
        (standing, lockdown_state::STATE_FILE_NAME, STANDING_LIVE, "s-old"),
    ] {
        if entry.seed(dir, file, live_record, token, &mut pf) {
            pf.rules = match file == lockdown_state::STATE_FILE_NAME {
                true => Rules::Standing,
                false if pf.rules == Rules::Open => Rules::Transient,
                false => pf.rules,
            };
        }
    }

    let mut found = Vec::new();
    for (index, party) in [first, second].into_iter().enumerate() {
        pf.drops_fail = first_drops_fail && index == 0;
        let result = party.run(&mut Host { dir, pf: &mut pf });
        pf.drops_fail = false;
        let covered: &[&str] = match party {
            Party::Engage => &[],
            Party::Release => &[state::STATE_FILE_NAME, lockdown_state::STATE_FILE_NAME],
            Party::Disengage => &[lockdown_state::STATE_FILE_NAME],
        };
        // A release restores before it clears, and the model's restores never fail: what it leaves is a record it
        // could not read (a directory), and then only with an error.
        let left: Vec<&&str> = covered
            .iter()
            .filter(|file| dir.join(file).is_file() || (result.is_ok() && dir.join(file).exists()))
            .collect();
        if !left.is_empty() {
            found.push(format!("{party:?} returned {result:?} and left {left:?}"));
        }
    }

    found.extend(
        pf.double_drops
            .iter()
            .map(|t| format!("pf was asked to drop {t} twice")),
    );
    let transient_named = pf_record::read::<state::FailClosedState>(dir);
    let standing_named = pf_record::read::<lockdown_state::LockdownPfState>(dir);
    let named: Vec<&str> = [transient_named.pf_token(), standing_named.pf_token()]
        .into_iter()
        .flatten()
        .collect();
    for token in &named {
        if !pf.live.contains(*token) && !pf.started_stale.contains(*token) {
            found.push(format!("a record names {token}, which pf no longer holds"));
        }
    }
    for token in &pf.live {
        if !named.contains(&token.as_str())
            && !pf.anonymous.contains(token)
            && !pf.left_by_a_failed_drop.contains(token)
        {
            found.push(format!("pf holds {token} and no record names it"));
        }
    }
    let any_record = [state::STATE_FILE_NAME, lockdown_state::STATE_FILE_NAME]
        .into_iter()
        .any(|f| dir.join(f).exists());
    if pf.rules != Rules::Open && !any_record {
        found.push(format!("pf blocks ({:?}) and no record could recover it", pf.rules));
    }
    found
}

fn every_cell(first_drops_fail: bool) {
    let mut red = Vec::new();
    let mut cells = 0;
    for first in Party::ALL {
        for second in Party::ALL {
            for transient in Entry::ALL {
                for standing in Entry::ALL {
                    cells += 1;
                    let found = violations_of(first, second, transient, standing, first_drops_fail);
                    if !found.is_empty() {
                        red.push(format!(
                            "{first:?} then {second:?} | transient {transient:?}, standing {standing:?}\n    {}",
                            found.join("\n    ")
                        ));
                    }
                }
            }
        }
    }
    assert!(
        red.is_empty(),
        "{} of {cells} cells are red:\n{}",
        red.len(),
        red.join("\n")
    );
}

#[skuld::test]
fn no_order_of_two_cover_operations_breaks_a_record_invariant() {
    every_cell(false);
}

#[skuld::test]
fn no_order_of_two_cover_operations_breaks_a_record_invariant_after_a_failed_token_drop() {
    every_cell(true);
}
