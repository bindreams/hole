//! The world the interleaving search runs in, and the four parties in it.
//!
//! The records are real files in a temp dir and every record step is the
//! production one (claim, compare-and-set, clear, peek). Only pf is
//! modelled: an enable-token set, the ruleset that is loaded, and a log of
//! violations the model itself can see (`pfctl -X` of a token that is not live,
//! which the production `dropped_tokens` ledger is there to keep from happening).
//! Each party is the production sequence a caller runs: the facade's epoch calls
//! around `engage_with` / `engage_lockdown_with` / `release_all_over` /
//! `disengage_lockdown_over`, and the overtaken cover's drop.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::explore::{Gate, Op, Res};
use super::*;
use crate::routing::failclosed::pf_claim::{Held, Record};
use crate::routing::failclosed::release_epoch::{begin_release, watch_releases, ReleaseWatch};
use crate::routing::failclosed::PfRecord;

pub const T_OLD: &str = "T-old";
pub const S_OLD: &str = "S-old";
const TUN: &str = "utun-model";
/// What `pfctl -sr` returns for the host before any cover: the model's baseline.
const HOST_RULES: &str = "pass all\n";

fn server() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

// The world ===========================================================================================================

/// What pf has loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rules {
    Open,
    Transient(String),
    Standing(String),
}

/// What a record file holds when the run starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Absent,
    /// An ordinary record naming the old token.
    Live,
    /// A release's tombstone over the old token, left by a release that did not finish.
    Tombstone,
    /// A file that does not parse, from which the old token can still be read.
    UnusableTokened,
    /// A file that does not parse and names no token.
    UnusableAnonymous,
}

impl Entry {
    pub const ALL: [Entry; 5] = [
        Entry::Absent,
        Entry::Live,
        Entry::Tombstone,
        Entry::UnusableTokened,
        Entry::UnusableAnonymous,
    ];

    fn names_a_token(self) -> bool {
        matches!(self, Entry::Live | Entry::Tombstone | Entry::UnusableTokened)
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Entry::Absent => "absent",
            Entry::Live => "live",
            Entry::Tombstone => "tombstone",
            Entry::UnusableTokened => "unusable+token",
            Entry::UnusableAnonymous => "unusable",
        })
    }
}

struct Pf {
    /// The enable tokens pf holds.
    live: BTreeSet<String>,
    minted: u32,
    rules: Rules,
    violations: Vec<String>,
    /// Tokens a release wrote a tombstone over, in this run.
    claimed: BTreeSet<(Record, String)>,
    /// Tokens pf holds that no record names, by construction of the entry.
    anonymous: BTreeSet<String>,
}

pub struct World {
    pub dir: PathBuf,
    pf: Mutex<Pf>,
}

/// What is left when every party is done.
pub struct Final {
    pub live: BTreeSet<String>,
    pub rules: Rules,
    pub violations: Vec<String>,
    pub anonymous: BTreeSet<String>,
    pub transient: StateFile<state::FailClosedState>,
    pub standing: StateFile<lockdown_state::LockdownPfState>,
}

impl World {
    /// A fresh world in `dir` whose records start as `transient` and `standing`.
    pub fn new(dir: PathBuf, transient: Entry, standing: Entry) -> Self {
        assert!(!dir.exists(), "a world starts in a directory of its own");
        std::fs::create_dir_all(&dir).unwrap();
        let mut live = BTreeSet::new();
        let mut anonymous = BTreeSet::new();
        seed_transient(&dir, transient);
        seed_standing(&dir, standing);
        for (entry, old, anon) in [(transient, T_OLD, "T-anon"), (standing, S_OLD, "S-anon")] {
            if entry.names_a_token() {
                live.insert(old.to_owned());
            } else if entry == Entry::UnusableAnonymous {
                live.insert(anon.to_owned());
                anonymous.insert(anon.to_owned());
            }
        }
        let rules = if standing != Entry::Absent {
            Rules::Standing(S_OLD.into())
        } else if transient != Entry::Absent {
            Rules::Transient(T_OLD.into())
        } else {
            Rules::Open
        };
        Self {
            dir,
            pf: Mutex::new(Pf {
                live,
                minted: 0,
                rules,
                violations: Vec::new(),
                claimed: BTreeSet::new(),
                anonymous,
            }),
        }
    }

    fn pf(&self) -> std::sync::MutexGuard<'_, Pf> {
        self.pf.lock().unwrap()
    }

    fn mint(&self, who: &str) -> String {
        let token = {
            let mut pf = self.pf();
            pf.minted += 1;
            let token = format!("{who}-{}", pf.minted);
            pf.live.insert(token.clone());
            token
        };
        dropped_tokens::minted(&self.dir, &token);
        token
    }

    fn pf_enabled(&self) -> bool {
        !self.pf().live.is_empty()
    }

    fn is_live(&self, token: &str) -> bool {
        self.pf().live.contains(token)
    }

    fn rules(&self) -> Rules {
        self.pf().rules.clone()
    }

    fn set_rules(&self, rules: Rules) {
        self.pf().rules = rules;
    }

    /// `pfctl -X`, through the production ledger: a drop it lets through of a
    /// token that is not live is a double drop.
    fn drop_token(&self, who: &str, token: &str) -> Result<(), RoutingError> {
        dropped_tokens::drop_once(&self.dir, token, || {
            let mut pf = self.pf();
            if pf.live.remove(token) {
                return Ok(());
            }
            pf.violations.push(format!(
                "{who} dropped {token}, which pf no longer holds (a double drop)"
            ));
            Err(RoutingError::RouteSetup(format!("pfctl -X: {token} is not live")))
        })
    }

    fn note_claim(&self, record: Record, before: &StateFile<impl PfRecord>, after: &StateFile<impl PfRecord>) {
        if let (StateFile::Present(b), StateFile::Present(a)) = (before, after) {
            if !b.releasing() && a.releasing() {
                self.pf().claimed.insert((record, a.pf_token().to_owned()));
            }
        }
    }

    pub fn finish(&self) -> Final {
        let pf = self.pf();
        Final {
            live: pf.live.clone(),
            rules: pf.rules.clone(),
            violations: pf.violations.clone(),
            anonymous: pf.anonymous.clone(),
            transient: state::load_presence(&self.dir),
            standing: lockdown_state::load_presence(&self.dir),
        }
    }

    fn held_on_return(&self, kind: Kind, token: &str) -> bool {
        let held = match kind {
            Kind::TransientEngage => state::holds(&self.dir, token),
            Kind::StandingEngage => lockdown_state::holds(&self.dir, token),
            Kind::Release | Kind::Disengage => unreachable!("only an engage holds a record"),
        };
        held == Held::Held && self.is_live(token)
    }
}

fn seed_transient(dir: &Path, entry: Entry) {
    let live = state::FailClosedState {
        version: state::SCHEMA_VERSION,
        pf_token: T_OLD.into(),
        pf_was_enabled: false,
        releasing: false,
    };
    match entry {
        Entry::Absent => {}
        Entry::Live => state::seed(dir, &live),
        Entry::Tombstone => state::seed(dir, &live.with_releasing(true)),
        Entry::UnusableTokened => write_unusable(dir, state::STATE_FILE_NAME, Some(T_OLD)),
        Entry::UnusableAnonymous => write_unusable(dir, state::STATE_FILE_NAME, None),
    }
}

fn seed_standing(dir: &Path, entry: Entry) {
    let live = lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: S_OLD.into(),
        main_snapshot: HOST_RULES.into(),
        nat_snapshot: String::new(),
        main_snapshot_captured: true,
        releasing: false,
    };
    match entry {
        Entry::Absent => {}
        Entry::Live => lockdown_state::seed(dir, &live),
        Entry::Tombstone => lockdown_state::seed(dir, &live.with_releasing(true)),
        Entry::UnusableTokened => write_unusable(dir, lockdown_state::STATE_FILE_NAME, Some(S_OLD)),
        Entry::UnusableAnonymous => write_unusable(dir, lockdown_state::STATE_FILE_NAME, None),
    }
}

fn write_unusable(dir: &Path, file: &str, token: Option<&str>) {
    let body = match token {
        Some(t) => format!("{{\"version\":1,\"pf_token\":\"{t}\",\"unknown_field\":true}}"),
        None => "not json".to_owned(),
    };
    std::fs::write(dir.join(file), body).unwrap();
}

// pf operations =======================================================================================================

/// [`PfOps`] over the world, for a release or for the drop of an overtaken cover.
pub struct PfParty<'a> {
    world: &'a World,
    gate: &'a Gate,
    who: &'static str,
}

impl<'a> PfParty<'a> {
    pub fn new(world: &'a World, gate: &'a Gate, who: &'static str) -> Self {
        Self { world, gate, who }
    }
}

/// What a text loaded through `pfctl -f -` does to the model: only a cover's own
/// text blocks; a restore opens the host.
fn restore_rules(text: &str) -> Rules {
    assert!(
        !text.contains(LOCKDOWN_PF_LABEL) && !text.contains("block out all"),
        "a release loaded a cover's ruleset"
    );
    Rules::Open
}

impl PfOps for PfParty<'_> {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.gate.step(Op::new("reload_default").commutes(Res::Ruleset));
        self.world.set_rules(Rules::Open);
        Ok(())
    }

    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        self.gate.step(Op::new("load_restore").commutes(Res::Ruleset));
        self.world.set_rules(restore_rules(text));
        Ok(())
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(
            Op::new("drop_token")
                .writes(Res::Token(token.into()))
                .commutes(Res::Enabled),
        );
        self.world.drop_token(self.who, token)
    }

    fn clear_transient(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        self.gate.step(Op::new("clear_transient").writes(Res::Transient));
        clear_transient_record(&self.world.dir, token, claimed)
    }

    fn clear_standing(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        self.gate.step(Op::new("clear_standing").writes(Res::Standing));
        clear_standing_record(&self.world.dir, token, claimed)
    }

    fn peek(&mut self, record: Record, token: Option<&str>, claimed: bool) -> Cleared {
        let res = match record {
            Record::Transient => Res::Transient,
            Record::Standing => Res::Standing,
        };
        self.gate.step(Op::new("peek").reads(res));
        peek_record(&self.world.dir, record, token, claimed)
    }

    fn claim_transient(&mut self) -> StateFile<state::FailClosedState> {
        self.gate.step(Op::new("claim_transient").writes(Res::Transient));
        let before = state::load_presence(&self.world.dir);
        let after = state::claim_for_release(&self.world.dir, None);
        self.world.note_claim(Record::Transient, &before, &after);
        after
    }

    fn claim_standing(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        self.gate.step(Op::new("claim_standing").writes(Res::Standing));
        let before = lockdown_state::load_presence(&self.world.dir);
        let after = lockdown_state::claim_for_release(&self.world.dir, None);
        self.world.note_claim(Record::Standing, &before, &after);
        after
    }

    fn lockdown_label(&mut self) -> Option<bool> {
        self.gate.step(Op::new("lockdown_label").reads(Res::Ruleset));
        Some(matches!(self.world.rules(), Rules::Standing(_)))
    }
}

// The transient engage ================================================================================================

struct TransientParty<'a> {
    world: &'a World,
    gate: &'a Gate,
    real: RealEngageOps<'a>,
    token: Option<String>,
}

impl CoverRulesetOps for TransientParty<'_> {
    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.gate.step(Op::new("load_cover").writes(Res::Ruleset));
        let token = self.token.clone().expect("the cover loads after the enable");
        self.world.set_rules(Rules::Transient(token));
        Ok(())
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        Ok(())
    }
}

impl EngageOps for TransientParty<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        self.gate.step(Op::new("pf_enabled").reads(Res::Enabled));
        Ok(self.world.pf_enabled())
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        self.gate.step(Op::new("enable").writes(Res::Enabled));
        let token = self.world.mint("T");
        self.token = Some(token.clone());
        Ok(token)
    }

    fn read_transient(&mut self) -> StateFile<state::FailClosedState> {
        self.gate.step(Op::new("read_transient").reads(Res::Transient));
        self.real.read_transient()
    }

    fn save_transient(
        &mut self,
        expected: &StateFile<state::FailClosedState>,
        st: &state::FailClosedState,
    ) -> Result<(), RoutingError> {
        self.gate.step(Op::new("save_transient").writes(Res::Transient));
        self.real.save_transient(expected, st)
    }

    fn transient_commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(Op::new("commit_check").reads(Res::Transient));
        self.real.transient_commit_check(token)
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(
            Op::new("drop_token")
                .writes(Res::Token(token.into()))
                .commutes(Res::Enabled),
        );
        self.world.drop_token("the transient engage", token)
    }

    fn transient_restore(&mut self, token: &str) -> bool {
        disengage_with(
            Some(token),
            false,
            &mut PfParty::new(self.world, self.gate, "the transient back-out"),
        )
    }

    fn reassert_transient(&mut self, token: &str) {
        self.gate.step(Op::new("reassert_transient").writes(Res::Transient));
        self.real.reassert_transient(token);
    }
}

// The standing engage =================================================================================================

struct StandingParty<'a> {
    world: &'a World,
    gate: &'a Gate,
    real: RealLockdownEngageOps<'a>,
    token: Option<String>,
}

impl CoverRulesetOps for StandingParty<'_> {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        let rules = if text.contains(LOCKDOWN_PF_LABEL) {
            self.gate.step(Op::new("load_cover").writes(Res::Ruleset));
            // A re-engage that reuses the record's token never enabled one.
            Rules::Standing(self.token.clone().unwrap_or_else(|| "reused".into()))
        } else {
            self.gate.step(Op::new("load_restore").commutes(Res::Ruleset));
            restore_rules(text)
        };
        self.world.set_rules(rules);
        Ok(())
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        Ok(())
    }
}

impl LockdownEngageOps for StandingParty<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        self.gate.step(Op::new("pf_enabled").reads(Res::Enabled));
        Ok(self.world.pf_enabled())
    }

    fn read_record(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        self.gate.step(Op::new("read_record").reads(Res::Standing));
        self.real.read_record()
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        self.gate.step(Op::new("enable").writes(Res::Enabled));
        let token = self.world.mint("S");
        self.token = Some(token.clone());
        Ok(token)
    }

    fn capture_and_persist(
        &mut self,
        token: &str,
        expected: &StateFile<lockdown_state::LockdownPfState>,
    ) -> Result<lockdown_state::LockdownPfState, RoutingError> {
        self.gate
            .step(Op::new("capture_and_persist").reads(Res::Ruleset).writes(Res::Standing));
        let presence = match self.world.rules() {
            Rules::Standing(_) => crate::routing::CoverPresence::Live,
            Rules::Open | Rules::Transient(_) => crate::routing::CoverPresence::Absent,
        };
        persist_baseline(
            token,
            self.real.site(),
            expected,
            presence,
            HOST_RULES.into(),
            String::new(),
        )
    }

    fn persist(
        &mut self,
        expected: &StateFile<lockdown_state::LockdownPfState>,
        fresh: &lockdown_state::LockdownPfState,
    ) -> Result<(), RoutingError> {
        self.gate.step(Op::new("persist").writes(Res::Standing));
        self.real.persist(expected, fresh)
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(
            Op::new("drop_token")
                .writes(Res::Token(token.into()))
                .commutes(Res::Enabled),
        );
        self.world.drop_token("the standing engage", token)
    }

    fn commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(Op::new("commit_check").reads(Res::Standing));
        self.real.commit_check(token)
    }

    fn clear_dropped(&mut self, token: &str) -> Result<(), RoutingError> {
        self.gate.step(Op::new("clear_dropped").writes(Res::Standing));
        self.real.clear_dropped(token)
    }

    fn reassert(&mut self, baseline: &lockdown_state::LockdownPfState) -> Result<bool, RoutingError> {
        self.gate.step(Op::new("reassert").writes(Res::Standing));
        self.real.reassert(baseline)
    }

    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.gate.step(Op::new("reload_default").commutes(Res::Ruleset));
        self.world.set_rules(Rules::Open);
        Ok(())
    }
}

// The parties =========================================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `release_all`, under the facade's epoch.
    Release,
    /// `disengage_lockdown`, under the facade's epoch.
    Disengage,
    /// The transient `engage` through the facade's watch.
    TransientEngage,
    /// `engage_lockdown` through the facade's watch.
    StandingEngage,
}

impl Kind {
    pub fn is_engage(self) -> bool {
        match self {
            Kind::TransientEngage | Kind::StandingEngage => true,
            Kind::Release | Kind::Disengage => false,
        }
    }

    pub fn touches_transient(self) -> bool {
        match self {
            Kind::Release | Kind::TransientEngage => true,
            Kind::Disengage | Kind::StandingEngage => false,
        }
    }

    pub fn touches_standing(self) -> bool {
        match self {
            Kind::Release | Kind::Disengage | Kind::StandingEngage => true,
            Kind::TransientEngage => false,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Release => "release_all",
            Kind::Disengage => "disengage_lockdown",
            Kind::TransientEngage => "transient engage",
            Kind::StandingEngage => "standing engage",
        })
    }
}

/// How a party ended.
pub struct Outcome {
    pub kind: Kind,
    /// `None`: it returned `Ok`. Otherwise the error, and whether it was `SupersededByRelease`.
    pub failure: Option<(bool, String)>,
    /// An engage that returned `Ok`: its record was the live one naming its token, and pf held it.
    pub held_on_return: bool,
}

impl Outcome {
    fn returned(kind: Kind, result: Result<(), RoutingError>) -> Self {
        Self {
            kind,
            failure: result
                .err()
                .map(|e| (matches!(e, RoutingError::SupersededByRelease), e.to_string())),
            held_on_return: false,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.failure.is_none()
    }
}

pub fn run_party(kind: Kind, world: &World, gate: &Gate) -> Outcome {
    match kind {
        Kind::Release => release(kind, world, gate, |pf| release_all_over(pf)),
        Kind::Disengage => release(kind, world, gate, |pf| disengage_lockdown_over(pf)),
        Kind::TransientEngage => engage(kind, world, gate, |watch| {
            let mut ops = TransientParty {
                world,
                gate,
                real: RealEngageOps {
                    state_dir: &world.dir,
                    owner: None,
                    watch,
                },
                token: None,
            };
            engage_with(server(), None, &mut ops)
        }),
        Kind::StandingEngage => engage(kind, world, gate, |watch| {
            let mut ops = StandingParty {
                world,
                gate,
                real: RealLockdownEngageOps {
                    state_dir: &world.dir,
                    owner: None,
                    watch,
                },
                token: None,
            };
            engage_lockdown_with(server(), TUN, &mut ops)
        }),
    }
}

/// A release entry: announced, run, ended, as the facade does.
fn release(
    kind: Kind,
    world: &World,
    gate: &Gate,
    run: impl FnOnce(&mut PfParty<'_>) -> Result<(), RoutingError>,
) -> Outcome {
    gate.step(Op::new("begin_release").commutes(Res::Epoch));
    let in_flight = begin_release(&world.dir);
    let result = run(&mut PfParty::new(world, gate, "the release"));
    gate.step(Op::new("end_release").commutes(Res::Epoch));
    drop(in_flight);
    Outcome::returned(kind, result)
}

/// An engage entry: a watch, the engage, the watch's check, and the overtaken
/// cover's drop, as `engage_within_watch` and `Cover::drop` do.
fn engage(
    kind: Kind,
    world: &World,
    gate: &Gate,
    run: impl FnOnce(&ReleaseWatch) -> Result<String, RoutingError>,
) -> Outcome {
    gate.step(Op::new("watch_releases").reads(Res::Epoch));
    let watch = match watch_releases(&world.dir) {
        Ok(watch) => watch,
        Err(e) => return Outcome::returned(kind, Err(e)),
    };
    let token = match run(&watch) {
        Ok(token) => token,
        Err(e) => return Outcome::returned(kind, Err(e)),
    };
    gate.step(Op::new("watch_check").reads(Res::Epoch));
    match watch.check() {
        Ok(()) => Outcome {
            kind,
            failure: None,
            held_on_return: world.held_on_return(kind, &token),
        },
        Err(e) => {
            let mut pf = PfParty::new(world, gate, "the overtaken cover");
            match kind {
                Kind::TransientEngage => {
                    disengage_with(Some(&token), false, &mut pf);
                }
                Kind::StandingEngage => {
                    // `Cover::drop` swallows the error.
                    let _ = disengage_lockdown_over(&mut pf);
                }
                Kind::Release | Kind::Disengage => unreachable!("only an engage holds a cover"),
            }
            Outcome::returned(kind, Err(e))
        }
    }
}
