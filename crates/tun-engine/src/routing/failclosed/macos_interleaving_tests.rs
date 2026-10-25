//! Every interleaving of two parties over the pf cover records.
//!
//! The parties are the four entries a caller can run (the transient and the
//! standing engage, `release_all`, `disengage_lockdown`); the matrix is every
//! unordered pair of them, from every entry state of the records they touch
//! (absent, live, a tombstone, unusable with and without a token), over every
//! order of their steps. A step is one operation on shared state: a record read,
//! write or clear, a pf call, the release epoch. The records are real files and
//! every record step is the production one; only pf is modelled
//! (`macos_interleaving_world_tests.rs`), and the search is `macos_interleaving_explore_tests.rs`.
//!
//! After each run the world must satisfy, for any order:
//!
//! - a token is let go of at most once (the model flags a second `pfctl -X`);
//! - no record names a token pf no longer holds, and no token pf holds is left
//!   without a record naming it (but for the anonymous one an unusable file never
//!   named);
//! - a release and a disengage return `Ok` (nothing here fails them), an engage
//!   fails only as `SupersededByRelease`, and an engage that returns `Ok` had no
//!   release begin while it ran and holds a live record naming its token;
//! - a pf block with no engage that succeeded has a record to recover it from,
//!   and a release leaves an open host when no engage succeeded.
//!
//! Two engages never overlap in the bridge (`start_cancellable` holds the proxy
//! lock), and one replacing the other's record is the cover transition `engage`
//! supports, so the last rule about an engage's own record is asserted only when
//! no other engage runs; the rest hold for every pair.
//!
//! The rules the cells exercise are in [`super::pf_claim`], [`super::dropped_tokens`]
//! and [`super::release_epoch`].

use super::*;

#[path = "macos_interleaving_explore_tests.rs"]
mod explore;
#[path = "macos_interleaving_world_tests.rs"]
mod world;

use explore::{explore, Op, Res, Run, Stats};
use world::{run_party, Entry, Final, Kind, Outcome, Rules, World};

/// What a cell found.
struct Red {
    cell: String,
    runs: usize,
    failing: usize,
    first: String,
}

/// Why `run` ended in a state that breaks one of the rules above.
fn violations(kinds: [Kind; 2], end: &Final, run: &Run<Outcome>) -> Vec<String> {
    let mut out = end.violations.clone();
    let mut outcomes = Vec::new();
    for (kind, result) in kinds.iter().zip(&run.results) {
        match result {
            Ok(outcome) => outcomes.push(outcome),
            Err(message) => out.push(format!("{kind} panicked: {message}")),
        }
    }

    let both_engage = kinds.iter().all(|k| k.is_engage());
    for o in &outcomes {
        match (&o.failure, o.kind.is_engage()) {
            (Some((_, why)), false) => out.push(format!("{} failed: {why}", o.kind)),
            (Some((false, why)), true) => out.push(format!("{} failed other than as superseded: {why}", o.kind)),
            (Some((true, _)), true) => {}
            (None, true) if !o.held_on_return && !both_engage => out.push(format!(
                "{} returned Ok without a live record naming its token and held in pf",
                o.kind
            )),
            (None, _) => {}
        }
    }

    // An engage that returned Ok had no release begin between opening its watch and checking it.
    let first = |who: usize, label: &str| run.trace.iter().position(|&(p, l)| p == who && l == label);
    for (e, engage) in run.results.iter().enumerate() {
        let Ok(engage) = engage else { continue };
        if !(engage.kind.is_engage() && engage.is_ok()) {
            continue;
        }
        let (Some(watch), Some(check)) = (first(e, "watch_releases"), first(e, "watch_check")) else {
            continue;
        };
        for (r, release) in run.results.iter().enumerate() {
            let Ok(release) = release else { continue };
            if release.kind.is_engage() {
                continue;
            }
            if first(r, "begin_release").is_some_and(|begin| watch < begin && begin < check) {
                out.push(format!(
                    "{} returned Ok although {} began after it opened its watch and before it checked it",
                    engage.kind, release.kind
                ));
            }
        }
    }

    // Records and tokens agree.
    let named: Vec<&str> = [end.transient.pf_token(), end.standing.pf_token()]
        .into_iter()
        .flatten()
        .collect();
    for token in &named {
        if !end.live.contains(*token) {
            out.push(format!("a record names {token}, which pf no longer holds"));
        }
    }
    for token in &end.live {
        if !named.contains(&token.as_str()) && !end.anonymous.contains(token) {
            out.push(format!("pf still holds {token} and no record names it"));
        }
    }

    // Blocks have a record; releases open the host.
    let any_record = end.transient != StateFile::Absent || end.standing != StateFile::Absent;
    let returned_ok = |kind: Kind| outcomes.iter().any(|o| o.kind == kind && o.is_ok());
    let any_engage_ok = outcomes.iter().any(|o| o.kind.is_engage() && o.is_ok());
    if end.rules != Rules::Open && !any_record && !any_engage_ok {
        out.push(format!("pf blocks ({:?}) and no record could recover it", end.rules));
    }
    if returned_ok(Kind::Release) && !any_engage_ok && (end.rules != Rules::Open || any_record) {
        out.push(format!(
            "release_all returned Ok and no engage did, but the host is {:?} with records {:?} / {:?}",
            end.rules, end.transient, end.standing
        ));
    }
    let standing_left = matches!(end.rules, Rules::Standing(_)) || end.standing != StateFile::Absent;
    if returned_ok(Kind::Disengage)
        && !returned_ok(Kind::Release)
        && !returned_ok(Kind::StandingEngage)
        && standing_left
    {
        out.push(format!(
            "disengage_lockdown returned Ok and no standing engage did, but the host is {:?} with record {:?}",
            end.rules, end.standing
        ));
    }
    out
}

fn counterexample(kinds: [Kind; 2], run: &Run<Outcome>) -> String {
    let name = |p: usize| {
        let same = kinds[0] == kinds[1];
        if same {
            format!("{}#{p}", kinds[p])
        } else {
            kinds[p].to_string()
        }
    };
    run.trace
        .iter()
        .map(|&(p, label)| format!("{}: {label}", name(p)))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn explore_cell(
    kinds: [Kind; 2],
    transient: Entry,
    standing: Entry,
    base: &std::path::Path,
    dirs: &mut usize,
) -> (Stats, Option<Red>) {
    let cell = format!(
        "{} + {} | transient {transient}, standing {standing}",
        kinds[0], kinds[1]
    );
    let mut last: Option<std::path::PathBuf> = None;
    let mut failing = 0usize;
    let mut first = None;
    let fresh = || {
        if let Some(dir) = last.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
        *dirs += 1;
        let dir = base.join(format!("run{dirs}"));
        last = Some(dir.clone());
        World::new(dir, transient, standing)
    };
    let a = |w: &World, g: &explore::Gate| run_party(kinds[0], w, g);
    let b = |w: &World, g: &explore::Gate| run_party(kinds[1], w, g);
    let stats = explore(&[&a, &b], fresh, |world, run| {
        let found = violations(kinds, &world.finish(), &run);
        if !found.is_empty() {
            failing += 1;
            first.get_or_insert_with(|| format!("{}\n    {}", counterexample(kinds, &run), found.join("\n    ")));
        }
    });
    let runs = stats.runs;
    if let Some(dir) = last.take() {
        let _ = std::fs::remove_dir_all(dir);
    }
    let red = first.map(|first| Red {
        cell,
        runs,
        failing,
        first,
    });
    (stats, red)
}

fn entries(any_party_touches: bool) -> &'static [Entry] {
    if any_party_touches {
        &Entry::ALL
    } else {
        &[Entry::Absent]
    }
}

/// Every cell of one pair: its entry states, and every order of its steps from each.
fn explore_pair(a: Kind, b: Kind) {
    let base = tempfile::tempdir().unwrap();
    let mut red = Vec::new();
    let (mut cells, mut runs, mut abandoned, mut dirs) = (0, 0, 0, 0usize);
    for &t in entries(a.touches_transient() || b.touches_transient()) {
        for &s in entries(a.touches_standing() || b.touches_standing()) {
            let (stats, found) = explore_cell([a, b], t, s, base.path(), &mut dirs);
            cells += 1;
            runs += stats.runs;
            abandoned += stats.abandoned;
            red.extend(found);
        }
    }
    eprintln!("{a} + {b}: {cells} cells, {runs} interleavings checked, {abandoned} abandoned as already covered");
    let report: Vec<String> = red
        .iter()
        .map(|r| format!("{} ({} of {} runs)\n  {}", r.cell, r.failing, r.runs, r.first))
        .collect();
    assert!(
        red.is_empty(),
        "{} of {cells} cells are red:\n{}",
        red.len(),
        report.join("\n")
    );
}

#[skuld::test]
fn no_order_of_two_release_alls_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Release, Kind::Release);
}

#[skuld::test]
fn no_order_of_release_all_and_disengage_lockdown_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Release, Kind::Disengage);
}

#[skuld::test]
fn no_order_of_release_all_and_a_transient_engage_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Release, Kind::TransientEngage);
}

#[skuld::test]
fn no_order_of_release_all_and_a_standing_engage_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Release, Kind::StandingEngage);
}

#[skuld::test]
fn no_order_of_two_disengage_lockdowns_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Disengage, Kind::Disengage);
}

#[skuld::test]
fn no_order_of_disengage_lockdown_and_a_transient_engage_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Disengage, Kind::TransientEngage);
}

#[skuld::test]
fn no_order_of_disengage_lockdown_and_a_standing_engage_breaks_a_pf_record_invariant() {
    explore_pair(Kind::Disengage, Kind::StandingEngage);
}

#[skuld::test]
fn no_order_of_two_transient_engages_breaks_a_pf_record_invariant() {
    explore_pair(Kind::TransientEngage, Kind::TransientEngage);
}

#[skuld::test]
fn no_order_of_a_transient_and_a_standing_engage_breaks_a_pf_record_invariant() {
    explore_pair(Kind::TransientEngage, Kind::StandingEngage);
}

#[skuld::test]
fn no_order_of_two_standing_engages_breaks_a_pf_record_invariant() {
    explore_pair(Kind::StandingEngage, Kind::StandingEngage);
}

// The search itself ===================================================================================================

/// A party of the search's own check: it steps through its operations.
type ToyParty = Box<dyn Fn(&(), &explore::Gate) + Sync>;

/// A small deterministic generator, so a failing case names its seed.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, n: u64) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) % n) as usize
    }
}

fn random_op(rng: &mut Lcg) -> Op {
    let res = [Res::Transient, Res::Standing, Res::Ruleset][rng.below(3)].clone();
    let op = Op::new("op");
    match rng.below(3) {
        0 => op.reads(res),
        1 => op.writes(res),
        _ => op.commutes(res),
    }
}

/// Which way each pair of conflicting operations of different parties went: what
/// separates one class of interleavings from another.
fn class_of(order: &[(usize, usize)], parties: &[Vec<Op>]) -> Vec<((usize, usize), (usize, usize))> {
    let mut pairs = Vec::new();
    for (i, &(p, a)) in order.iter().enumerate() {
        for &(q, b) in &order[i + 1..] {
            if p != q && parties[p][a].conflicts(&parties[q][b]) {
                pairs.push(((p, a), (q, b)));
            }
        }
    }
    pairs.sort();
    pairs
}

fn all_interleavings(parties: &[Vec<Op>]) -> Vec<Vec<(usize, usize)>> {
    fn go(
        parties: &[Vec<Op>],
        next: &mut Vec<usize>,
        order: &mut Vec<(usize, usize)>,
        out: &mut Vec<Vec<(usize, usize)>>,
    ) {
        if next.iter().zip(parties).all(|(n, p)| *n == p.len()) {
            out.push(order.clone());
            return;
        }
        for p in 0..parties.len() {
            if next[p] < parties[p].len() {
                order.push((p, next[p]));
                next[p] += 1;
                go(parties, next, order, out);
                next[p] -= 1;
                order.pop();
            }
        }
    }
    let mut out = Vec::new();
    go(parties, &mut vec![0; parties.len()], &mut Vec::new(), &mut out);
    out
}

#[skuld::test]
fn the_search_reaches_every_class_of_interleaving_a_full_enumeration_does() {
    let mut reduced_somewhere = false;
    for seed in 0..1500u64 {
        let mut rng = Lcg(seed);
        let parties: Vec<Vec<Op>> = (0..2)
            .map(|_| (0..1 + rng.below(5)).map(|_| random_op(&mut rng)).collect())
            .collect();

        let full = all_interleavings(&parties);
        let expected: std::collections::BTreeSet<_> = full.iter().map(|o| class_of(o, &parties)).collect();

        let mut reached = std::collections::BTreeSet::new();
        let fns: Vec<ToyParty> = parties
            .iter()
            .map(|ops| {
                let ops = ops.clone();
                Box::new(move |_: &(), gate: &explore::Gate| {
                    for op in &ops {
                        gate.step(op.clone());
                    }
                }) as ToyParty
            })
            .collect();
        let refs: Vec<explore::PartyFn<'_, (), ()>> = fns.iter().map(|f| &**f).collect();
        let stats = explore(
            &refs,
            || (),
            |_, run| {
                let mut seen = vec![0; parties.len()];
                let order: Vec<(usize, usize)> = run
                    .trace
                    .iter()
                    .map(|&(p, _)| {
                        seen[p] += 1;
                        (p, seen[p] - 1)
                    })
                    .collect();
                reached.insert(class_of(&order, &parties));
            },
        );

        let missed: Vec<_> = expected.difference(&reached).collect();
        assert!(
            missed.is_empty(),
            "seed {seed}: classes never run: {missed:?}
parties: {parties:?}"
        );
        assert!(
            stats.runs + stats.abandoned <= full.len(),
            "seed {seed}: more runs than interleavings"
        );
        reduced_somewhere |= stats.runs + stats.abandoned < full.len();
    }
    assert!(reduced_somewhere, "and the search must actually skip some");
}
