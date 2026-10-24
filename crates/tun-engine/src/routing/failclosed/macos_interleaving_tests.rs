//! Every interleaving of two parties over the pf cover records.
//!
//! The parties are the four entries a caller can run (the transient and the
//! standing engage, `release_all`, `disengage_lockdown`); the matrix is every
//! unordered pair of them, from every entry state of the records they touch
//! (absent, live, a tombstone, unusable with and without a token), over every
//! order of their steps. A step is one operation on shared state (a record
//! read, write or clear, a pf call, a drop right, the release epoch).
//!
//! After each run the world must satisfy, for any order:
//!
//! - a pf token is dropped only while pf holds it (never twice);
//! - no record names a token pf no longer holds;
//! - no token pf holds is left without a record naming it, except one an engage
//!   overwrote as an unclaimed leftover or one whose record never named it;
//! - a release and a disengage return `Ok` (nothing here fails them), an engage
//!   fails only as `SupersededByRelease`, and an engage that returns `Ok` holds a
//!   live record naming its token and began after every release that ran;
//! - a pf block with no engage that succeeded has a record to recover it from,
//!   and a release leaves an open host when no engage succeeded.
//!
//! The ownership rules the cells exercise are in [`super::pf_claim`].

use super::*;

#[path = "macos_interleaving_explore.rs"]
mod explore;
#[path = "macos_interleaving_world.rs"]
mod world;

use explore::{explore, Run};
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

    for o in &outcomes {
        match (&o.failure, o.kind.is_engage()) {
            (Some((_, why)), false) => out.push(format!("{} failed: {why}", o.kind)),
            (Some((false, why)), true) => out.push(format!("{} failed other than as superseded: {why}", o.kind)),
            (Some((true, _)), true) => {}
            (None, true) if !o.held_on_return => out.push(format!(
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
        if !named.contains(&token.as_str()) && !end.unreachable.contains(token) {
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
) -> (usize, Option<Red>) {
    let cell = format!(
        "{} + {} | transient {transient}, standing {standing}",
        kinds[0], kinds[1]
    );
    if let Ok(only) = std::env::var("DBG_CELL") {
        if !cell.contains(&only) {
            return (0, None);
        }
    }
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
    let started = std::time::Instant::now();
    let stats = explore(&[&a, &b], fresh, |world, run| {
        let found = violations(kinds, &world.finish(), &run);
        if !found.is_empty() {
            failing += 1;
            first.get_or_insert_with(|| format!("{}\n    {}", counterexample(kinds, &run), found.join("\n    ")));
        }
    });
    eprintln!(
        "CELL {cell}: {} runs, {} abandoned, {:?}",
        stats.runs,
        stats.abandoned,
        started.elapsed()
    );
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
    (runs, red)
}

fn entries(any_party_touches: bool) -> &'static [Entry] {
    if any_party_touches {
        &Entry::ALL
    } else {
        &[Entry::Absent]
    }
}

#[skuld::test]
fn no_interleaving_of_two_cover_parties_breaks_a_pf_record_invariant() {
    let base = tempfile::tempdir().unwrap();
    let mut red = Vec::new();
    let (mut cells, mut runs, mut dirs) = (0, 0, 0usize);
    for (i, &a) in Kind::ALL.iter().enumerate() {
        for &b in &Kind::ALL[i..] {
            let kinds = [a, b];
            for &t in entries(a.touches_transient() || b.touches_transient()) {
                for &s in entries(a.touches_standing() || b.touches_standing()) {
                    let (r, found) = explore_cell(kinds, t, s, base.path(), &mut dirs);
                    cells += 1;
                    runs += r;
                    red.extend(found);
                }
            }
        }
    }
    eprintln!("{cells} cells, {runs} interleavings checked");
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
