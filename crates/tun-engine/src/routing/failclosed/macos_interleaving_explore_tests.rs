//! A deterministic scheduler that runs the interleavings of a few parties, one
//! at a time, and a depth-first search over its choices.
//!
//! Each party runs on its own thread, but only the one the scheduler resumed
//! runs: a party parks in [`Gate::step`] before each operation that touches
//! shared state, saying which resources it is about to touch ([`Op`]). The
//! scheduler then picks the next party. No timing is involved: a run is a
//! sequence of choices, and the search replays prefixes of it.
//!
//! Two operations of different parties that touch no resource in common (or
//! only read it) commute, so their order cannot change any outcome. The search
//! is dynamic partial-order reduction with sleep sets (Flanagan and Godefroid,
//! POPL 2005): after a run it finds the pairs of conflicting operations whose
//! order nothing else in the run forces, and tries the other order at that
//! point; a party already tried first from an equivalent state sleeps instead of
//! being tried again. Every class of runs that differ only by swapping commuting
//! operations is reached, and the search is finite because every party's
//! operations are.

use std::any::Any;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::mpsc::{channel, Receiver, Sender};

/// Something two parties can contend for.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Res {
    /// `bridge-failclosed.json`.
    Transient,
    /// `bridge-lockdown-pf.json`.
    Standing,
    /// The ruleset pf has loaded.
    Ruleset,
    /// Whether pf is enabled, which is whether any enable token is live.
    Enabled,
    /// One pf enable token.
    Token(String),
    /// The release epoch.
    Epoch,
}

/// How an operation touches a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    /// An update that commutes with every other `Commute` of the same resource
    /// (a counter bump, or a write of the one value all such writers store), yet
    /// not with a read or a `Write` of it.
    Commute,
}

impl Access {
    fn conflicts(self, other: Access) -> bool {
        !matches!(
            (self, other),
            (Access::Read, Access::Read) | (Access::Commute, Access::Commute)
        )
    }
}

/// The next thing a party does, and what it touches.
#[derive(Clone, Debug)]
pub struct Op {
    pub label: &'static str,
    touches: Vec<(Res, Access)>,
}

impl Op {
    pub fn new(label: &'static str) -> Self {
        Self {
            label,
            touches: Vec::new(),
        }
    }

    pub fn reads(mut self, res: Res) -> Self {
        self.touches.push((res, Access::Read));
        self
    }

    pub fn writes(mut self, res: Res) -> Self {
        self.touches.push((res, Access::Write));
        self
    }

    pub fn commutes(mut self, res: Res) -> Self {
        self.touches.push((res, Access::Commute));
        self
    }

    /// Whether the order of `self` and `other` can matter.
    pub fn conflicts(&self, other: &Op) -> bool {
        self.touches.iter().any(|(res, mine)| {
            other
                .touches
                .iter()
                .any(|(theirs_res, theirs)| res == theirs_res && mine.conflicts(*theirs))
        })
    }
}

enum Event<T> {
    Parked(usize, Op),
    /// `Err(None)`: cancelled by the scheduler. `Err(Some(_))`: panicked.
    Done(usize, Result<T, Option<String>>),
}

/// The scheduler cancelled this party; unwinding carries it out of the code under test.
struct Cancelled;

/// A party's handle on the scheduler.
pub struct Gate {
    park: Box<dyn Fn(Op) -> bool>,
}

impl Gate {
    /// Park until the scheduler resumes this party; `op` is what it then does.
    pub fn step(&self, op: Op) {
        if !(self.park)(op) {
            resume_unwind(Box::new(Cancelled));
        }
    }
}

/// One party: the code it runs against the world, given its gate.
pub type PartyFn<'a, W, T> = &'a (dyn Fn(&W, &Gate) -> T + Sync);

/// How a run went.
pub struct Run<T> {
    /// Each party's result, or the message it panicked with.
    pub results: Vec<Result<T, String>>,
    /// Who did what, in order.
    pub trace: Vec<(usize, &'static str)>,
}

/// What the search did.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Runs that finished and were observed.
    pub runs: usize,
    /// Runs abandoned because every party that could run next was asleep.
    pub abandoned: usize,
}

/// A decision point along the current path.
struct Node {
    /// Every party's next operation here.
    pending: Vec<Option<Op>>,
    /// Parties whose turn here was already covered from an equivalent state.
    sleep: BTreeSet<usize>,
    /// The parties to try from here. A party joins when a run shows that
    /// running it here, before what the path ran, reverses a race.
    backtrack: BTreeSet<usize>,
    /// The parties tried from here, in order; the last is the one the path runs.
    done: Vec<usize>,
}

impl Node {
    fn chosen(&self) -> usize {
        *self.done.last().expect("a node always has a party it runs")
    }
}

/// What one run executed, for the search to learn races from.
struct Executed {
    /// The operations run, in order, with the party that ran each.
    events: Vec<(usize, Op)>,
    /// The operations the parties were parked at when the run ended early.
    parked: Vec<(usize, Op)>,
}

/// Run the interleavings of two parties that are not equivalent by swapping
/// commuting operations, a fresh world per run from `fresh`, handing each
/// finished run to `observe`.
///
/// Exactly two parties: with three, the search below misses classes of
/// interleavings (the check in `macos_interleaving_tests` finds it), so it refuses.
pub fn explore<W: Sync, T: Send + 'static>(
    parties: &[PartyFn<'_, W, T>],
    mut fresh: impl FnMut() -> W,
    mut observe: impl FnMut(&W, Run<T>),
) -> Stats {
    assert_eq!(parties.len(), 2, "the search is only proved for two parties");
    let mut stats = Stats::default();
    let mut path: Vec<Node> = Vec::new();
    loop {
        let world = fresh();
        let (run, executed) = run_once(parties, &world, &mut path);
        match run {
            Some(run) => {
                stats.runs += 1;
                observe(&world, run);
            }
            None => stats.abandoned += 1,
        }
        add_backtracks(&mut path, &executed);
        loop {
            let Some(node) = path.last_mut() else {
                return stats;
            };
            if let Some(&next) = node.backtrack.iter().find(|p| !node.done.contains(p)) {
                node.done.push(next);
                break;
            }
            path.pop();
        }
    }
}

/// For every pair of conflicting operations of different parties that nothing
/// else in the run orders, make the search try the later party first at the
/// earlier operation's decision point (or, if it was not able to run there,
/// every party that was). Parties asleep there were covered from an equivalent
/// state already.
fn add_backtracks(path: &mut [Node], executed: &Executed) {
    let events = &executed.events;
    let n = events.len();
    // before[j]: the events ordered before event j by program order and conflicts.
    let mut before: Vec<Vec<bool>> = Vec::with_capacity(n);
    let mut last_of_party: Vec<Option<usize>> = vec![None; path.first().map_or(0, |node| node.pending.len())];

    // The predecessors of an operation `op` of `party` coming after the first `j` events.
    let predecessors = |j: usize, party: usize, op: &Op, last_of_party: &[Option<usize>]| -> Vec<usize> {
        (0..j)
            .filter(|&k| last_of_party[party] == Some(k) || (events[k].0 != party && events[k].1.conflicts(op)))
            .collect()
    };
    let races = |preds: &[usize], party: usize, op: &Op, before: &[Vec<bool>]| -> Vec<usize> {
        preds
            .iter()
            .copied()
            .filter(|&i| events[i].0 != party && events[i].1.conflicts(op))
            // Another predecessor that already follows `i` orders it before `op`.
            .filter(|&i| !preds.iter().any(|&k| k != i && before[k][i]))
            .collect()
    };

    let mut learned: Vec<(usize, usize)> = Vec::new();
    for (j, (party, op)) in events.iter().enumerate() {
        let preds = predecessors(j, *party, op, &last_of_party);
        learned.extend(races(&preds, *party, op, &before).into_iter().map(|i| (i, *party)));
        let mut ordered = vec![false; n];
        for &k in &preds {
            ordered[k] = true;
            for (b, k_before) in ordered.iter_mut().zip(&before[k]) {
                *b |= *k_before;
            }
        }
        before.push(ordered);
        last_of_party[*party] = Some(j);
    }
    for (party, op) in &executed.parked {
        let preds = predecessors(n, *party, op, &last_of_party);
        learned.extend(races(&preds, *party, op, &before).into_iter().map(|i| (i, *party)));
    }

    for (i, party) in learned {
        let node = &mut path[i];
        if node.pending[party].is_some() {
            if !node.sleep.contains(&party) {
                node.backtrack.insert(party);
            }
            continue;
        }
        let runnable: Vec<usize> = (0..node.pending.len())
            .filter(|p| node.pending[*p].is_some() && !node.sleep.contains(p))
            .collect();
        node.backtrack.extend(runnable);
    }
}

fn run_once<W: Sync, T: Send + 'static>(
    parties: &[PartyFn<'_, W, T>],
    world: &W,
    path: &mut Vec<Node>,
) -> (Option<Run<T>>, Executed) {
    let n = parties.len();
    let (events, inbox) = channel::<Event<T>>();
    std::thread::scope(|scope| {
        let mut resume: Vec<Sender<()>> = Vec::new();
        for (id, party) in parties.iter().enumerate() {
            let (resume_tx, resume_rx) = channel();
            resume.push(resume_tx);
            let events = events.clone();
            scope.spawn(move || {
                let gate = gate_for(id, events.clone(), resume_rx);
                let result = catch_unwind(AssertUnwindSafe(|| party(world, &gate)));
                let done = result.map_err(|payload| panic_message(&*payload));
                let _ = events.send(Event::Done(id, done));
            });
        }
        drop(events);

        let mut pending: Vec<Option<Op>> = vec![None; n];
        let mut results: Vec<Option<Result<T, String>>> = (0..n).map(|_| None).collect();
        for _ in 0..n {
            absorb(inbox.recv().expect("every party reports"), &mut pending, &mut results);
        }

        let mut events: Vec<(usize, Op)> = Vec::new();
        let mut sleep: BTreeSet<usize> = BTreeSet::new();
        for depth in 0.. {
            if pending.iter().all(Option::is_none) {
                let trace = events.iter().map(|(party, op)| (*party, op.label)).collect();
                let results = results.into_iter().map(|r| r.expect("every party finished")).collect();
                return (
                    Some(Run { results, trace }),
                    Executed {
                        events,
                        parked: Vec::new(),
                    },
                );
            }
            if depth == path.len() {
                let Some(first) = (0..n).find(|p| pending[*p].is_some() && !sleep.contains(p)) else {
                    // Everything that could run next ran first from an equivalent state.
                    let parked = (0..n).filter_map(|p| pending[p].clone().map(|op| (p, op))).collect();
                    drop(resume);
                    return (None, Executed { events, parked });
                };
                path.push(Node {
                    pending: pending.clone(),
                    sleep: sleep.clone(),
                    backtrack: BTreeSet::from([first]),
                    done: vec![first],
                });
            }
            let node = &path[depth];
            let chosen = node.chosen();
            let op = pending[chosen].clone().expect("the path only chooses a parked party");
            let tried = &node.done[..node.done.len() - 1];
            sleep = node
                .sleep
                .iter()
                .chain(tried)
                .copied()
                .filter(|q| node.pending[*q].as_ref().is_some_and(|other| !other.conflicts(&op)))
                .collect();
            events.push((chosen, op));
            resume[chosen].send(()).expect("a parked party is waiting");
            absorb(
                inbox.recv().expect("the resumed party reports"),
                &mut pending,
                &mut results,
            );
        }
        unreachable!("the loop returns when every party is done or asleep")
    })
}

fn absorb<T>(event: Event<T>, pending: &mut [Option<Op>], results: &mut [Option<Result<T, String>>]) {
    match event {
        Event::Parked(id, op) => pending[id] = Some(op),
        Event::Done(id, done) => {
            pending[id] = None;
            results[id] = Some(done.map_err(Option::unwrap_or_default));
        }
    }
}

fn gate_for<T: Send + 'static>(id: usize, events: Sender<Event<T>>, resume: Receiver<()>) -> Gate {
    Gate {
        park: Box::new(move |op| {
            events.send(Event::Parked(id, op)).expect("the scheduler listens");
            resume.recv().is_ok()
        }),
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> Option<String> {
    if payload.is::<Cancelled>() {
        return None;
    }
    let text = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "a panic with a non-text payload".to_owned());
    Some(text)
}
