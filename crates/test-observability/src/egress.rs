//! Outbound-egress probes that tell a runner network loss from a product defect.
//!
//! The privileged cover tests assert on real egress: a baseline before the cover
//! engages, a permit while it is engaged, and "egress is back" after it lifts. A
//! CI runner that briefly loses its network fails those probes exactly as a
//! broken cover would, so a failed probe alone proves nothing about Hole.
//!
//! Three independent signals separate the two causes:
//!
//! * **Hole's own state**, read from the OS by the caller ([`HoleState`]). A
//!   failed probe while Hole still holds a cover is Hole's, whatever the network
//!   is doing. This is what a cover left behind by a partial release or an
//!   earlier test looks like, and it must fail at once rather than read as an
//!   outage.
//! * **A control host** the lifted cover never blocks. It tells a lost network
//!   from a target that is unreachable for another reason, and it is probed on
//!   both sides of whatever it vouches for.
//! * **A `Window`** around a scenario that probes while a cover is engaged. A
//!   cover blocks every host but its own permits, so the control cannot be probed
//!   inside it: the scenario probes a host the cover permits, before and after
//!   each probe whose result it reports ([`InCover`]), and hands the readings to
//!   the judge as a [`Failure`]. Every run opens only once the hosts it claims the
//!   cover blocks answer outside any cover, a rerun's included. A scenario that
//!   reads a capture of the NIC probes the permit over TCP on both sides of its
//!   markers the same way ([`Failure::captured`]).
//!
//! A reading of runner state is vouched for by the control around it: a read
//! that fails, or is not bracketed by an answering control, is taken again; a
//! read that fails with the control answering on both sides is a defect
//! ([`read_with_network_up`]).
//!
//! The residuals (an outage between two adjacent probes of one engage, or over an in-cover reading and
//! gone by the teardown probe) read as defects; see [`InCover`].
//!
//! No wait here has a cap: each round re-probes the real condition, the CI job's
//! wall clock is the only bound, and every change of state is logged.

use std::io;
use std::net::TcpStream;
use std::time::{Duration, Instant};

mod diagnostics;
mod in_cover;

pub use in_cover::{Failure, InCover};

/// Bound on one connect. The peer is a remote host that may never answer, so
/// expiry is a failure of that probe, not a verdict.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause between two rounds of a wait. Pacing for an external event, not a
/// synchronization: every round re-probes the real condition.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Reads from the OS what cover Hole holds right now: `None` when it holds
/// nothing, otherwise a description of what it holds. Taken from OS state
/// (WFP filters, the pf ruleset), never from what a test believes it left.
pub type HoleState<'a> = &'a dyn Fn() -> Option<String>;

/// Dial `addr` (an `ip:port` literal) once.
pub fn probe(addr: &str) -> io::Result<()> {
    let sock = addr
        .parse()
        .unwrap_or_else(|e| panic!("egress target {addr:?} is not ip:port: {e}"));
    TcpStream::connect_timeout(&sock, PROBE_TIMEOUT).map(drop)
}

/// Block until every target in `targets` answers. For a precondition.
///
/// A failing target while `hole_state` reports a cover is not a network loss
/// (a previous test left it behind): panics instead of waiting.
#[track_caller]
pub fn wait_for_egress(what: &str, targets: &[&str], hole_state: HoleState<'_>) {
    if let Err(why) = wait_for_egress_on(&mut System, what, targets, hole_state) {
        panic!("{why}");
    }
}

/// Panic unless every host in `targets` answers once the network is up. See
/// [`check_egress_restored`].
#[track_caller]
pub fn assert_egress_restored(what: &str, targets: &[&str], control: &str, hole_state: HoleState<'_>) {
    if let Err(why) = check_egress_restored(what, targets, control, hole_state) {
        panic!("{why}");
    }
}

/// Wait out a lost network and report whether every host in `targets` answers.
///
/// For the assertion that a lifted cover let egress back out. A probe of
/// `targets` that fails with the network demonstrably up is the verdict: a
/// release that returns while Hole still holds a cover is a defect. A failure is
///
/// * Hole's when `hole_state` reports a cover, at once, whatever `control` says;
/// * the environment's when `control` fails on either side of the probe: the
///   outage may have ended between the two, so only a control that answered
///   before AND after vouches for the network. It waits for `control`, then
///   probes again;
/// * the environment's otherwise: with Hole holding nothing and `control`
///   answering, a target that is down is down on its own (one anycast host can
///   be). It waits for the target, then probes again.
///
/// `control` must be a host the lifted cover never blocked. For a caller that
/// must run cleanup between the measurement and the verdict.
pub fn check_egress_restored(
    what: &str,
    targets: &[&str],
    control: &str,
    hole_state: HoleState<'_>,
) -> Result<(), String> {
    check_egress_restored_on(&mut System, what, targets, control, hole_state)
}

/// Take `read()` with `control` answering on both sides of it, and return what it read.
///
/// For a reading of the runner's own state (its default gateway, its resolver set): the network going
/// away takes that state with it, so a reading taken while it was away is not evidence about Hole. A
/// read, failed or not, with a control probe that failed before or after it is taken again; a cover
/// Hole holds while it waits panics at once ([`wait_for_egress`]), since a cover that blocks `control`
/// is no network loss. A reading that disagrees with the network up on both sides is the caller's to
/// assert on.
///
/// A read that fails with `control` answering on both sides is the verdict, not an outage: it panics
/// with the read's error.
#[track_caller]
pub fn read_with_network_up<T, E: std::fmt::Display>(
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    read: impl FnMut() -> Result<T, E>,
) -> T {
    read_with_network_up_on(&mut System, what, control, hole_state, read).unwrap_or_else(|why| panic!("{why}"))
}

/// Run `scenario` (engage a cover, probe while it is engaged, tear it down) until it holds, and
/// return its value.
///
/// A scenario that fails reports a [`Failure`] AFTER dropping its cover, built from the readings it
/// took inside the cover ([`InCover`]); each run is bracketed by a `Window`. `blocked` lists every
/// host the scenario claims the cover blocks.
pub fn rerun_until_network_holds<T>(
    what: &str,
    control: &str,
    blocked: &[&str],
    hole_state: HoleState<'_>,
    scenario: impl FnMut() -> Result<T, Failure>,
) -> Result<T, String> {
    rerun_until_network_holds_on(&mut System, what, control, blocked, hole_state, scenario)
}

/// [`rerun_until_network_holds`] for a scenario that awaits (an IPC call to the bridge, a capture of a
/// TUN device); the closure may borrow what it needs mutably across runs.
pub async fn rerun_until_network_holds_async<T>(
    what: &str,
    control: &str,
    blocked: &[&str],
    hole_state: HoleState<'_>,
    scenario: impl AsyncFnMut() -> Result<T, Failure>,
) -> Result<T, String> {
    rerun_until_network_holds_async_on(&mut System, what, control, blocked, hole_state, scenario).await
}

/// Run `step` until it holds, for a step that needs the network while Hole holds no block at all (a
/// Full-mode Start needs the default route and an upstream). `Err(why)` is a step that failed.
///
/// `control` is probed on both sides of the step and the failure is judged as [`Failure::uncovered`]:
/// a step that fails with `control` answering on both sides is a defect, otherwise it is run again
/// once `control` answers. Each run is bracketed by a `Window`.
pub async fn rerun_uncovered<T>(
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    step: impl AsyncFnMut() -> Result<T, String>,
) -> Result<T, String> {
    rerun_uncovered_on(&mut System, what, control, hole_state, step).await
}

/// The control probes that bracket one run of a scenario that probes while a cover is engaged.
///
/// [`open_window_on`] waits (uncapped) until `control` and every `blocked` host answer and Hole holds
/// nothing: a block verdict is only evidence if the host would have answered without the cover. After the
/// scenario tore its cover down, [`judge_on`] decides what a [`Failure`] was:
///
/// * Hole holds a cover: the scenario left one behind, a defect;
/// * [`Failure::Defect`]: a defect;
/// * [`Failure::Wavered`]: a probe outside any cover failed, so the network wavered. It waits for
///   `control` and returns `Ok(())`: run the scenario again;
/// * [`Failure::Failed`] (and [`Failure::Unvouched`], with no targets): `control` and the failing
///   targets are probed outside the cover. `control` failing means the network is down: wait, run
///   again. A target failing while `control` answers means the target is down outside any cover: wait
///   for it, run again. Both answering is a defect.
pub(crate) struct Window<'a> {
    what: &'a str,
    control: &'a str,
    hole_state: HoleState<'a>,
    opened: Instant,
}

/// Open a TCP connection to `addr` once the network answers, and return it. For a precondition that
/// must HOLD the connection (a flow that has to exist before a cover engages): a network loss between
/// the wait and the connect is waited out as well, instead of failing the connect.
///
/// A failing `addr` while `hole_state` reports a cover panics, as in [`wait_for_egress`].
#[track_caller]
pub fn connect_when_reachable(what: &str, addr: &str, hole_state: HoleState<'_>) -> TcpStream {
    let connect = |addr: &str| {
        TcpStream::connect_timeout(
            &addr
                .parse()
                .unwrap_or_else(|e| panic!("egress target {addr:?} is not ip:port: {e}")),
            PROBE_TIMEOUT,
        )
    };
    connect_when_reachable_on(&mut System, what, addr, hole_state, connect).unwrap_or_else(|why| panic!("{why}"))
}

/// The OS interactions of the waits, split out so a test can script them.
pub(crate) trait Host {
    fn probe(&mut self, addr: &str) -> io::Result<()>;
    fn pause(&mut self);
    /// Log what the OS says about its network. Called once per wait, at the first failure.
    fn dump(&mut self, what: &str);
}

struct System;

impl Host for System {
    fn probe(&mut self, addr: &str) -> io::Result<()> {
        probe(addr)
    }

    fn pause(&mut self) {
        std::thread::sleep(POLL_INTERVAL);
    }

    fn dump(&mut self, what: &str) {
        diagnostics::dump(what);
    }
}

type Failing = Vec<(String, io::ErrorKind)>;

fn failing_targets(host: &mut impl Host, targets: &[&str]) -> Failing {
    targets
        .iter()
        .filter_map(|t| host.probe(t).err().map(|e| (t.to_string(), e.kind())))
        .collect()
}

pub(crate) fn wait_for_egress_on(
    host: &mut impl Host,
    what: &str,
    targets: &[&str],
    hole_state: HoleState<'_>,
) -> Result<(), String> {
    let mut last_logged: Option<Failing> = None;
    loop {
        let failing = failing_targets(host, targets);
        if failing.is_empty() {
            if last_logged.is_some() {
                tracing::info!("{what}: egress is back");
            }
            return Ok(());
        }
        if let Some(held) = hole_state() {
            return Err(format!("{what}: {failing:?} are unreachable while Hole holds {held}"));
        }
        if last_logged.as_ref() != Some(&failing) {
            if last_logged.is_none() {
                host.dump(what);
            }
            tracing::warn!(
                "{what}: waiting for the runner's network to answer ({failing:?}); Hole holds no cover, so it is the network"
            );
            last_logged = Some(failing);
        }
        host.pause();
    }
}

pub(crate) fn connect_when_reachable_on<T>(
    host: &mut impl Host,
    what: &str,
    addr: &str,
    hole_state: HoleState<'_>,
    mut connect: impl FnMut(&str) -> io::Result<T>,
) -> Result<T, String> {
    loop {
        wait_for_egress_on(host, what, &[addr], hole_state)?;
        match connect(addr) {
            Ok(held) => return Ok(held),
            Err(e) => {
                tracing::warn!(
                    "{what}: {addr} answered a probe but the connection failed ({:?}); waiting again",
                    e.kind()
                );
                host.pause();
            }
        }
    }
}

pub(crate) fn check_egress_restored_on(
    host: &mut impl Host,
    what: &str,
    targets: &[&str],
    control: &str,
    hole_state: HoleState<'_>,
) -> Result<(), String> {
    loop {
        let control_before = host.probe(control).is_ok();
        let failing = failing_targets(host, targets);
        if failing.is_empty() {
            return Ok(());
        }
        if let Some(held) = hole_state() {
            return Err(format!("{what}: {failing:?} stay unreachable while Hole holds {held}"));
        }
        let control_after = host.probe(control).is_ok();
        if control_before && control_after {
            tracing::warn!(
                "{what}: {failing:?} are unreachable while {control} answers and Hole holds no cover, so they are down on their own; waiting for them"
            );
            let down: Vec<&str> = failing.iter().map(|(t, _)| t.as_str()).collect();
            wait_for_egress_on(host, what, &down, hole_state)?;
            continue;
        }
        tracing::warn!("{what}: {control} did not answer around the probe of {failing:?}; waiting for the network");
        wait_for_egress_on(host, what, &[control], hole_state)?;
    }
}

pub(crate) fn read_with_network_up_on<T, E: std::fmt::Display>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    mut read: impl FnMut() -> Result<T, E>,
) -> Result<T, String> {
    loop {
        let before = host.probe(control).is_ok();
        let reading = read();
        let after = host.probe(control).is_ok();
        match reading {
            Ok(value) if before && after => return Ok(value),
            Ok(_) => tracing::warn!(
                "{what}: {control} did not answer around the reading; waiting for the network and reading again"
            ),
            Err(e) if before && after => return Err(format!("{what}: the reading failed with {control} answering around it: {e}")),
            Err(e) => tracing::warn!(
                "{what}: the reading failed ({e}) and {control} did not answer around it; waiting for the network and reading again"
            ),
        }
        wait_for_egress_on(host, what, &[control], hole_state)?;
    }
}

pub(crate) fn rerun_until_network_holds_on<T>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    blocked: &[&str],
    hole_state: HoleState<'_>,
    mut scenario: impl FnMut() -> Result<T, Failure>,
) -> Result<T, String> {
    loop {
        let window = open_window_on(host, what, control, blocked, hole_state)?;
        match scenario() {
            Ok(value) => return Ok(value),
            Err(failure) => judge_on(host, window, failure)?,
        }
    }
}

pub(crate) async fn rerun_until_network_holds_async_on<T>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    blocked: &[&str],
    hole_state: HoleState<'_>,
    mut scenario: impl AsyncFnMut() -> Result<T, Failure>,
) -> Result<T, String> {
    loop {
        let window = open_window_on(host, what, control, blocked, hole_state)?;
        match scenario().await {
            Ok(value) => return Ok(value),
            Err(failure) => judge_on(host, window, failure)?,
        }
    }
}

pub(crate) async fn rerun_uncovered_on<T>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    mut step: impl AsyncFnMut() -> Result<T, String>,
) -> Result<T, String> {
    loop {
        let window = open_window_on(host, what, control, &[], hole_state)?;
        let before = host.probe(control).is_ok();
        match step().await {
            Ok(value) => return Ok(value),
            Err(why) => {
                let after = host.probe(control).is_ok();
                judge_on(host, window, Failure::uncovered(why, &[before, after]))?;
            }
        }
    }
}

pub(crate) fn open_window_on<'a>(
    host: &mut impl Host,
    what: &'a str,
    control: &'a str,
    blocked: &[&str],
    hole_state: HoleState<'a>,
) -> Result<Window<'a>, String> {
    let waited: Vec<&str> = std::iter::once(control).chain(blocked.iter().copied()).collect();
    wait_for_egress_on(host, what, &waited, hole_state)?;
    if let Some(held) = hole_state() {
        return Err(format!(
            "{what}: Hole already holds {held} before the scenario engages anything"
        ));
    }
    Ok(Window {
        what,
        control,
        hole_state,
        opened: Instant::now(),
    })
}

pub(crate) fn judge_on(host: &mut impl Host, window: Window<'_>, failure: Failure) -> Result<(), String> {
    let Window {
        what,
        control,
        hole_state,
        opened,
    } = window;
    let (why, targets) = match failure {
        Failure::Defect(why) => return Err(with_held_cover(why, what, hole_state)),
        Failure::Wavered(why) => {
            if let Some(held) = hole_state() {
                return Err(left_behind(why, what, &held));
            }
            tracing::warn!(
                "{what}: {why}\nthe network wavered inside the run; running the scenario again once {control} answers"
            );
            return wait_for_egress_on(host, what, &[control], hole_state);
        }
        Failure::Failed { why, targets } => (why, targets),
        Failure::Unvouched(why) => (why, Vec::new()),
    };
    if let Some(held) = hole_state() {
        return Err(left_behind(why, what, &held));
    }
    let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
    let control_before = host.probe(control).is_ok();
    let failing = failing_targets(host, &targets);
    let control_after = host.probe(control).is_ok();
    if !(control_before && control_after) {
        tracing::warn!(
            "{what}: {why}\n{control} does not answer around the run's teardown, so the network was down; running the scenario again once it does"
        );
        return wait_for_egress_on(host, what, &[control], hole_state);
    }
    if !failing.is_empty() {
        tracing::warn!(
            "{what}: {why}\n{failing:?} are unreachable outside the cover while {control} answers and Hole holds no cover, so they are down on their own; waiting for them"
        );
        return wait_for_egress_on(host, what, &targets, hole_state);
    }
    Err(format!(
        "{why}\n{what}: {control} and {targets:?} answer outside the cover after a {:?} window and Hole holds no cover, so the run is the cause",
        opened.elapsed()
    ))
}

fn left_behind(why: String, what: &str, held: &str) -> String {
    format!("{why}\n{what}: the scenario ended with Hole still holding {held}")
}

fn with_held_cover(why: String, what: &str, hole_state: HoleState<'_>) -> String {
    match hole_state() {
        Some(held) => left_behind(why, what, &held),
        None => why,
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod egress_tests;
