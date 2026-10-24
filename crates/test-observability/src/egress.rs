//! Outbound-egress probes that tell a runner network loss from a product defect.
//!
//! The privileged cover tests assert on real egress: a baseline before the cover
//! engages, a permit while it is engaged, and "egress is back" after it lifts. A
//! CI runner that briefly loses its network fails those probes exactly as a
//! broken cover would, so a failed probe alone proves nothing about Hole.
//!
//! Two independent signals separate the two causes:
//!
//! * **Hole's own state**, read from the OS by the caller ([`HoleState`]). A
//!   failed probe while Hole still holds a cover is Hole's, whatever the network
//!   is doing. This is what a cover left behind by a partial release or an
//!   earlier test looks like, and it must fail at once rather than read as an
//!   outage.
//! * **A control host** the lifted cover never blocks. It tells a lost network
//!   from a target that is unreachable for another reason, and it is probed on
//!   both sides of whatever it vouches for.
//!
//! No wait here has a cap: each round re-probes the real condition, the test's
//! own nextest timeout is the bound, and every change of state is logged.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

mod diagnostics;

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
/// For the assertion that a lifted cover let egress back out. The first probe
/// of `targets` is the verdict; there is no second chance, because a release
/// that returns before egress is restored is a defect. A failure is
///
/// * Hole's when `hole_state` reports a cover, at once, whatever `control` says;
/// * the environment's when `control` fails on either side of the probe: the
///   outage may have ended between the two, so only a control that answered
///   before AND after vouches for the network. It waits for `control`, then
///   probes again;
/// * Hole's otherwise: `targets` unreachable with the network demonstrably up
///   and no cover installed.
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

/// Take `read()` with `control` answering on both sides of it.
///
/// For a comparison against the runner's own state (its resolver set): the
/// network going away takes that state with it, so a reading taken while it was
/// away is not evidence about Hole. A control probe that failed before or after
/// the read sends it back to wait for the network and read again. A reading
/// that disagrees with the network up on both sides is the caller's to assert on.
pub fn read_with_network_up<T>(what: &str, control: &str, read: impl FnMut() -> T) -> T {
    read_with_network_up_on(&mut System, what, control, read)
}

/// Run `scenario` (engage a cover, probe while it is engaged, tear it down) until
/// it holds, and return its value.
///
/// A probe made while the cover is engaged cannot use a control host: the cover
/// blocks everything but its own permit. So a permit probe that fails is
/// reported as `Err(why)` AFTER the scenario has dropped its cover, and the
/// verdict is taken by [`judge_failed_run`].
pub fn rerun_until_network_holds<T>(
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    scenario: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    rerun_until_network_holds_on(&mut System, what, control, hole_state, scenario)
}

/// The verdict on one failed run of a scenario whose cover has already been torn down, for a caller
/// whose scenario cannot be a sync closure (it awaits): `Ok(())` means the network was down and has
/// answered again, so run the scenario again; `Err` is a defect, to be reported as it stands.
///
/// * `hole_state` reports a cover: the scenario left one behind, a defect;
/// * `control` fails: the network was down. It waits for `control` to answer;
/// * `control` answers: the failure was the cover's, a defect, returned as `why`.
///
/// A control that answers does not prove the network was up during the failed probe: an outage that
/// ended before the control probe reads as a permit failure.
pub fn judge_failed_run(what: &str, control: &str, hole_state: HoleState<'_>, why: String) -> Result<(), String> {
    judge_failed_run_on(&mut System, what, control, hole_state, why)
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
            Err(e) => tracing::warn!(
                "{what}: {addr} answered a probe but the connection failed ({:?}); waiting again",
                e.kind()
            ),
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
            return Err(format!(
                "{what}: {failing:?} stay unreachable while {control} answers and Hole holds no cover"
            ));
        }
        tracing::warn!("{what}: {control} did not answer around the probe of {failing:?}; waiting for the network");
        wait_for_egress_on(host, what, &[control], hole_state)?;
    }
}

pub(crate) fn read_with_network_up_on<T>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    mut read: impl FnMut() -> T,
) -> T {
    let no_hole_state = || None;
    loop {
        let before = host.probe(control).is_ok();
        let reading = read();
        let after = host.probe(control).is_ok();
        if before && after {
            return reading;
        }
        tracing::warn!(
            "{what}: {control} did not answer around the reading; waiting for the network and reading again"
        );
        wait_for_egress_on(host, what, &[control], &no_hole_state).expect("no Hole state is ever reported here");
    }
}

pub(crate) fn rerun_until_network_holds_on<T>(
    host: &mut impl Host,
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    mut scenario: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    loop {
        match scenario() {
            Ok(value) => return Ok(value),
            Err(why) => judge_failed_run_on(host, what, control, hole_state, why)?,
        }
    }
}

pub(crate) fn judge_failed_run_on(
    host: &mut impl Host,
    what: &str,
    control: &str,
    hole_state: HoleState<'_>,
    why: String,
) -> Result<(), String> {
    if let Some(held) = hole_state() {
        return Err(format!(
            "{why}
{what}: the scenario ended with Hole still holding {held}"
        ));
    }
    if host.probe(control).is_ok() {
        return Err(why);
    }
    tracing::warn!(
        "{what}: {why}
{control} does not answer, so the network was down; running the scenario again once it does"
    );
    wait_for_egress_on(host, what, &[control], hole_state)
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod egress_tests;
