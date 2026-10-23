//! Outbound-egress probes that tell a runner network loss from a product defect.
//!
//! The privileged cover tests assert on real egress: a baseline before the cover
//! engages, and "egress is back" after it lifts. A CI runner that briefly loses
//! its network fails those probes exactly as a broken cover would, so a failed
//! probe alone proves nothing about Hole.
//!
//! * [`wait_for_egress`] is for a precondition: it waits until the targets
//!   answer. No cap; the test's own nextest timeout is the bound, and each
//!   change of state is logged while it waits.
//! * [`assert_egress_restored`] is for a Hole assertion: a control host that the
//!   cover never blocked tells a lost network (wait, then re-probe) from a
//!   block that outlived the cover (fail).

use std::io;
use std::net::TcpStream;
use std::time::Duration;

/// Bound on one connect. The peer is a remote host that may never answer, so
/// expiry is a failure of that probe, not a verdict.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause between two rounds of a wait. Pacing for an external event, not a
/// synchronization: every round re-probes the real condition.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Dial `addr` (an `ip:port` literal) once.
pub fn probe(addr: &str) -> io::Result<()> {
    let sock = addr
        .parse()
        .unwrap_or_else(|e| panic!("egress target {addr:?} is not ip:port: {e}"));
    TcpStream::connect_timeout(&sock, PROBE_TIMEOUT).map(drop)
}

/// Block until every target in `targets` answers.
pub fn wait_for_egress(what: &str, targets: &[&str]) {
    wait_for_egress_with(what, targets, probe, || std::thread::sleep(POLL_INTERVAL));
}

/// Panic unless every host in `targets` answers once the network is up. See
/// [`check_egress_restored`].
#[track_caller]
pub fn assert_egress_restored(what: &str, targets: &[&str], control: &str) {
    if let Err(why) = check_egress_restored(what, targets, control) {
        panic!("{why}");
    }
}

/// Wait out a lost network and report whether every host in `targets` answers.
///
/// `control` must be a host the lifted cover never blocked. A target failing
/// while `control` fails too is a lost network: wait for `control`, then probe
/// again. A target failing twice in a row while `control` answers is the block
/// outliving the cover, returned as `Err`. For a caller that must run cleanup
/// between the measurement and the verdict.
pub fn check_egress_restored(what: &str, targets: &[&str], control: &str) -> Result<(), String> {
    check_egress_restored_with(what, targets, control, probe, || std::thread::sleep(POLL_INTERVAL))
}

/// Take `read()` until `agrees` accepts it, or until it disagrees while the network is up.
///
/// For a comparison against the runner's own state (its resolver set): the
/// network going away takes that state with it, so a disagreement read while
/// `control` fails is not evidence about Hole. It waits for `control` to answer
/// and reads again. A disagreement with `control` answering is returned for the
/// caller to assert on.
pub fn read_until_network_agrees<T>(
    what: &str,
    control: &str,
    read: impl FnMut() -> T,
    agrees: impl Fn(&T) -> bool,
) -> T {
    read_until_network_agrees_with(what, control, read, agrees, probe, || std::thread::sleep(POLL_INTERVAL))
}

pub(crate) fn read_until_network_agrees_with<T>(
    what: &str,
    control: &str,
    mut read: impl FnMut() -> T,
    agrees: impl Fn(&T) -> bool,
    mut probe: impl FnMut(&str) -> io::Result<()>,
    mut pause: impl FnMut(),
) -> T {
    loop {
        let reading = read();
        if agrees(&reading) || probe(control).is_ok() {
            return reading;
        }
        wait_for_egress_with(what, &[control], &mut probe, &mut pause);
    }
}

pub(crate) fn wait_for_egress_with(
    what: &str,
    targets: &[&str],
    mut probe: impl FnMut(&str) -> io::Result<()>,
    mut pause: impl FnMut(),
) {
    let mut last_logged: Option<Vec<(String, io::ErrorKind)>> = None;
    loop {
        let failing: Vec<(String, io::ErrorKind)> = targets
            .iter()
            .filter_map(|t| probe(t).err().map(|e| (t.to_string(), e.kind())))
            .collect();
        if failing.is_empty() {
            if last_logged.is_some() {
                tracing::info!("{what}: egress is back");
            }
            return;
        }
        if last_logged.as_ref() != Some(&failing) {
            tracing::warn!(
                "{what}: waiting for the runner's network to answer ({failing:?}); this is the environment, not Hole"
            );
            last_logged = Some(failing);
        }
        pause();
    }
}

pub(crate) fn check_egress_restored_with(
    what: &str,
    targets: &[&str],
    control: &str,
    mut probe: impl FnMut(&str) -> io::Result<()>,
    mut pause: impl FnMut(),
) -> Result<(), String> {
    let failing = |probe: &mut dyn FnMut(&str) -> io::Result<()>| -> Vec<(String, io::ErrorKind)> {
        targets
            .iter()
            .filter_map(|t| probe(t).err().map(|e| (t.to_string(), e.kind())))
            .collect()
    };
    loop {
        if failing(&mut probe).is_empty() {
            return Ok(());
        }
        if probe(control).is_err() {
            // The control host fails too: the network is down, which says nothing about the cover.
            wait_for_egress_with(what, &[control], &mut probe, &mut pause);
            continue;
        }
        // The control answers, so the first failure may have been a blip: probe once more.
        let still = failing(&mut probe);
        if still.is_empty() {
            return Ok(());
        }
        return Err(format!(
            "{what}: {still:?} stay unreachable while {control} answers, so the block outlived the cover"
        ));
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod egress_tests;
