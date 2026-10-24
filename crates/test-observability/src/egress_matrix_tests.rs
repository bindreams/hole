//! Class pin: every kind of fault placed at every step of a scripted run.
//!
//! A network outage is placed over each contiguous stretch of the run's probes (every start, every
//! length), and the verdict must never be a defect. A cover that is never released, one that leaks and
//! one that blocks its own permit are each run under the same placements, and the verdict must always
//! be a defect. Fixing one placement at a time is how a new hole appears in the last fix; the matrix
//! is what has to hold.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;

/// The server permit, which is also the control host (as in the lockdown scenarios).
const PERMIT: &str = CONTROL;
/// Blocked by the cover.
const BLOCK: &str = TARGET;
/// A second permitted host, on a remote that can go down by itself.
const SECOND_PERMIT: &str = "1.0.0.1:443";

/// How the cover behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cover {
    Healthy,
    /// The scenario never releases it.
    NeverReleased,
    /// It lets the blocked host through.
    Leaks,
    /// It blocks the permit it was engaged with.
    BlocksItsOwnPermit,
}

impl Cover {
    fn permits(self, with_second: bool) -> &'static [&'static str] {
        match (self, with_second) {
            (Cover::Leaks, _) => &[PERMIT, SECOND_PERMIT, BLOCK],
            (Cover::BlocksItsOwnPermit, _) => &[],
            (_, true) => &[PERMIT, SECOND_PERMIT],
            (_, false) => &[PERMIT],
        }
    }
}

/// Every outage that is one contiguous stretch of ticks inside the first `SPAN` ticks, plus no outage.
fn placements() -> Vec<Range<u32>> {
    const SPAN: u32 = 9;
    let mut all: Vec<Range<u32>> = std::iter::once(0..0).collect();
    for start in 0..SPAN {
        for end in start + 1..=start + SPAN {
            all.push(start..end);
        }
    }
    all
}

/// The whole run a privileged test makes: a window around one engage-probe-release scenario, then the
/// check that egress is back. A panic inside the scenario (a leak) is a defect like an `Err`.
fn full_run(net: &Net, cover: Cover, with_second: bool) -> Result<(), String> {
    let hole = || net.cover.get().then(|| "a cover".to_string());
    let scenario = || {
        net.engage(cover.permits(with_second));
        let mut host = net;
        let permit = host.probe(PERMIT);
        let second = with_second.then(|| host.probe(SECOND_PERMIT));
        let blocked = host.probe(BLOCK);
        if cover != Cover::NeverReleased {
            net.release();
        }
        permit.map_err(|e| format!("the permit failed: {:?}", e.kind()))?;
        if let Some(Err(e)) = second {
            return Err(format!("the second permit failed: {:?}", e.kind()));
        }
        assert!(blocked.is_err(), "LEAK: the blocked host connected");
        Ok(())
    };
    let ran = catch_unwind(AssertUnwindSafe(|| {
        rerun_until_network_holds_on(&mut { net }, "t", CONTROL, &hole, scenario)
    }));
    match ran {
        Err(_) => Err("the scenario panicked".to_string()),
        Ok(Err(why)) => Err(why),
        Ok(Ok(())) => check_egress_restored_on(&mut { net }, "t", &[BLOCK], CONTROL, &hole),
    }
}

fn verdicts(cover: Cover, with_second: bool, net: impl Fn(Range<u32>) -> Net) -> Vec<(Range<u32>, Result<(), String>)> {
    placements()
        .into_iter()
        .map(|down| {
            let net = net(down.clone());
            (down, full_run(&net, cover, with_second))
        })
        .collect()
}

#[skuld::test]
fn no_outage_placement_is_charged_to_a_healthy_cover() {
    let defects: Vec<_> = verdicts(Cover::Healthy, false, |d| Net::new(d, &[]))
        .into_iter()
        .filter(|(_, v)| v.is_err())
        .collect();
    assert!(defects.is_empty(), "outages read as defects: {defects:#?}");
}

#[skuld::test]
fn no_outage_placement_hides_a_leaking_cover() {
    let passed: Vec<_> = verdicts(Cover::Leaks, false, |d| Net::new(d, &[]))
        .into_iter()
        .filter(|(_, v)| v.is_ok())
        .map(|(d, _)| d)
        .collect();
    assert!(passed.is_empty(), "a leaking cover passed under outages {passed:?}");
}

#[skuld::test]
fn a_cover_that_is_never_released_is_a_defect_under_every_placement() {
    let passed: Vec<_> = verdicts(Cover::NeverReleased, false, |d| Net::new(d, &[]))
        .into_iter()
        .filter(|(_, v)| v.is_ok())
        .map(|(d, _)| d)
        .collect();
    assert!(passed.is_empty(), "an unreleased cover passed under outages {passed:?}");
}

#[skuld::test]
fn a_cover_that_blocks_its_own_permit_is_a_defect_under_every_placement() {
    let passed: Vec<_> = verdicts(Cover::BlocksItsOwnPermit, false, |d| Net::new(d, &[]))
        .into_iter()
        .filter(|(_, v)| v.is_ok())
        .map(|(d, _)| d)
        .collect();
    assert!(
        passed.is_empty(),
        "a cover blocking its permit passed under outages {passed:?}"
    );
}

#[skuld::test]
fn a_permitted_host_that_is_down_on_its_own_is_waited_for_not_charged_to_the_cover() {
    // The second permit is down for a stretch of ticks that covers its in-cover probe and the judge's
    // look at it; the cover permits it, so nothing is wrong with the cover.
    let defects: Vec<_> = verdicts(Cover::Healthy, true, |d| {
        Net::new(d, &[]).with_host_down(SECOND_PERMIT, 0..14)
    })
    .into_iter()
    .filter(|(_, v)| v.is_err())
    .collect();
    assert!(
        defects.is_empty(),
        "a remote host's own outage read as a defect: {defects:#?}"
    );
}

// read_with_network_up ================================================================================================

/// A read the network can fail: Err while the network is down at the tick it runs.
fn gateway(net: &Net) -> Result<u32, &'static str> {
    if net.step() {
        Ok(7)
    } else {
        Err("no default route")
    }
}

#[skuld::test]
fn no_outage_placement_returns_a_failed_reading() {
    let bad: Vec<_> = placements()
        .into_iter()
        .filter_map(|down| {
            let net = Net::new(down.clone(), &[]);
            let got = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || gateway(&net)).unwrap();
            (got != Ok(7)).then_some((down, got))
        })
        .collect();
    assert!(bad.is_empty(), "a reading taken during an outage was returned: {bad:?}");
}

#[skuld::test]
fn a_cover_blocking_the_control_fails_a_reading_under_every_placement() {
    let waited: Vec<_> = placements()
        .into_iter()
        .filter_map(|down| {
            let net = Net::new(down.clone(), &[CONTROL]);
            let got = read_with_network_up_on(&mut { &net }, "t", CONTROL, &|| Some("a cover".to_string()), || {
                gateway(&net)
            });
            got.is_ok().then_some(down)
        })
        .collect();
    assert!(
        waited.is_empty(),
        "a reading was returned over a cover under {waited:?}"
    );
}
