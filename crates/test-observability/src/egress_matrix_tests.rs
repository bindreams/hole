//! Class pin: every kind of fault placed at every step of a scripted run.
//!
//! A network outage is placed over each contiguous stretch of the run's probes (every start, every
//! length), and the verdict must never be a defect. A cover that is never released, one that leaks and
//! one that blocks its own permit are each run under the same placements, and the verdict must always
//! be a defect. Fixing one placement at a time is how a new hole appears in the last fix; the matrix
//! is what has to hold.

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
/// check that egress is back.
fn full_run(net: &Net, cover: Cover, with_second: bool) -> Result<(), String> {
    let hole = || net.cover.get().then(|| "a cover".to_string());
    let scenario = || {
        net.engage(cover.permits(with_second));
        let mut probes = InCover::new(PERMIT, "the server permit must beat block-all");
        if with_second {
            probes = probes.answers(SECOND_PERMIT, "the second permit must beat block-all");
        }
        let verdict = probes
            .blocked(BLOCK, "a non-permitted host must be blocked")
            .run_on(&mut { net });
        if cover != Cover::NeverReleased {
            net.release();
        }
        verdict
    };
    // A run that never settles panics in the scripted host: a spin fails the test, it is not a verdict.
    rerun_until_network_holds_on(&mut { net }, "t", CONTROL, &hole, scenario)?;
    check_egress_restored_on(&mut { net }, "t", &[BLOCK], CONTROL, &hole)
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

/// Placements whose verdict is `want`, other than the `residual` ones no probe can tell apart.
fn wrong_verdicts(
    cover: Cover,
    with_second: bool,
    want_ok: bool,
    residual: &[Range<u32>],
    net: impl Fn(Range<u32>) -> Net,
) -> Vec<(Range<u32>, Result<(), String>)> {
    verdicts(cover, with_second, net)
        .into_iter()
        .filter(|(down, v)| v.is_ok() != want_ok && !residual.contains(down))
        .collect()
}

/// Every outage that starts and ends inside the in-cover probes `lo..hi` of the first run. One that
/// covers an in-cover reading and has ended when the judge probes the control reads as a mixed reading
/// the control cannot excuse, so it is a defect: a rerun needs a probe outside any cover to have failed.
fn within(lo: u32, hi: u32) -> Vec<Range<u32>> {
    placements()
        .into_iter()
        .filter(|d| !d.is_empty() && d.start >= lo && d.end <= hi)
        .collect()
}

/// An outage over every in-cover probe of the first run (ticks 1..=3: permit, block, permit) that has
/// ended when the judge looks: indistinguishable from a cover that blocks its own permit.
const OVER_EVERY_IN_COVER_PROBE: Range<u32> = 1..4;
/// An outage over the block probe alone, between two answering permits: no probe sees it.
const OVER_THE_BLOCK_PROBE_ALONE: Range<u32> = 2..3;
/// An outage over the final "egress is back" probe alone, between two answering control probes.
const OVER_THE_RESTORE_PROBE_ALONE: Range<u32> = 5..6;

#[skuld::test]
fn no_outage_placement_is_charged_to_a_healthy_cover() {
    let defects = wrong_verdicts(
        Cover::Healthy,
        false,
        true,
        &[within(1, 4), vec![OVER_THE_RESTORE_PROBE_ALONE]].concat(),
        |d| Net::new(d, &[]),
    );
    assert!(defects.is_empty(), "outages read as defects: {defects:#?}");
}

#[skuld::test]
fn an_outage_over_an_in_cover_reading_that_ended_before_the_teardown_probe_is_a_defect() {
    // The permit before the block probe is missing (tick 1) and the network is back by tick 2: nothing
    // outside the cover failed, so a rerun would be a wait on no failed probe.
    let net = Net::new(1..2, &[]);
    assert!(full_run(&net, Cover::Healthy, false).is_err());
}

#[skuld::test]
fn an_outage_over_every_in_cover_probe_reads_as_a_cover_that_blocks_its_permit() {
    let net = Net::new(OVER_EVERY_IN_COVER_PROBE, &[]);
    assert!(full_run(&net, Cover::Healthy, false).is_err());
}

#[skuld::test]
fn no_outage_placement_hides_a_leaking_cover() {
    let passed = wrong_verdicts(Cover::Leaks, false, false, &[OVER_THE_BLOCK_PROBE_ALONE], |d| {
        Net::new(d, &[])
    });
    assert!(passed.is_empty(), "a leaking cover passed under outages {passed:#?}");
}

#[skuld::test]
fn an_outage_over_the_block_probe_alone_hides_a_leak_from_that_run() {
    let net = Net::new(OVER_THE_BLOCK_PROBE_ALONE, &[]);
    assert!(full_run(&net, Cover::Leaks, false).is_ok());
}

#[skuld::test]
fn a_cover_that_is_never_released_is_a_defect_under_every_placement() {
    let passed = wrong_verdicts(Cover::NeverReleased, false, false, &[], |d| Net::new(d, &[]));
    assert!(
        passed.is_empty(),
        "an unreleased cover passed under outages {passed:#?}"
    );
}

#[skuld::test]
fn a_cover_that_blocks_its_own_permit_is_a_defect_under_every_placement() {
    let passed = wrong_verdicts(Cover::BlocksItsOwnPermit, false, false, &[], |d| Net::new(d, &[]));
    assert!(
        passed.is_empty(),
        "a cover blocking its permit passed under outages {passed:#?}"
    );
}

#[skuld::test]
fn a_permitted_host_that_is_down_on_its_own_is_waited_for_not_charged_to_the_cover() {
    // The second permit is down for a stretch of ticks that covers its in-cover probe and the judge's
    // look at it; the cover permits it, so nothing is wrong with the cover. With the second permit the
    // run has five in-cover probes (ticks 1..=5) and a restore probe at tick 8.
    let mut residual = within(1, 6);
    residual.push(8..9);
    let defects = wrong_verdicts(Cover::Healthy, true, true, &residual, |d| {
        Net::new(d, &[]).with_host_down(SECOND_PERMIT, 0..40)
    });
    assert!(
        defects.is_empty(),
        "a remote host's own outage read as a defect: {defects:#?}"
    );
}

/// What a wire scenario reports for markers missing from the capture, given its permit readings.
fn wire_failure(vouch: &[bool], markers: &[bool]) -> Failure {
    Failure::captured("a marker was not captured".to_string(), CONTROL, vouch, markers)
}

/// A wire scenario: the permit is probed before the head marker and after the tail, and each marker
/// reaches the capture only while the network is up. `readings` turns what the run saw into its failure.
fn wire_run(net: &Net, readings: fn(&[bool], &[bool]) -> Failure) -> Result<(), String> {
    let hole = || net.cover.get().then(|| "a cover".to_string());
    let scenario = || {
        net.engage(&[PERMIT]);
        let vouch_before = net.reachable(PERMIT);
        let head = net.step();
        net.step(); // the leak marker: its own outcome is the capture's
        let tail = net.step();
        let vouch_after = net.reachable(PERMIT);
        net.release();
        if head && tail {
            return Ok(());
        }
        Err(readings(&[vouch_before, vouch_after], &[head, tail]))
    };
    rerun_until_network_holds_on(&mut { net }, "t", CONTROL, &hole, scenario)
}

/// The ticks of a wire run's first pass: window open 0, permit 1, head 2, leak 3, tail 4, permit 5, then
/// the judge's control probe at 6.
const WIRE_TEARDOWN_PROBE: u32 = 6;

#[skuld::test]
fn a_wire_run_with_the_control_down_at_the_teardown_is_rerun_not_charged() {
    let defects: Vec<_> = placements()
        .into_iter()
        .filter(|down| down.contains(&WIRE_TEARDOWN_PROBE))
        .filter(|down| wire_run(&Net::new(down.clone(), &[]), wire_failure).is_err())
        .collect();
    assert!(defects.is_empty(), "a wire run was charged under outages {defects:?}");
}

#[skuld::test]
fn a_wire_outage_that_ended_before_the_teardown_probe_is_the_stated_residual() {
    // The vouch before and the head are missing, the control answers at the teardown: a rerun needs a
    // probe outside any cover to have failed, so this is a defect.
    let net = Net::new(1..3, &[]);
    assert!(wire_run(&net, wire_failure).is_err());
}

#[skuld::test]
fn a_head_only_wire_drop_with_the_control_answering_is_a_defect_under_every_placement() {
    // The head is dropped whatever the network does; the permit answers on both sides.
    let passed: Vec<_> = placements()
        .into_iter()
        .filter(|down| {
            let net = Net::new(down.clone(), &[]);
            let hole = || net.cover.get().then(|| "a cover".to_string());
            let scenario = || {
                net.engage(&[PERMIT]);
                net.release();
                Err::<(), _>(wire_failure(&[true, true], &[false, true]))
            };
            rerun_until_network_holds_on(&mut { &net }, "t", CONTROL, &hole, scenario).is_ok()
        })
        .collect();
    assert!(passed.is_empty(), "a wire drop was excused under {passed:?}");
}

/// A run inside a block the oracle cannot read (a process-scoped confinement, not a cover on disk) that
/// blocks everything, the control included. The control is probed on both sides of the marker and the
/// marker never arrives; `readings` turns what the run saw into its failure.
fn confined_run(net: &Net, readings: fn(&[bool], &[bool]) -> Failure) -> Result<(), String> {
    let scenario = || {
        net.engage(&[]);
        let before = net.reachable(CONTROL);
        net.step(); // the marker: the block drops it
        let after = net.reachable(CONTROL);
        net.release();
        Err::<(), _>(readings(&[before, after], &[false]))
    };
    rerun_until_network_holds_on(&mut { net }, "t", CONTROL, &clean, scenario)
}

#[skuld::test]
fn a_block_that_also_blocks_the_control_is_a_defect_under_every_placement() {
    // The control answers once the block is released, so the miss inside it was the block's.
    let excused: Vec<_> = placements()
        .into_iter()
        .filter(|down| confined_run(&Net::new(down.clone(), &[]), wire_failure).is_ok())
        .collect();
    assert!(
        excused.is_empty(),
        "an over-blocking confinement was excused under {excused:?}"
    );
}

#[skuld::test]
#[should_panic(expected = "never settled")]
fn a_miss_inside_a_block_handed_to_uncovered_is_rerun_without_end() {
    // Why `Failure::uncovered` is for readings taken with Hole holding nothing: handed these, the same
    // run is rerun for ever.
    let _ = confined_run(&Net::new(0..0, &[]), |readings, _| {
        Failure::uncovered("a marker was not captured".to_string(), readings)
    });
}

/// A permit reading that breaks only after the cover was reloaded, with the control answering.
fn reload_run(net: &Net) -> Result<(), String> {
    let hole = || net.cover.get().then(|| "a cover".to_string());
    let scenario = || {
        net.engage(&[PERMIT]);
        let cold = net.reachable(PERMIT);
        net.release();
        Err::<(), _>(Failure::covered(
            "the permit broke after the reloads".to_string(),
            PERMIT,
            &[cold, false],
        ))
    };
    rerun_until_network_holds_on(&mut { net }, "t", CONTROL, &hole, scenario)
}

#[skuld::test]
fn a_permit_broken_by_the_reloads_with_the_control_answering_is_a_defect_under_every_placement() {
    // A spin panics inside the scripted host, so a rerun without end fails here too.
    let passed: Vec<_> = placements()
        .into_iter()
        .filter(|down| reload_run(&Net::new(down.clone(), &[])).is_ok())
        .collect();
    assert!(passed.is_empty(), "a broken permit was excused under {passed:?}");
}

#[skuld::test]
fn a_restored_target_that_is_down_on_its_own_is_waited_for_not_charged_to_the_release() {
    let net = Net::new(0..0, &[]).with_host_down(BLOCK, 0..40);
    check_egress_restored_on(&mut { &net }, "t", &[BLOCK], CONTROL, &|| None).unwrap();
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

/// An outage over the read alone, between two answering control probes: the read fails with the
/// network up on both sides, so it is the verdict.
const OVER_THE_READ_ALONE: Range<u32> = 1..2;

#[skuld::test]
fn no_outage_placement_returns_a_failed_reading() {
    let bad: Vec<_> = placements()
        .into_iter()
        .filter(|down| *down != OVER_THE_READ_ALONE)
        .filter_map(|down| {
            let net = Net::new(down.clone(), &[]);
            let got = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || gateway(&net));
            (got != Ok(7)).then_some((down, got))
        })
        .collect();
    assert!(bad.is_empty(), "a reading taken during an outage was returned: {bad:?}");
}

#[skuld::test]
fn an_outage_over_the_read_alone_is_the_verdict_on_the_read() {
    let net = Net::new(OVER_THE_READ_ALONE, &[]);
    let err = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || gateway(&net)).unwrap_err();
    assert!(err.contains("no default route"), "{err}");
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

#[skuld::test]
fn a_read_that_fails_with_the_control_answering_is_the_verdict_under_every_placement() {
    let returned: Vec<_> = placements()
        .into_iter()
        .filter_map(|down| {
            let net = Net::new(down.clone(), &[]);
            let got = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || {
                net.step();
                Err::<u32, _>("no default route")
            });
            got.is_ok().then_some(down)
        })
        .collect();
    assert!(
        returned.is_empty(),
        "a failing read was returned as a value under {returned:?}"
    );
}
