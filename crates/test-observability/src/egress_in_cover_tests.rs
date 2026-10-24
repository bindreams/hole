//! `InCover`, `Failure` and the judge's reading of them, on a scripted host.

use super::*;

const PERMIT: &str = CONTROL;
const SECOND: &str = "1.0.0.1:443";
const BLOCK: &str = TARGET;

fn run(net: &Net, probes: InCover<'_>) -> Result<(), Failure> {
    net.engage(&[PERMIT, SECOND]);
    probes.run_on(&mut { net })
}

fn standard<'a>() -> InCover<'a> {
    InCover::new(PERMIT, "the server permit must beat block-all").blocked(BLOCK, "a non-permitted host must be blocked")
}

// InCover =============================================================================================================

#[skuld::test]
fn a_permit_brackets_every_claim() {
    let net = Net::new(0..0, &[]);
    run(
        &net,
        standard()
            .answers(SECOND, "the resolver permit")
            .blocked(BLOCK, "again"),
    )
    .unwrap();
    assert_eq!(
        *net.probed.borrow(),
        [PERMIT, BLOCK, PERMIT, SECOND, PERMIT, BLOCK, PERMIT]
    );
}

#[skuld::test]
fn a_blocked_target_that_connects_is_a_defect_whatever_the_network_did() {
    // The permit fails on both sides of the block probe (an outage), yet the probe got through.
    let net = Net::new(0..0, &[]);
    net.engage(&[BLOCK]);
    let failure = standard().run_on(&mut { &net }).unwrap_err();
    let Failure::Defect(why) = failure else {
        panic!("not a defect: {failure:?}")
    };
    assert!(why.contains(BLOCK) && why.contains("connected"), "{why}");
}

#[skuld::test]
fn a_blocked_target_that_failed_with_the_permit_answering_on_both_sides_is_blocked() {
    let net = Net::new(0..0, &[]);
    run(&net, standard()).unwrap();
}

#[skuld::test]
fn a_blocked_target_that_failed_beside_a_failed_permit_proves_nothing() {
    // permit (tick 0), block probe (tick 1), permit (tick 2): an outage over the block probe and
    // either permit leaves it unvouched.
    for outage in [0..2, 1..3] {
        let net = Net::new(outage.clone(), &[]);
        let failure = run(&net, standard()).unwrap_err();
        assert!(matches!(failure, Failure::Wavered(_)), "{outage:?}: {failure:?}");
    }
}

#[skuld::test]
fn a_target_that_must_answer_and_failed_with_the_permit_on_both_sides_is_a_failure_to_probe_outside() {
    let net = Net::new(0..0, &[]);
    net.engage(&[PERMIT]);
    let failure = InCover::new(PERMIT, "the permit")
        .answers(SECOND, "the resolver permit")
        .run_on(&mut { &net })
        .unwrap_err();
    let Failure::Failed { why, targets } = failure else {
        panic!("not Failed: {failure:?}")
    };
    assert_eq!(targets, [SECOND]);
    assert!(why.contains("the resolver permit") && why.contains(SECOND), "{why}");
}

#[skuld::test]
fn a_target_that_must_answer_and_failed_beside_a_failed_permit_is_a_wavering() {
    for outage in [0..2, 1..3] {
        let net = Net::new(outage.clone(), &[]);
        let failure = run(
            &net,
            InCover::new(PERMIT, "the permit").answers(SECOND, "the resolver permit"),
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::Wavered(_)), "{outage:?}: {failure:?}");
    }
}

#[skuld::test]
fn a_permit_that_never_answers_is_the_failure_and_the_permit_is_the_target() {
    let net = Net::new(0..0, &[]);
    net.engage(&[]);
    let failure = standard().run_on(&mut { &net }).unwrap_err();
    let Failure::Failed { targets, .. } = failure else {
        panic!("not Failed: {failure:?}")
    };
    assert_eq!(targets, [PERMIT]);
}

#[skuld::test]
fn an_outage_over_one_probe_between_two_answering_permits_is_not_seen() {
    // The residual: the permit answers at ticks 0 and 2, so the block probe at tick 1 reads as blocked.
    let net = Net::new(1..2, &[]);
    run(&net, standard()).unwrap();
}

// Failure::covered / uncovered ========================================================================================

#[skuld::test]
fn covered_readings_decide_between_failed_and_wavered() {
    let why = || "x".to_string();
    assert_eq!(
        Failure::covered(why(), CONTROL, &[true, true]),
        Failure::Failed {
            why: why(),
            targets: vec![]
        }
    );
    assert_eq!(
        Failure::covered(why(), CONTROL, &[true, false]),
        Failure::Wavered(why())
    );
    assert_eq!(
        Failure::covered(why(), CONTROL, &[false, true]),
        Failure::Wavered(why())
    );
    assert_eq!(
        Failure::covered(why(), CONTROL, &[false, false]),
        Failure::Failed {
            why: why(),
            targets: vec![CONTROL.to_string()]
        }
    );
}

#[skuld::test]
fn uncovered_readings_excuse_any_miss() {
    let why = || "x".to_string();
    assert_eq!(
        Failure::uncovered(why(), &[true, true]),
        Failure::Failed {
            why: why(),
            targets: vec![]
        }
    );
    for readings in [[true, false], [false, true], [false, false]] {
        assert_eq!(
            Failure::uncovered(why(), &readings),
            Failure::Wavered(why()),
            "{readings:?}"
        );
    }
}

// Window::judge on each Failure =======================================================================================

fn judged(net: &Net, hole: HoleState<'_>, failure: Failure) -> Result<(), String> {
    let window = open_window_on(&mut { net }, "t", CONTROL, hole).unwrap();
    judge_on(&mut { net }, window, failure)
}

#[skuld::test]
fn a_defect_is_a_defect_with_the_control_down() {
    let net = Net::new(1..u32::MAX, &[]);
    let err = judged(&net, &clean, Failure::Defect("leaked".into())).unwrap_err();
    assert!(err.contains("leaked"), "{err}");
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn a_wavering_is_waited_out_and_never_a_defect() {
    let net = Net::new(1..4, &[]);
    judged(&net, &clean, Failure::Wavered("wavered".into())).unwrap();
}

#[skuld::test]
fn a_wavering_over_a_cover_that_was_left_behind_is_a_defect() {
    let net = Net::new(1..u32::MAX, &[]);
    let cover = Cell::new(false);
    let hole = || cover.get().then(|| "the lockdown cover".to_string());
    let window = open_window_on(&mut { &net }, "t", CONTROL, &hole).unwrap();
    cover.set(true);
    let err = judge_on(&mut { &net }, window, Failure::Wavered("wavered".into())).unwrap_err();
    assert!(err.contains("the lockdown cover"), "{err}");
}

#[skuld::test]
fn a_failed_target_is_probed_outside_with_the_control_on_both_sides() {
    let net = Net::new(0..0, &[]);
    let err = judged(
        &net,
        &clean,
        Failure::Failed {
            why: "no".into(),
            targets: vec![SECOND_TARGET.into()],
        },
    )
    .unwrap_err();
    assert!(err.contains("no") && err.contains(SECOND_TARGET), "{err}");
    // open, then control, target, control
    assert_eq!(*net.probed.borrow(), [CONTROL, CONTROL, SECOND_TARGET, CONTROL]);
}

const SECOND_TARGET: &str = "1.0.0.1:443";

#[skuld::test]
fn a_failed_target_that_is_down_outside_the_cover_is_waited_for() {
    // The target is down for its own reasons while the control answers and Hole holds nothing.
    let net = Net::new(0..0, &[]).with_host_down(SECOND_TARGET, 0..8);
    judged(
        &net,
        &clean,
        Failure::Failed {
            why: "no".into(),
            targets: vec![SECOND_TARGET.into()],
        },
    )
    .unwrap();
    assert!(net.probes_of(SECOND_TARGET) > 1);
}

#[skuld::test]
fn a_failure_with_the_control_down_around_the_teardown_is_excused() {
    let net = Net::new(1..4, &[]);
    judged(&net, &clean, failed("no")).unwrap();
}

#[skuld::test]
fn an_unvouched_failure_is_judged_by_the_control_alone() {
    let net = Net::new(0..0, &[]);
    let err = judged(&net, &clean, Failure::Unvouched("no".into())).unwrap_err();
    assert!(err.contains("no"), "{err}");
    let net = Net::new(1..4, &[]);
    judged(&net, &clean, Failure::Unvouched("no".into())).unwrap();
}

#[skuld::test]
fn the_defect_text_names_no_cover_that_may_not_exist() {
    let net = Net::new(0..0, &[]);
    let err = judged(&net, &clean, failed("no")).unwrap_err();
    assert!(!err.contains("the cover is the cause"), "{err}");
}
