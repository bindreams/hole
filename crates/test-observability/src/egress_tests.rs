use std::cell::{Cell, RefCell};
use std::io;
use std::ops::Range;

use super::*;

const CONTROL: &str = "1.1.1.1:443";
const TARGET: &str = "8.8.8.8:443";

/// A scripted network on a clock that ticks once per probe or reading, so a test can place an outage
/// at an exact position in the sequence of operations. Probes inside `down` fail whatever their
/// target (the runner lost its network); outside it every probe answers, except the addresses in
/// `blocked` (a cover that outlived its guard).
struct Net {
    tick: Cell<u32>,
    down: Range<u32>,
    blocked: &'static [&'static str],
    /// A cover engaged on this host: while `cover` is set, only the addresses in `permits` answer.
    cover: Cell<bool>,
    permits: Cell<&'static [&'static str]>,
    /// One remote host down for a stretch of ticks, whatever else the network is doing.
    host_down: Option<(&'static str, Range<u32>)>,
    probed: RefCell<Vec<String>>,
    /// Whether each probe in `probed` answered, in the same order.
    answered: RefCell<Vec<bool>>,
    dumps: Cell<u32>,
    pauses: Cell<u32>,
}

impl Net {
    fn new(down: Range<u32>, blocked: &'static [&'static str]) -> Self {
        Net {
            tick: Cell::new(0),
            down,
            blocked,
            cover: Cell::new(false),
            permits: Cell::new(&[]),
            host_down: None,
            probed: RefCell::new(Vec::new()),
            answered: RefCell::new(Vec::new()),
            dumps: Cell::new(0),
            pauses: Cell::new(0),
        }
    }

    /// Advance the clock and say whether the network is up at the tick that just ran.
    fn step(&self) -> bool {
        let t = self.tick.get();
        // A harness bound, not a product one: a verdict that never settles is a failed test, not a hang.
        assert!(t < 100_000, "the scripted run never settled (a spin)");
        self.tick.set(t + 1);
        !self.down.contains(&t)
    }

    fn engage(&self, permits: &'static [&'static str]) {
        self.permits.set(permits);
        self.cover.set(true);
    }

    fn release(&self) {
        self.cover.set(false);
    }

    fn with_host_down(mut self, addr: &'static str, ticks: Range<u32>) -> Self {
        self.host_down = Some((addr, ticks));
        self
    }

    fn probes_of(&self, addr: &str) -> usize {
        self.probed.borrow().iter().filter(|a| *a == addr).count()
    }
}

impl Host for &Net {
    fn probe(&mut self, addr: &str) -> io::Result<()> {
        self.probed.borrow_mut().push(addr.to_string());
        let tick = self.tick.get();
        let up = self.step();
        let host_down = self
            .host_down
            .as_ref()
            .is_some_and(|(a, r)| *a == addr && r.contains(&tick));
        let covered = self.cover.get() && !self.permits.get().contains(&addr);
        let result = if !up {
            Err(io::ErrorKind::NetworkUnreachable.into())
        } else if host_down || covered || self.blocked.contains(&addr) {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        };
        self.answered.borrow_mut().push(result.is_ok());
        result
    }

    fn pause(&mut self) {
        self.pauses.set(self.pauses.get() + 1);
    }

    fn dump(&mut self, _what: &str) {
        self.dumps.set(self.dumps.get() + 1);
    }
}

fn clean() -> Option<String> {
    None
}

fn wait(net: &Net, targets: &[&str], hole: HoleState<'_>) -> Result<(), String> {
    wait_for_egress_on(&mut { net }, "t", targets, hole)
}

fn check(net: &Net, targets: &[&str], hole: HoleState<'_>) -> Result<(), String> {
    check_egress_restored_on(&mut { net }, "t", targets, CONTROL, hole)
}

// wait_for_egress =====================================================================================================

#[skuld::test]
fn waiting_returns_only_after_the_network_is_back() {
    let net = Net::new(0..7, &[]);
    wait(&net, &["1.1.1.1:443", TARGET], &clean).unwrap();
    // Each round probes both targets, so 7 failed probes span 4 rounds: 4 pauses, then a clean round.
    assert_eq!(net.pauses.get(), 4);
    assert!(net.tick.get() >= 7, "returned before the network was back");
}

#[skuld::test]
fn the_os_is_dumped_once_however_long_the_wait() {
    let net = Net::new(0..9, &[]);
    wait(&net, &[TARGET], &clean).unwrap();
    assert_eq!(net.dumps.get(), 1);
}

#[skuld::test]
fn nothing_is_dumped_when_the_network_never_failed() {
    let net = Net::new(0..0, &[]);
    wait(&net, &[TARGET], &clean).unwrap();
    assert_eq!(net.dumps.get(), 0);
}

#[skuld::test]
fn an_unreachable_target_with_hole_state_installed_fails_at_once() {
    // A cover left behind by an earlier test: waiting for the network would wait forever.
    let net = Net::new(0..0, &[TARGET]);
    let err = wait(&net, &[TARGET], &|| Some("a lockdown cover".to_string())).unwrap_err();
    assert!(err.contains("a lockdown cover"), "{err}");
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn hole_state_is_consulted_again_every_round() {
    // The oracle answers "nothing" for the first round and "a cover" afterwards.
    let net = Net::new(0..100, &[]);
    let asked = Cell::new(0);
    let err = wait(&net, &[TARGET], &|| {
        asked.set(asked.get() + 1);
        (asked.get() > 1).then(|| "a cover".to_string())
    })
    .unwrap_err();
    assert!(err.contains("a cover"), "{err}");
    assert_eq!(net.pauses.get(), 1);
}

// check_egress_restored ===============================================================================================

#[skuld::test]
fn a_lost_network_is_waited_out_and_the_target_then_answers() {
    let net = Net::new(0..9, &[]);
    check(&net, &[TARGET], &clean).unwrap();
    assert!(net.tick.get() >= 9, "returned before the network was back");
}

#[skuld::test]
fn a_target_blocked_while_the_control_answers_is_a_defect() {
    let net = Net::new(0..0, &[TARGET]);
    let err = check(&net, &[TARGET], &clean).unwrap_err();
    assert!(err.contains("unreachable"), "{err}");
}

#[skuld::test]
fn a_blocked_target_is_probed_once_not_twice() {
    // The assertion is immediate: a release that returns before egress is restored must not pass on a
    // second probe taken seconds later.
    let net = Net::new(0..0, &[TARGET]);
    let _ = check(&net, &[TARGET], &clean);
    assert_eq!(net.probes_of(TARGET), 1);
}

#[skuld::test]
fn a_block_that_outlives_a_network_loss_is_still_a_defect() {
    let net = Net::new(0..5, &[TARGET]);
    let err = check(&net, &[TARGET], &clean).unwrap_err();
    assert!(err.contains("unreachable"), "{err}");
}

#[skuld::test]
fn a_cover_left_behind_fails_at_once_even_though_the_control_fails_too() {
    // A partial release: the control's own permit is gone with the rest, so both fail. Without the
    // oracle that reads as a lost network and waits forever.
    let net = Net::new(0..u32::MAX, &[]);
    let err = check(&net, &[TARGET], &|| Some("the lockdown block-all".to_string())).unwrap_err();
    assert!(err.contains("the lockdown block-all"), "{err}");
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn an_outage_that_ends_right_after_the_target_failed_is_not_a_defect() {
    // control fails (tick 0), target fails (tick 1), control answers (tick 2): the control answering
    // afterwards says nothing about the network when the target was probed.
    let net = Net::new(0..2, &[]);
    check(&net, &[TARGET], &clean).unwrap();
}

#[skuld::test]
fn the_log_blames_the_environment_only_when_hole_holds_nothing() {
    // Hole holds nothing while the network is down: the wait is the environment's.
    let net = Net::new(0..4, &[]);
    check(&net, &[TARGET], &clean).unwrap();
    assert_eq!(net.dumps.get(), 1);
}

#[skuld::test]
fn every_target_must_answer_not_just_the_first() {
    let net = Net::new(0..0, &["1.0.0.1:853"]);
    let err = check(&net, &["8.8.8.8:443", "1.0.0.1:853"], &clean).unwrap_err();
    assert!(err.contains("1.0.0.1:853"), "{err}");
}

// read_with_network_up ================================================================================================

#[skuld::test]
fn a_reading_taken_as_the_network_returns_is_retaken() {
    // The outage covers the first operation only. A read followed by one control probe (the old shape)
    // read during the outage, probed after it, and kept the degraded reading. With the control probed
    // first, the outage is seen and the reading is taken again, whatever the first one said.
    let net = Net::new(0..1, &[]);
    let readings = Cell::new(0);
    let reading = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || {
        readings.set(readings.get() + 1);
        if net.step() {
            1
        } else {
            0
        }
    })
    .unwrap();
    assert_eq!(reading, 1);
    assert_eq!(readings.get(), 2);
}

#[skuld::test]
fn a_reading_taken_during_an_outage_is_retaken() {
    let net = Net::new(1..6, &[]);
    let readings = Cell::new(0);
    let reading = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || {
        readings.set(readings.get() + 1);
        if net.step() {
            1
        } else {
            0
        }
    })
    .unwrap();
    assert_eq!(reading, 1);
    assert!(readings.get() >= 2);
}

#[skuld::test]
fn a_reading_with_the_network_up_on_both_sides_is_returned_as_it_is() {
    // A disagreement the network cannot explain is the caller's to assert on.
    let net = Net::new(0..0, &[]);
    let reading = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || {
        net.step();
        0
    })
    .unwrap();
    assert_eq!(reading, 0);
}

#[skuld::test]
fn a_resolver_set_reading_is_retaken_after_a_network_loss() {
    // The shape the macOS resolver-set tests use: a reading is a (raw output, parsed set) pair.
    let net = Net::new(1..4, &[]);
    let (raw, servers) = read_with_network_up_on(&mut { &net }, "t", CONTROL, &clean, || {
        let raw = if net.step() { "nameserver[0] : 192.168.64.1" } else { "" };
        let servers: Vec<String> = raw.lines().map(str::to_owned).collect();
        (raw.to_string(), servers)
    })
    .unwrap();
    assert_eq!(servers, vec!["nameserver[0] : 192.168.64.1".to_string()]);
    assert!(raw.contains("192.168.64.1"));
}

#[skuld::test]
fn a_reading_taken_while_hole_holds_a_cover_and_the_control_is_down_fails_at_once() {
    // A cover left by an earlier test blocks the control, so waiting for the network would never end.
    let net = Net::new(0..0, &[CONTROL]);
    let err = read_with_network_up_on(
        &mut { &net },
        "t",
        CONTROL,
        &|| Some("a lockdown cover".to_string()),
        || 1,
    )
    .unwrap_err();
    assert!(err.contains("a lockdown cover"), "{err}");
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn a_cover_found_while_waiting_out_a_network_loss_fails_the_reading() {
    // The control drops out around the first reading; the cover is only seen on a later round.
    let net = Net::new(1..6, &[]);
    let polls = Cell::new(0);
    let hole = || {
        polls.set(polls.get() + 1);
        (polls.get() >= 2).then(|| "a transient cover".to_string())
    };
    let err = read_with_network_up_on(&mut { &net }, "t", CONTROL, &hole, || 1).unwrap_err();
    assert!(err.contains("a transient cover"), "{err}");
    assert_eq!(net.pauses.get(), 1);
}

// rerun_until_network_holds ===========================================================================================

fn scenario_result<T>(
    net: &Net,
    hole: HoleState<'_>,
    scenario: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    rerun_until_network_holds_on(&mut { net }, "t", CONTROL, hole, scenario)
}

#[skuld::test]
fn a_scenario_that_failed_while_the_network_was_down_is_rerun_until_it_holds() {
    // The control answers at open (tick 0); the outage then covers the in-cover probe and the judge.
    let net = Net::new(1..6, &[]);
    let runs = Cell::new(0);
    let out = scenario_result(&net, &clean, || {
        runs.set(runs.get() + 1);
        // The in-cover probe fails exactly while the network is down.
        if net.step() {
            Ok("held")
        } else {
            Err("the permit probe failed".to_string())
        }
    })
    .unwrap();
    assert_eq!(out, "held");
    assert_eq!(runs.get(), 2);
}

#[skuld::test]
fn a_scenario_that_left_a_cover_behind_is_a_defect_even_with_the_network_down() {
    let cover = Cell::new(false);
    let net = Net::new(1..u32::MAX, &[]);
    let err = scenario_result(
        &net,
        &|| cover.get().then(|| "the transient cover".to_string()),
        || -> Result<(), String> {
            cover.set(true);
            Err("the permit probe failed".to_string())
        },
    )
    .unwrap_err();
    assert!(err.contains("the permit probe failed"), "{err}");
    assert!(err.contains("the transient cover"), "{err}");
}

// Window ==============================================================================================================

fn open<'a>(net: &Net, hole: HoleState<'a>) -> Result<Window<'a>, String> {
    open_window_on(&mut { net }, "t", CONTROL, hole)
}

fn judge(net: &Net, window: Window<'_>, why: &str) -> Result<(), String> {
    judge_on(&mut { net }, window, why.to_string())
}

#[skuld::test]
fn a_window_opens_only_once_the_control_answers() {
    let net = Net::new(0..2, &[]);
    open(&net, &clean).unwrap();
    assert_eq!(net.probes_of(CONTROL), 3);
}

#[skuld::test]
fn a_window_does_not_open_while_hole_holds_a_cover_and_the_control_fails() {
    let net = Net::new(0..u32::MAX, &[]);
    let err = open(&net, &|| Some("a leaked cover".to_string()))
        .err()
        .expect("opened over a cover");
    assert!(err.contains("a leaked cover"), "{err}");
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn a_window_does_not_open_over_a_cover_the_control_can_still_reach_through() {
    // The control answers but Hole still holds a cover: the run would start from a dirty host.
    let net = Net::new(0..0, &[]);
    let err = open(&net, &|| Some("a leaked cover".to_string()))
        .err()
        .expect("opened over a cover");
    assert!(err.contains("a leaked cover"), "{err}");
}

#[skuld::test]
fn a_failed_run_with_the_control_answering_on_both_sides_is_a_defect() {
    let net = Net::new(0..0, &[]);
    let window = open(&net, &clean).unwrap();
    let err = judge(&net, window, "the permit probe failed").unwrap_err();
    assert!(err.contains("the permit probe failed"), "{err}");
    assert!(err.contains("before and after"), "{err}");
}

#[skuld::test]
fn a_failed_run_with_the_control_down_afterwards_is_excused_and_waited_out() {
    // tick 0: control answers at open; tick 1..4: down at judge; the wait probes the control until it answers.
    let net = Net::new(1..4, &[]);
    let window = open(&net, &clean).unwrap();
    judge(&net, window, "the permit probe failed").unwrap();
    assert_eq!(*net.answered.borrow(), [true, false, false, false, true]);
    assert!(net.probed.borrow().iter().all(|a| a == CONTROL));
}

#[skuld::test]
fn a_failed_run_that_left_a_cover_is_a_defect_with_the_control_down() {
    // The oracle reports nothing at open and a cover after the run: waiting for the control would wait forever.
    let cover = Cell::new(false);
    let hole = || cover.get().then(|| "the transient cover".to_string());
    let net = Net::new(1..u32::MAX, &[]);
    let window = open(&net, &hole).unwrap();
    cover.set(true);
    let err = judge(&net, window, "the permit probe failed").unwrap_err();
    assert!(err.contains("the permit probe failed"), "{err}");
    assert!(err.contains("the transient cover"), "{err}");
    assert_eq!(
        net.probes_of(CONTROL),
        1,
        "the control was waited on after a cover was found"
    );
    assert_eq!(net.pauses.get(), 0);
}

#[skuld::test]
fn an_outage_before_the_window_is_not_charged_to_the_run() {
    // The control is down at open and answers by the time the scenario starts.
    let net = Net::new(0..3, &[]);
    let window = open(&net, &clean).unwrap();
    let started = net.tick.get();
    assert!(started >= 3, "the window opened inside the outage");
    let err = judge(&net, window, "the permit probe failed").unwrap_err();
    assert!(err.contains("before and after"), "{err}");
}

#[skuld::test]
fn every_rerun_is_preceded_by_a_control_probe_that_answered() {
    // Run 1 fails with the control down at judge (ticks 1..4); run 2 holds.
    let net = Net::new(1..4, &[]);
    let starts = RefCell::new(Vec::new());
    let out = scenario_result(&net, &clean, || {
        starts.borrow_mut().push((net.probed.borrow().len(), net.tick.get()));
        if starts.borrow().len() == 1 {
            Err("the permit probe failed".to_string())
        } else {
            Ok("held")
        }
    })
    .unwrap();
    assert_eq!(out, "held");
    let starts = starts.into_inner();
    assert_eq!(starts.len(), 2, "the scenario must be rerun exactly once");
    let (probes_at_rerun, tick_at_rerun) = starts[1];
    assert!(tick_at_rerun >= 4, "the rerun started inside the outage");
    assert!(
        net.answered.borrow()[probes_at_rerun - 1],
        "the last probe before the rerun did not answer"
    );
    assert_eq!(net.probed.borrow()[probes_at_rerun - 1], CONTROL);
}

#[skuld::test]
fn a_scenario_that_fails_with_the_control_answering_on_both_sides_is_not_rerun() {
    let net = Net::new(0..0, &[]);
    let runs = Cell::new(0);
    let err = scenario_result(&net, &clean, || -> Result<(), String> {
        runs.set(runs.get() + 1);
        Err("the permit probe failed".to_string())
    })
    .unwrap_err();
    assert!(err.contains("the permit probe failed"), "{err}");
    assert!(err.contains("before and after"), "{err}");
    assert_eq!(runs.get(), 1);
}

// connect_when_reachable ==============================================================================================

#[skuld::test]
fn a_connection_lost_between_the_wait_and_the_connect_is_opened_on_the_next_round() {
    // tick 0: the wait's probe answers; tick 1: the connect lands in an outage; then the network is back.
    let net = Net::new(1..2, &[]);
    let opened = connect_when_reachable_on(&mut { &net }, "t", TARGET, &clean, |_| {
        if net.step() {
            Ok("held")
        } else {
            Err(io::ErrorKind::NetworkUnreachable.into())
        }
    })
    .unwrap();
    assert_eq!(opened, "held");
}

#[skuld::test]
fn a_connection_is_not_awaited_while_hole_holds_a_cover() {
    let net = Net::new(0..0, &[TARGET]);
    let err = connect_when_reachable_on(&mut { &net }, "t", TARGET, &|| Some("a cover".to_string()), |_| {
        Ok::<(), io::Error>(())
    })
    .unwrap_err();
    assert!(err.contains("a cover"), "{err}");
}

#[path = "egress_matrix_tests.rs"]
mod matrix;
