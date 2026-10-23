use std::cell::Cell;
use std::io;

use super::*;

fn assert_restored_with(
    what: &str,
    targets: &[&str],
    control: &str,
    probe: impl FnMut(&str) -> io::Result<()>,
    pause: impl FnMut(),
) {
    if let Err(why) = check_egress_restored_with(what, targets, control, probe, pause) {
        panic!("{why}");
    }
}

/// A scripted network. `down_for` probes fail whatever their target (the runner lost its network);
/// after that every probe answers, except the addresses in `blocked` (a cover that outlived its guard).
struct Net {
    down_for: Cell<u32>,
    blocked: &'static [&'static str],
}

impl Net {
    fn probe(&self, addr: &str) -> io::Result<()> {
        if self.down_for.get() > 0 {
            self.down_for.set(self.down_for.get() - 1);
            return Err(io::ErrorKind::NetworkUnreachable.into());
        }
        if self.blocked.contains(&addr) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

#[skuld::test]
fn waiting_returns_only_after_the_network_is_back() {
    let net = Net {
        down_for: Cell::new(7),
        blocked: &[],
    };
    let pauses = Cell::new(0);
    wait_for_egress_with(
        "t",
        &["1.1.1.1:443", "8.8.8.8:443"],
        |a| net.probe(a),
        || pauses.set(pauses.get() + 1),
    );
    // Each round probes both targets, so 7 failed probes span 4 rounds: 4 pauses, then a clean round.
    assert_eq!(pauses.get(), 4);
    assert_eq!(net.down_for.get(), 0);
}

#[skuld::test]
fn a_lost_network_is_waited_out_and_the_target_then_answers() {
    let net = Net {
        down_for: Cell::new(9),
        blocked: &[],
    };
    assert_restored_with("t", &["8.8.8.8:443"], "1.1.1.1:443", |a| net.probe(a), || {});
    assert_eq!(net.down_for.get(), 0, "returned before the network was back");
}

#[skuld::test]
#[should_panic(expected = "block outlived the cover")]
fn a_target_blocked_while_the_control_answers_is_a_defect() {
    let net = Net {
        down_for: Cell::new(0),
        blocked: &["8.8.8.8:443"],
    };
    assert_restored_with("t", &["8.8.8.8:443"], "1.1.1.1:443", |a| net.probe(a), || {});
}

#[skuld::test]
#[should_panic(expected = "block outlived the cover")]
fn a_block_that_outlives_a_network_loss_is_still_a_defect() {
    // The network is down for a while, then returns with the target still blocked.
    let net = Net {
        down_for: Cell::new(5),
        blocked: &["8.8.8.8:443"],
    };
    assert_restored_with("t", &["8.8.8.8:443"], "1.1.1.1:443", |a| net.probe(a), || {});
}

#[skuld::test]
fn a_reading_is_retaken_after_a_network_loss_and_kept_once_the_network_is_up() {
    // The first reading disagrees because the network is down; the retaken one agrees.
    let net = Net {
        down_for: Cell::new(3),
        blocked: &[],
    };
    let readings = Cell::new(0);
    let reading = read_until_network_agrees_with(
        "t",
        "1.1.1.1:443",
        || {
            readings.set(readings.get() + 1);
            // The resolver set is empty while the network is down.
            if net.down_for.get() > 0 {
                0
            } else {
                1
            }
        },
        |r| *r == 1,
        |a| net.probe(a),
        || {},
    );
    assert_eq!(reading, 1);
    assert_eq!(readings.get(), 2);
}

#[skuld::test]
fn a_disagreement_with_the_network_up_is_returned_as_it_is() {
    let net = Net {
        down_for: Cell::new(0),
        blocked: &[],
    };
    let reading = read_until_network_agrees_with("t", "1.1.1.1:443", || 0, |r| *r == 1, |a| net.probe(a), || {});
    assert_eq!(reading, 0);
}

#[skuld::test]
#[should_panic(expected = "block outlived the cover")]
fn every_target_must_answer_not_just_the_first() {
    let net = Net {
        down_for: Cell::new(0),
        blocked: &["1.0.0.1:853"],
    };
    assert_restored_with(
        "t",
        &["8.8.8.8:443", "1.0.0.1:853"],
        "1.1.1.1:443",
        |a| net.probe(a),
        || {},
    );
}

/// The shape the macOS resolver-set tests use: a reading is a (raw output, parsed set) pair.
#[skuld::test]
fn a_resolver_set_reading_is_retaken_after_a_network_loss() {
    let net = Net {
        down_for: Cell::new(2),
        blocked: &[],
    };
    let before = vec!["nameserver[0] : 192.168.64.1".to_string()];
    let (raw, servers) = read_until_network_agrees_with(
        "t",
        "1.1.1.1:443",
        || {
            let raw = if net.down_for.get() > 0 {
                ""
            } else {
                "nameserver[0] : 192.168.64.1"
            };
            let servers: Vec<String> = raw.lines().map(str::to_owned).collect();
            (raw.to_string(), servers)
        },
        |(_, servers)| *servers == before,
        |a| net.probe(a),
        || {},
    );
    assert_eq!(servers, before);
    assert!(raw.contains("192.168.64.1"));
}
