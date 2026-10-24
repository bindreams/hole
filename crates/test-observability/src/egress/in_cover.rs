//! What a scenario that probes while a cover is engaged reports to the judge.
//!
//! A cover blocks every host but its own permits, so nothing outside it can be probed from inside. The
//! scenario vouches for the network itself: it probes a host the cover permits immediately before and
//! after each probe whose result it reports, in the same engage, and hands the readings to the judge as
//! a [`Failure`].

use std::io;

use super::{Host, System};

/// A run that did not hold, and what the in-cover readings say about why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// A defect no network loss explains: a probe got through the block.
    Defect(String),
    /// A probe outside any cover failed, so the network wavered inside the run. The run says nothing
    /// about the cover; run it again once the network answers. Only readings of a host nothing
    /// blocks produce it: a miss inside a cover is [`Failure::Failed`], since a rerun needs a failed
    /// probe outside any cover or a defect that shows only sometimes would be rerun without end.
    Wavered(String),
    /// `targets` failed with the permit answering on both sides of each (or the permit itself never
    /// answered). The judge probes them outside the cover: a target that is down there is waited for,
    /// one that answers is a defect. No `targets`: the control alone decides.
    Failed { why: String, targets: Vec<String> },
    /// The scenario has no host to vouch with (a cover that permits nothing off the box). The control
    /// outside the run is the only evidence, so an outage that starts and ends inside the run reads as
    /// a defect.
    Unvouched(String),
}

impl Failure {
    /// A run whose permit readings were taken in order across cover changes (reloads), after the
    /// cold engage's permit answered: a later miss may be a permit Hole broke, so it is no evidence of
    /// an outage and the control around the teardown decides (`Failed`, no targets).
    pub fn covered(why: String) -> Failure {
        Failure::Failed {
            why,
            targets: Vec::new(),
        }
    }

    /// A run whose markers were read from a local capture of the NIC, with `vouch` the readings of a
    /// permitted host probed over TCP on both sides of the markers in the same engage. A missing
    /// marker is `Failed` whatever the vouch said (whether a datagram leaves the NIC does not depend
    /// on the network upstream), and the control around the teardown decides. `outside` is the target
    /// the judge probes when nothing in the engage answered: neither a vouch reading nor a marker.
    pub fn captured(why: String, outside: &str, vouch: &[bool], markers: &[bool]) -> Failure {
        let targets = if vouch.iter().chain(markers).any(|a| *a) {
            Vec::new()
        } else {
            vec![outside.to_string()]
        };
        Failure::Failed { why, targets }
    }

    /// Readings taken while Hole holds no block at all, cover or confinement (the oracle reads covers
    /// only): a failed one is the network's, so the run is rerun. Handed a reading from inside a
    /// block, a defect that blocks the control is rerun without end; use [`Failure::captured`].
    pub fn uncovered(why: String, readings: &[bool]) -> Failure {
        if readings.iter().all(|a| *a) {
            Failure::Failed {
                why,
                targets: Vec::new(),
            }
        } else {
            Failure::Wavered(why)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Answers,
    Blocked,
}

struct Claim<'a> {
    target: &'a str,
    expect: Expect,
    claim: &'a str,
}

/// Probes made inside one engage, each bracketed by the permit: permit, claim 1, permit, claim 2,
/// permit, and so on, so every claim has a reading on both sides.
///
/// * a target expected blocked that answers is a [`Failure::Defect`], whatever the network did;
/// * a failed target with the permit answering on both sides is [`Failure::Failed`] with that target;
///   with a side missing it is [`Failure::Failed`] with no target, so the control around the teardown
///   decides, and a target expected blocked that failed with a side missing proves nothing about the
///   block;
/// * no reading of the permit answered: the permit itself failed ([`Failure::Failed`] with the permit as
///   target).
///
/// No reading can tell an outage that covers an in-cover reading and ends before the teardown probe
/// from a cover that breaks its permit, so it is a defect.
pub struct InCover<'a> {
    permit: &'a str,
    permit_claim: &'a str,
    claims: Vec<Claim<'a>>,
}

impl<'a> InCover<'a> {
    /// `permit` is the host the cover permits; `permit_claim` states why it must answer.
    pub fn new(permit: &'a str, permit_claim: &'a str) -> Self {
        InCover {
            permit,
            permit_claim,
            claims: Vec::new(),
        }
    }

    /// `target` must answer (another permit).
    pub fn answers(mut self, target: &'a str, claim: &'a str) -> Self {
        self.claims.push(Claim {
            target,
            expect: Expect::Answers,
            claim,
        });
        self
    }

    /// `target` must be blocked.
    pub fn blocked(mut self, target: &'a str, claim: &'a str) -> Self {
        self.claims.push(Claim {
            target,
            expect: Expect::Blocked,
            claim,
        });
        self
    }

    /// Make the probes and judge the readings.
    pub fn run(self) -> Result<(), Failure> {
        self.run_on(&mut System)
    }

    pub(crate) fn run_on(self, host: &mut impl Host) -> Result<(), Failure> {
        let mut permit = vec![host.probe(self.permit)];
        let mut results = Vec::with_capacity(self.claims.len());
        for claim in &self.claims {
            results.push(host.probe(claim.target));
            permit.push(host.probe(self.permit));
        }
        self.judge(&permit, &results)
    }

    fn judge(&self, permit: &[io::Result<()>], results: &[io::Result<()>]) -> Result<(), Failure> {
        let answered: Vec<bool> = permit.iter().map(|r| r.is_ok()).collect();
        let readings = readings_text(self.permit, &answered);
        let vouched = |i: usize| answered[i] && answered[i + 1];

        let leaks: Vec<String> = self
            .claims
            .iter()
            .zip(results)
            .filter(|(c, r)| c.expect == Expect::Blocked && r.is_ok())
            .map(|(c, _)| format!("{}: {} connected ({readings})", c.claim, c.target))
            .collect();
        if !leaks.is_empty() {
            return Err(Failure::Defect(leaks.join("\n")));
        }

        let failed: Vec<(&Claim, &io::Error)> = self
            .claims
            .iter()
            .zip(results)
            .enumerate()
            .filter_map(|(i, (c, r))| match r {
                Err(e) if c.expect == Expect::Answers && vouched(i) => Some((c, e)),
                _ => None,
            })
            .collect();
        if !failed.is_empty() {
            let why = failed
                .iter()
                .map(|(c, e)| format!("{}: {}={:?} ({readings})", c.claim, c.target, e.kind()))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = failed.iter().map(|(c, _)| c.target.to_string()).collect();
            return Err(Failure::Failed { why, targets });
        }

        // Residual: an outage over every in-cover probe, ended by teardown, reads the same.
        if !answered.iter().any(|a| *a) {
            return Err(Failure::Failed {
                why: format!("{}: {readings}", self.permit_claim),
                targets: vec![self.permit.to_string()],
            });
        }

        let unproven: Vec<String> = self
            .claims
            .iter()
            .zip(results)
            .enumerate()
            .filter(|(i, (_, r))| r.is_err() && !vouched(*i))
            .map(|(_, (c, _))| format!("{}: {} failed", c.claim, c.target))
            .collect();
        if !unproven.is_empty() {
            return Err(Failure::Failed {
                why: format!("{} ({readings})", unproven.join("; ")),
                targets: Vec::new(),
            });
        }
        Ok(())
    }
}

fn readings_text(permit: &str, answered: &[bool]) -> String {
    let shown: Vec<&str> = answered
        .iter()
        .map(|a| if *a { "answered" } else { "FAILED" })
        .collect();
    format!("permit {permit}: {}", shown.join(", "))
}
