use super::*;

#[skuld::test]
fn all_lists_every_phase_in_teardown_order() {
    // Exhaustive match: adding a variant breaks the build here until it is
    // placed in `ALL` too.
    fn position(p: StopPhase) -> usize {
        match p {
            StopPhase::StopProxy => 0,
            StopPhase::CloseEtw => 1,
            StopPhase::ShutdownRuntime => 2,
        }
    }
    let positions: Vec<usize> = StopPhase::ALL.iter().map(|p| position(*p)).collect();
    assert_eq!(positions, vec![0, 1, 2]);
}

#[skuld::test]
fn checkpoints_strictly_increase_and_are_never_zero() {
    // SCM: checkpoint 0 means "no pending operation"; a repeated value is
    // indistinguishable from no progress.
    let cps: Vec<u32> = StopPhase::ALL.iter().map(|p| p.checkpoint()).collect();
    assert!(cps[0] >= 1, "checkpoint 0 reads as not-pending: {cps:?}");
    assert!(cps.windows(2).all(|w| w[0] < w[1]), "not strictly increasing: {cps:?}");
}

#[skuld::test]
fn every_phase_carries_a_nonzero_wait_hint() {
    for p in StopPhase::ALL {
        assert!(!p.wait_hint().is_zero(), "{p:?} has no wait hint");
    }
}

#[skuld::test]
fn enter_reports_each_phase_once_in_the_order_entered() {
    let mut seen = Vec::new();
    {
        let mut progress = StopProgress::new(|p| {
            seen.push(p);
            Ok(())
        });
        for p in StopPhase::ALL {
            progress.enter(p);
        }
    }
    assert_eq!(seen, StopPhase::ALL.to_vec());
}

#[skuld::test]
fn nothing_is_reported_until_a_phase_is_entered() {
    // Checkpoints are progress-driven: constructing the reporter emits nothing.
    let mut count = 0;
    {
        let _progress = StopProgress::new(|_| {
            count += 1;
            Ok(())
        });
    }
    assert_eq!(count, 0);
}

#[skuld::test]
fn a_failed_report_does_not_stop_teardown_or_later_reports() {
    let mut attempts = Vec::new();
    {
        let mut progress = StopProgress::new(|p| {
            attempts.push(p);
            if p == StopPhase::StopProxy {
                Err(std::io::Error::other("SCM refused"))
            } else {
                Ok(())
            }
        });
        for p in StopPhase::ALL {
            progress.enter(p);
        }
    }
    assert_eq!(attempts, StopPhase::ALL.to_vec());
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "out of order")]
fn entering_an_earlier_phase_than_the_last_is_rejected() {
    let mut progress = StopProgress::new(|_| Ok(()));
    progress.enter(StopPhase::CloseEtw);
    progress.enter(StopPhase::StopProxy);
}
