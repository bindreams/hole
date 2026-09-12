//! Privileged-lane real-engage tests for the macOS transient cover's
//! TRANSITION behaviour (bindreams/hole#997), for its pf state purge
//! (bindreams/hole#1015), and for what a `pfctl -f -` does to loopback while it
//! loads: a second `engage()` replacing a still-live cover must never open a
//! window, an engage must not let a flow established before it survive it, and
//! no load may drop a loopback packet during the interval in which `pfctl` has
//! cleared the interface skip flags but not yet committed the new rules. All
//! engage the REAL OS cover, so they run on the elevated `tun` lane only — the `TUN` label gates them out of the unprivileged
//! `SKULD_LABELS="!tun"` pass, and `serial = TUN` + `GLOBAL_NET_STATE`
//! serialize them against every other test that mutates host network state.
//!
//! A DESCENDANT module of `platform` (mounted from `macos.rs`) rather than a
//! sibling of `lockdown_privileged_tests.rs` under `failclosed`: these tests
//! reach for `Cover`'s private `token` field and the private `pfctl` helper,
//! and Rust privacy cascades to descendant modules. Descendance is what buys
//! that access — not sharing a file with the unprivileged builder tests.

use super::*;
use std::net::IpAddr;

use crate::{GLOBAL_NET_STATE, TUN};

/// Engage a transient cover exactly like the public [`engage`], except
/// `permitted_idx` and `commit_gen` are published from INSIDE the engage path,
/// synchronously right after `pfctl -f -` returns success — the instant the new
/// ruleset actually takes effect — rather than after `engage`/`engage_with`
/// return.
///
/// That gap is real, not cosmetic: a successful load is followed by
/// `load_cover_ruleset`'s `pfctl -F states` purge (`purges_state(Transient)
/// == true`) — a second `pfctl` fork/exec/ioctl/exit — before control climbs
/// back out to the caller. On a 24-36ms transition period that is enough for a
/// whole probe attempt's window to fall inside it, so a marker published only
/// on return can be stale for that attempt's entire span, not merely racy with
/// it. Publishing at the real commit, from inside the same call that produced
/// it, removes that gap instead of describing it.
///
/// `permitted_idx` is stored BEFORE `commit_gen` is bumped, and the consumer
/// reads `commit_gen` before `permitted_idx` (see the control thread). That
/// order is what makes the generation check conservative in the safe
/// direction: an attempt can be excluded needlessly, never counted against a
/// target that changed under it.
///
/// Test-only: wraps [`RealEngageOps`] rather than reimplementing it, and leaves
/// production `engage`/`engage_with` untouched.
fn engage_publishing(
    server_ip: IpAddr,
    state_dir: &std::path::Path,
    permitted_idx: &std::sync::atomic::AtomicUsize,
    commit_gen: &std::sync::atomic::AtomicUsize,
    server_idx: usize,
) -> Result<Cover, RoutingError> {
    struct PublishOnCommit<'a> {
        inner: RealEngageOps<'a>,
        permitted_idx: &'a std::sync::atomic::AtomicUsize,
        commit_gen: &'a std::sync::atomic::AtomicUsize,
        server_idx: usize,
    }

    impl CoverRulesetOps for PublishOnCommit<'_> {
        fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
            self.inner.load_ruleset(text)?;
            // The commit `engage_publishing`'s doc comment promises: this runs
            // the instant `pfctl -f -` reports success, before the state purge
            // that follows it in `load_cover_ruleset`.
            self.permitted_idx
                .store(self.server_idx, std::sync::atomic::Ordering::SeqCst);
            // Monotonic, so two commits inside one attempt's window are
            // distinguishable from none. `permitted_idx` alone cannot say that:
            // it only ever alternates 0/1.
            self.commit_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn flush_states(&mut self) -> Result<(), RoutingError> {
            self.inner.flush_states()
        }
    }

    impl EngageOps for PublishOnCommit<'_> {
        fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
            self.inner.pf_enabled()
        }
        fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
            self.inner.enable_capture_token()
        }
        fn save_transient(&mut self, st: &state::FailClosedState) -> Result<(), RoutingError> {
            self.inner.save_transient(st)
        }
        fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
            self.inner.drop_token(token)
        }
        fn transient_restore(&mut self, token: &str) {
            self.inner.transient_restore(token)
        }
    }

    let mut ops = PublishOnCommit {
        inner: RealEngageOps { state_dir, owner: None },
        permitted_idx,
        commit_gen,
        server_idx,
    };
    let token = engage_with(server_ip, None, &mut ops)?;
    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Transient,
    })
}

/// Floor the positive control of
/// [`macos_failclosed_cover_transition_never_admits_blocked_flow`] is gated on,
/// as a percentage of EVERY control attempt (raw, unfiltered).
///
/// A bare `raw_hits > 0` certifies nothing: one success in thousands passes it.
/// And the number it would be hiding is not incidental — the control's
/// completion rate and the prober pool's per-probe chance of catching a real
/// leak are the same quantity, since both ask whether a handshake finishes
/// inside `PROBER_TIMEOUT`. A collapsed control is a collapsed guard, reported
/// green.
///
/// 25%, sited between the measurement and the cliff:
///
/// - ABOVE: both lanes measured ~97% (see LAST MEASURED on the test). A runner
///   would have to fail more than three of every four handshakes to a healthy
///   anycast host inside 20ms to breach this — a different runner, not
///   variance. Near-measurement floors are what turn ordinary runner load into
///   a red, and this repo pays for flakes.
/// - BELOW: the pool emits ~0.8 probes/ms, so a 2-3ms window sees ~2 probes and
///   24 transitions offer ~46 independent chances. At a 5% control rate the
///   chance of missing every one is already ~10%; at the ~0.08% a genuine
///   collapse produces it is ~97%. The floor sits ~5x above where the guard
///   starts failing to detect, and ~4x below where it was measured — roughly
///   the geometric mean, which is where a threshold with an order of magnitude
///   of slack on each side belongs.
const CONTROL_RATE_FLOOR_PCT: f64 = 25.0;

/// Proves a transient-cover TRANSITION — a second real `engage()` replacing a
/// still-live cover, with no intervening `disengage` — never admits a flow the
/// OLD cover was blocking. This is the scenario `-Fa` broke: `pfctl -Fa -f -`
/// is two separate kernel transactions (flush, then load), so a host between
/// them briefly runs with no pf rules at all — a pass-all window between two
/// rulesets that both block `NON_PERMITTED`. Dropping `-Fa` makes the load a
/// single `pfctl -f -`, one atomic pf transaction under the kernel's
/// DIOCADDRULE/DIOCXCOMMIT ticket discipline (see `macos.rs`'s module doc), so
/// no such window should exist.
///
/// TWO DIFFERENT ASSERTIONS, and the difference is structural. Do NOT unify
/// them — the strict one is deliberately not applied to the cold engage, and
/// widening it there does not make this test stricter, it makes it
/// unconditionally red:
///
/// - **Cold engage** (the first one, over a host carrying no cover at all —
///   pf's enable bit is host-global kernel state that outlives the
///   per-test process, so an earlier test's normal `disengage` leaves this
///   the state nearly every real CI run starts in). Asserted on its
///   POST-CONDITION only: once `engage()` has RETURNED, `NON_PERMITTED` must
///   be unreachable. Nothing is asserted about the window before or during
///   that call, because there is no property to assert there — an uncovered
///   host is *supposed* to be open, and this test's own `baseline` below
///   REQUIRES it to be open before anything starts. A prober spanning that
///   window observes exactly the open host the baseline demanded and reports
///   a "leak" on every run. Mechanically the window cannot be closed either,
///   in any ordering: `pfctl -E` (enable) and `pfctl -f -` (load) are
///   separate process invocations, and while pf is disabled nothing is
///   filtered regardless of what is loaded.
/// - **Every transition** (each later `engage()`, replacing a still-live
///   cover). Asserted STRICTLY: the prober pool runs continuously across all
///   of them and not one probe may succeed. This is the actual #997 property.
///   The pool starts only after the cold engage's post-condition has been
///   verified, so from the instant the first prober SYN goes out the host is
///   KNOWN blocked and any success at all is a leak — no phase filtering, no
///   carve-outs.
///
/// The cold post-condition is not a formality: the failure mode it catches is
/// the INERT cover — `engage` returning Ok with the ruleset loaded but pf never
/// actually enabled, reported armed while egress runs in the clear. A load that
/// outright fails already surfaces as an Err from `engage`; only a settled
/// connect catches the silent half.
///
/// EVIDENTIARY SCOPE (the #997 caveat, `macos.rs`'s module doc has the
/// ticket-discipline argument in full): a pass here is strong empirical
/// evidence, not a mathematical proof, of atomicity across `TRANSITIONS` real
/// transitions — `PROBER_THREADS` concurrent short-timeout probers give an
/// `-Fa`-shaped regression many overlapping, independent chances to be caught.
/// The pool (not a single serial prober) is load-bearing specifically because
/// `block-policy drop` silently blocks a connect for its *entire* timeout, so
/// one thread alone could be parked inside a single blocked `connect_timeout`
/// call for a whole transition and never overlap it at all.
///
/// SENSITIVITY IS PRINTED, NOT ASSUMED — every real failure this guard has
/// caught was the cold `-E`→load window (tens of ms), an order of magnitude
/// wider than the `-Fa` window it exists for, so a green here is not a bound on
/// the narrowest window that would still be caught. The run therefore prints its
/// own numbers (the control's completed-connect ratio and the pool's aggregate
/// probe rate) rather than leaving a green uninformative;
/// `.config/nextest.toml` gives this test `success-output` so that line
/// survives a PASS. See the printed line itself for what it means and its own
/// caveats — this comment does not restate them.
///
/// LAST MEASURED — from this branch's own green privileged darwin run, and
/// nowhere else; not carried over from a previous filter's run, since the
/// commit-generation check below changed which attempts are counted.
///
/// | lane  | filtered       | raw (unfiltered) | pool                                              |
/// |-------|----------------|------------------|---------------------------------------------------|
/// | arm64 | 191/191 100.0% | 208/214 97.2%    | 480 probes / 16 threads / 627.470417ms = 1307 us   |
/// | amd64 | 184/184 100.0% | 200/206 97.1%    | 416 probes / 16 threads / 523.110046ms = 1257 us   |
///
/// The raw rate is what [`CONTROL_RATE_FLOOR_PCT`] is set from; see that const
/// for why the floor sits where it does.
///
/// Those figures answer the question the printed caveat leaves open. The window
/// this guards is NOT sub-millisecond: `-Fa`'s gap spans the `/etc/pf.os`
/// fingerprint reload plus the rule parse, and a bare `pfctl -n -f -` round
/// trip measures 2.0-2.7ms. The pool's ~1.3ms probe interval is the same order
/// — roughly two probes per window — which is why the guard works at all rather
/// than being structurally coarser than what it hunts.
///
/// An attempt is excluded by the generation filter exactly when a commit lands
/// inside its window, so the exclusion rate is attempt duration over transition
/// period. Both lanes measured ~11% (arm64 23/214, amd64 22/206) — close,
/// because their attempt durations and transition periods scale together. A leg
/// with slow attempts against fast transitions would exclude most of its
/// sample, and that too would be the filter working, not a defect.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_transition_never_admits_blocked_flow() {
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    // Two real, reachable hosts on the same reliable anycast network the
    // neighbouring privileged tests use (see `lockdown_privileged_tests.rs`'s
    // `PERMITTED`/`RESOLVER` doc for why real routable IPs, not loopback, are
    // required here). Alternating the permitted server between them forces
    // every `engage()` here to load a ruleset whose TEXT actually differs from
    // the one it replaces. `NON_PERMITTED` is blocked by EVERY ruleset in the
    // run, so any successful connect to it while a cover is live is a leak,
    // full stop — it can never be explained by which server happens to be
    // permitted at that moment.
    const SERVER_A: &str = "1.1.1.1";
    const SERVER_B: &str = "1.0.0.1";
    const NON_PERMITTED: &str = "8.8.8.8:443";
    // Transitions after the cold engage, so `TRANSITIONS + 1` real `engage()`
    // calls in total.
    const TRANSITIONS: usize = 24;
    // See the doc comment above: `block-policy drop` parks a single prober
    // thread inside one blocked `connect_timeout` call for the whole timeout,
    // so a lone prober could miss an entire fast transition. A pool of short-
    // timeout probers keeps several SYNs in flight at every instant instead.
    const PROBER_THREADS: usize = 16;
    const PROBER_TIMEOUT: Duration = Duration::from_millis(20);
    // The bound for the three one-shot verdicts that must be SETTLED rather
    // than sampled (reachable baseline, cold-engage post-condition, restored
    // egress). The same value both ways round on purpose: "blocked" means the
    // host stayed silent for the very bound it cleared when open. It is the
    // 5s the neighbouring privileged cover tests already use.
    const SETTLED_TIMEOUT: Duration = Duration::from_secs(5);

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal for a remote host that might not respond, not a
    // sync sleep or a poll on state this test controls.
    let connect = |addr: &str, timeout: Duration| TcpStream::connect_timeout(&addr.parse().unwrap(), timeout);

    let baseline = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        baseline.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach \
         {NON_PERMITTED}: {:?}",
        baseline.err().map(|e| e.kind()),
    );

    // One `state_dir` for the whole run: each engage's persist-before-mutate
    // save overwrites the previous cover's state file with its own token
    // before loading its ruleset, exactly as a real re-engage-without-
    // disengage would.
    let dir = tempfile::tempdir().unwrap();
    let addrs = [SERVER_A, SERVER_B];

    // COLD engage — its POST-CONDITION is the whole of its assertion (doc
    // comment above: the pre/mid-engage window is the open host `baseline`
    // just required, so there is nothing there to assert). Settling that
    // post-condition here is also what licenses the strict rule for everything
    // after it: the host is KNOWN blocked from this point on, so the prober
    // pool spawned below needs no phase carve-out.
    let mut held: Option<Cover> =
        Some(engage(addrs[0].parse().unwrap(), None, dir.path(), None).expect("cold engage real pf transient cover"));
    let cold = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        cold.is_err(),
        "a cold engage that returned Ok must already block {NON_PERMITTED} — the cover is INERT: \
         reported armed while egress runs in the clear (pf never enabled, or enabled under a \
         ruleset that is not ours)",
    );

    let leaked = AtomicBool::new(false);
    let stop = AtomicBool::new(false);

    // `phase` names which transition is in flight at any instant (0 = the cold
    // cover is live and steady, no transition started yet), and
    // `leaked_at_phase` latches the phase of the FIRST leak, so a failure says
    // WHICH engage admitted the flow instead of only THAT one did. Every value
    // it can report is a real leak — the cold engage's own window is not
    // probed at all.
    let phase = AtomicUsize::new(0);
    let leaked_at_phase = AtomicUsize::new(usize::MAX);

    // `permitted_idx` names which of `addrs` the LIVE ruleset actually permits
    // right now, and `commit_gen` counts the commits that produced it. Both are
    // published at the instant the `pfctl -f -` that makes them true commits,
    // from inside `engage_publishing` (see its doc comment for why "after
    // `engage` returns" is too late), not sampled before `engage` runs like
    // `phase` is. The cold engage above already committed `addrs[0]` before
    // this line runs, so `0` is correct from the start, not a placeholder.
    let permitted_idx = AtomicUsize::new(0);
    let commit_gen = AtomicUsize::new(0);

    // See the control thread below for what each of these counts.
    let control_hits = AtomicUsize::new(0);
    let control_permitted_attempts = AtomicUsize::new(0);
    let control_raw_hits = AtomicUsize::new(0);

    // Counts (not just logs) a failed `-X` retiring the OLD cover's refcount
    // below — production code in this module never swallows a `pfctl` result
    // without at least logging it, and a refcount that fails to drop here is
    // a real leak, not a benign no-op.
    let mut old_x_failures = 0usize;

    // Stops the pool on EVERY exit from the scope below, a panic included.
    // Without it, a panic between the spawns and the explicit `stop.store` —
    // reachably a flaky real `pfctl` failure at `engage_publishing(..).expect`
    // — unwinds past the store, and `thread::scope`'s join then waits forever
    // on 17 threads whose loop condition is still false. `skuld`'s `run_all`
    // runs the whole binary in ONE process, so those threads would otherwise
    // outlive this test and keep hammering real egress through every
    // neighbouring privileged case that engages a block-all cover and asserts
    // on egress — turning one genuine failure into a cascade and perturbing the
    // very host state `serial = TUN` exists to serialize.
    struct StopPool<'a>(&'a AtomicBool);
    impl Drop for StopPool<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    // Scoped, so the threads are JOINED (not detached) on both exits. A
    // `Vec<JoinHandle>` dropped during an unwind detaches instead, which is the
    // other half of the same leak.
    let (attempts, control_total_attempts, elapsed) = std::thread::scope(|s| {
        // Declared first so it drops LAST among this closure's locals, and
        // therefore always before `thread::scope`'s implicit join.
        let _stop_pool = StopPool(&stop);

        // Continuous prober POOL spanning the WHOLE transition loop below, each
        // on its own thread with a short timeout, so many SYNs are in flight at
        // every instant and the pool overlaps every one of the loop's real
        // `pfctl` calls rather than only sampling between iterations (see the
        // doc comment above for why a single serial prober is not enough under
        // `block-policy drop`).
        let probers: Vec<_> = (0..PROBER_THREADS)
            .map(|_| {
                s.spawn(|| {
                    let mut attempts = 0usize;
                    while !stop.load(Ordering::SeqCst) {
                        attempts += 1;
                        if connect(NON_PERMITTED, PROBER_TIMEOUT).is_ok() {
                            leaked.store(true, Ordering::SeqCst);
                            let _ = leaked_at_phase.compare_exchange(
                                usize::MAX,
                                phase.load(Ordering::SeqCst),
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            );
                        }
                    }
                    attempts
                })
            })
            .collect();

        // POSITIVE CONTROL for `PROBER_TIMEOUT`. The strict assertion below is
        // "no prober ever connected" — which is equally what a timeout too
        // short to complete ANY handshake on this runner would produce,
        // silently. One extra thread probes, at the same timeout over the same
        // run, the servers the covers PERMIT: a single success anywhere proves
        // the budget is live, so the silence next door is the cover's doing and
        // not the clock's.
        //
        // It reads `permitted_idx` to pick WHERE to connect — dialling
        // `addrs[permitted_idx]` on every attempt, never the other arm — so the
        // sample is not diluted by attempts aimed at the arm `block-policy
        // drop` guarantees can never land.
        //
        // What gets COUNTED is a separate question, and `commit_gen` — not
        // `permitted_idx` — decides it. `permitted_idx` only alternates 0/1, so
        // comparing it before and after an attempt cannot tell "no commit
        // landed" from "two did": both read the same value. That is a plain
        // ABA, and the measured figures put it inside the operating range
        // rather than outside it — an attempt can run the full
        // `PROBER_TIMEOUT` against a transition period of the same order. The
        // monotonic `commit_gen`, bumped inside the same call that stores
        // `permitted_idx`, cannot alias: equal generations across the attempt
        // means zero commits landed in its window, full stop.
        //
        // `commit_gen` is read BEFORE `permitted_idx`, mirroring the publisher's
        // store-then-bump order, so the window the generation check covers
        // always starts no later than the target read it is vouching for.
        //
        // Both a RAW count (every successful connect, uncounted attempts
        // included) and the filtered `hits`/`permitted_attempts` are tracked, so
        // the printed line carries both. RAW is the one the assertion and the
        // acceptance criterion both read: a hit is a hit whether or not its
        // window straddled a commit, so gating the positive control on the
        // filtered count would let the straddle filter alone redden a run on
        // which the budget was demonstrably live. The filtered pair stays for
        // the printed line, where the permitted-target denominator is what
        // makes the rate meaningful.
        let control = s.spawn(|| {
            let mut attempts = 0usize;
            while !stop.load(Ordering::SeqCst) {
                let gen_before = commit_gen.load(Ordering::SeqCst);
                let target = format!("{}:443", addrs[permitted_idx.load(Ordering::SeqCst)]);
                attempts += 1;
                let ok = connect(&target, PROBER_TIMEOUT).is_ok();
                let gen_after = commit_gen.load(Ordering::SeqCst);
                if ok {
                    control_raw_hits.fetch_add(1, Ordering::SeqCst);
                }
                // Only count an attempt no commit landed inside.
                if gen_before == gen_after {
                    control_permitted_attempts.fetch_add(1, Ordering::SeqCst);
                    if ok {
                        control_hits.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            attempts
        });

        // Wall clock spanning exactly the window the pool covers, so the printed
        // probe rate is probes-per-second of the run the assertions are about.
        let pool_started = std::time::Instant::now();

        for i in 1..=TRANSITIONS {
            phase.store(i, Ordering::SeqCst);
            let server_idx = i % addrs.len();
            let server_ip: IpAddr = addrs[server_idx].parse().unwrap();
            // `engage_publishing` publishes `permitted_idx` and `commit_gen`
            // itself, synchronously at the real `pfctl -f -` commit — see its
            // doc comment.
            let new_cover = engage_publishing(server_ip, dir.path(), &permitted_idx, &commit_gen, server_idx)
                .expect("engage real pf transient cover");
            if let Some(old) = held.take() {
                // Retire the OLD cover's pf enable refcount only — never its
                // normal Drop, which would reload /etc/pf.conf (a pass-all host)
                // over the ruleset the NEW cover (already engaged above) just
                // loaded. The refcount stays balanced: this engage's own `-E`
                // already ran, so this `-X` brings it back down by exactly one.
                if let Err(e) = pfctl_status(
                    pfctl(&["-X", &old.token], None, BestEffortPhase::RecoverCover),
                    "pfctl -X",
                ) {
                    tracing::warn!(error = %e, iteration = i, "pfctl -X failed retiring the old cover's refcount mid-transition");
                    old_x_failures += 1;
                }
                old.detach();
            }
            held = Some(new_cover);
        }

        stop.store(true, Ordering::SeqCst);
        let elapsed = pool_started.elapsed();
        let attempts: usize = probers
            .into_iter()
            .map(|p| p.join().expect("prober thread panicked"))
            .sum();
        let control_total_attempts = control.join().expect("control prober thread panicked");
        (attempts, control_total_attempts, elapsed)
    });

    assert!(
        attempts > 0,
        "prober pool made no attempts at all — this test is vacuous"
    );
    assert_eq!(
        old_x_failures, 0,
        "pfctl -X failed retiring the old cover's refcount on {old_x_failures}/{TRANSITIONS} \
         transitions — each failure leaks a pf enable refcount (see the warn logged above for \
         which iteration and why)"
    );

    // The guard stating its own sensitivity. Printed unconditionally (see the
    // doc comment): a green with no number attached says only that nothing was
    // caught, not that anything would have been. `permitted_attempts` (not
    // `control_total_attempts`) is `hits`' denominator: some control attempts
    // straddle a commit and are excluded by the generation check even though
    // every attempt targets the believed-permitted arm (see the control
    // thread's doc comment above).
    let hits = control_hits.load(Ordering::SeqCst);
    let permitted_attempts = control_permitted_attempts.load(Ordering::SeqCst);
    let raw_hits = control_raw_hits.load(Ordering::SeqCst);
    // Guard the division: a `permitted_attempts` of 0 (every control attempt
    // straddled a commit) must print as an explicit "no permitted-target
    // attempts" rather than a silent `NaN%` that could slip past a human
    // skimming the printed line.
    let control_rate = if permitted_attempts == 0 {
        f64::NAN
    } else {
        100.0 * hits as f64 / permitted_attempts as f64
    };
    // RAW: every successful connect over every control attempt, filtered or
    // not. This — not `hits/permitted_attempts` — is the figure that does not
    // move when the filter changes: a correct filter changes only which
    // attempts are COUNTED, never whether a connect succeeds.
    let raw_rate = if control_total_attempts == 0 {
        f64::NAN
    } else {
        100.0 * raw_hits as f64 / control_total_attempts as f64
    };
    let per_probe_us = elapsed.as_micros() as f64 / attempts as f64;
    // What a probe needs to DETECT a leak, stated exactly: the cover's ruleset
    // is `block out all` with no `block in` at all (`build_pf_ruleset`,
    // macos.rs), so only the outbound SYN has to escape the window — the
    // SYN-ACK comes back through an unfiltered inbound path, and the client's
    // own outbound ACK being dropped afterwards does not fail the connect,
    // because BSD completes `connect` at ESTABLISHED on SYN-ACK receipt and
    // queues the ACK behind it. That last half is reasoned from TCP and
    // `std`'s documented `connect_timeout` semantics, not executed here; the
    // `block out all`/no-`block in` half is read straight off the builder.
    eprintln!(
        "[sensitivity] macos_failclosed_cover_transition: control completed {hits}/{permitted_attempts} \
         connects ({control_rate:.1}%) to a PERMITTED server within {PROBER_TIMEOUT:?}, filtered by the \
         commit-generation check; raw (unfiltered) {raw_hits}/{control_total_attempts} connects \
         ({raw_rate:.1}%) across every control attempt — raw/total is the figure independent of that \
         filter; the pool emitted {attempts} probes across {PROBER_THREADS} threads over {elapsed:?} = \
         one probe per {per_probe_us:.0} us of wall clock. That interval bounds probe COVERAGE, not \
         detection: to be CAUGHT, a leak window must let a probe's outbound SYN escape and the SYN-ACK \
         return inside {PROBER_TIMEOUT:?}. The cover blocks egress only (`block out all`, no `block in`) \
         and `connect` completes on the SYN-ACK, so the client's own ACK being dropped by the next \
         `pfctl -f -` commit does NOT hide the leak — the ACK is not required. A leak window shorter than \
         the probe interval, or too short to pass a SYN at all, is still likelier to be missed than \
         caught; the window this guards is the `-Fa` gap — an /etc/pf.os fingerprint reload plus a rule \
         parse, 2.0-2.7ms for a bare `pfctl -n -f -` round trip — so it is millisecond-scale, the same \
         order as the interval above, not shorter than it."
    );

    assert!(
        !leaked.load(Ordering::SeqCst),
        "a connection to {NON_PERMITTED} got out while a cover was live — every ruleset across \
         the {TRANSITIONS} transitions blocks it, and the cold engage was verified blocking \
         before the first prober started, so `pfctl -f -` is not behaving as one atomic \
         transaction; leaked_at_phase={} (0 = the cold cover, steady, before any transition \
         began; >=1 = that transition)",
        leaked_at_phase.load(Ordering::SeqCst),
    );

    // Gated on RAW, not `hits`: the straddle filter decides what gets COUNTED,
    // never whether a connect succeeded, so it has no business deciding
    // whether the budget is live (see the control thread's doc comment).
    assert!(
        control_total_attempts > 0,
        "the control prober made no attempt at all — the positive control is vacuous"
    );
    assert!(
        raw_rate >= CONTROL_RATE_FLOOR_PCT,
        "positive control: only {raw_hits}/{control_total_attempts} ({raw_rate:.1}%) connects to a \
         PERMITTED server ({SERVER_A}/{SERVER_B}) completed within {PROBER_TIMEOUT:?}, under the \
         {CONTROL_RATE_FLOOR_PCT:.0}% floor (of which {permitted_attempts} survived the \
         commit-generation filter). The never-admitted assertion above is therefore not trustworthy: \
         this rate IS the prober pool's per-probe chance of catching a real leak, because both are the \
         same question — does a handshake finish inside {PROBER_TIMEOUT:?}. This gates on the RAW count, \
         so the filter cannot be the cause — suspect the budget itself: {PROBER_TIMEOUT:?} is also the \
         control's connect budget, and an anycast RTT from this runner near it fails most control \
         attempts on a perfectly healthy host. Do NOT widen {PROBER_TIMEOUT:?} to buy that margin, and \
         do NOT lower the floor: {PROBER_TIMEOUT:?} is the prober pool's budget too, and raising it \
         thins the pool's probe density, which IS this guard's sensitivity. The knob is loaded both \
         ways."
    );

    // The last cover's normal Drop restores /etc/pf.conf.
    drop(held.take());
    let restored = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        restored.is_ok(),
        "final disengage must restore egress: {NON_PERMITTED}={:?}",
        restored.err().map(|e| e.kind()),
    );
}

// pf state purge on a transient engage (bindreams/hole#1015, transient half) ==========================================

/// Proves the behavioural half of [`purges_state`]: a flow that already holds
/// a pf state entry when the transient cover engages does **not** survive it.
///
/// pf matches the state table before the ruleset, so without the purge this
/// flow keeps running past `block out all` for as long as its entry lives —
/// `tcp.established` defaults to 86400s and every packet refreshes it, so a
/// long-lived upload, an SSH session or a WebSocket never expires at all. The
/// unit tests next door assert the `pfctl` sequence; this one asserts the
/// kernel consequence, which is the property that actually matters.
///
/// **Staging the precondition is the whole setup.** A state entry exists only
/// if pf saw the packet while pf was ENABLED (`pf_af_hook` bails on
/// `!pf_is_enabled`), and stock macOS ships pf loaded but never enabled. So the
/// test stands in for the third party that enabled it — Internet Sharing,
/// another VPN, a hand-run `pfctl -e` — with its own `pfctl -E` plus a
/// permissive keep-state ruleset, exactly the case #1015 calls its case 2. The
/// `-E` refcount this takes is returned at the end; the cover's own `-E`/`-X`
/// pair nests inside it, so pf's enable state is exactly as this test found it
/// once both are released.
///
/// Asserted on the STATE TABLE (`pfctl -s state`) rather than on whether the
/// held socket still carries traffic: the state entry is the thing pf consults
/// before the ruleset, so its absence is the property directly, with no
/// dependence on a remote peer choosing to answer.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_state_purge_kills_a_flow_established_before_engage() {
    use std::net::TcpStream;
    use std::time::Duration;

    // Same reliable anycast pair the transition test above uses, and for the
    // same reason (see its doc): the cover's permits are IP-based, so the flow
    // that must die has to be a real routable destination the cover blocks.
    const PERMITTED: &str = "1.1.1.1";
    const NON_PERMITTED_IP: &str = "8.8.8.8";
    const NON_PERMITTED: &str = "8.8.8.8:443";
    // External-event bound: a remote host that might not answer, surfaced to a
    // human — not a sync sleep. Same 5s the neighbouring cover tests use.
    const SETTLED_TIMEOUT: Duration = Duration::from_secs(5);

    let states = || {
        pfctl_stdout(
            pfctl(&["-s", "state"], None, BestEffortPhase::RecoverCover),
            "pfctl -s state",
        )
        .expect("pfctl -s state")
    };

    // 1. Stand in for the third party that already enabled pf, under a ruleset
    //    that creates state for everything. RAII, so EVERY exit path — a failed
    //    assertion included — reloads /etc/pf.conf and returns the refcount;
    //    otherwise a red run leaves the runner with pf enabled under a pass-all
    //    ruleset and an unreferenced token until reboot. Declared first, so it
    //    unwinds after the cover and the socket below.
    struct HostPfStandIn(String);
    impl Drop for HostPfStandIn {
        fn drop(&mut self) {
            // Mirrors `disengage`'s warn-on-failure pattern (macos.rs): a red
            // run must not ALSO leave a silently-stranded pf ruleset or an
            // unreferenced enable token with no logged trace of why the
            // restore failed.
            if let Err(e) = pfctl_status(pfctl(&["-f", PFCONF], None, BestEffortPhase::RecoverCover), "pfctl -f") {
                tracing::warn!(error = %e, "pf ruleset restore failed unwinding the HostPfStandIn test fixture");
            }
            if let Err(e) = pfctl_status(pfctl(&["-X", &self.0], None, BestEffortPhase::RecoverCover), "pfctl -X") {
                tracing::warn!(error = %e, "pfctl -X failed unwinding the HostPfStandIn test fixture");
            }
        }
    }
    let enabled = pfctl(&["-E"], None, BestEffortPhase::RecoverCover).expect("pfctl -E");
    let _host_pf = HostPfStandIn(
        parse_enable_token(&String::from_utf8_lossy(&enabled.stderr))
            .or_else(|| parse_enable_token(&String::from_utf8_lossy(&enabled.stdout)))
            .expect("pfctl -E must print an enable token"),
    );
    let permissive = pfctl(
        &["-f", "-"],
        Some(b"pass out all keep state\npass in all keep state\n"),
        BestEffortPhase::RecoverCover,
    )
    .expect("load the permissive pre-cover ruleset");
    assert!(
        permissive.status.success(),
        "the permissive pre-cover ruleset must load: {}",
        String::from_utf8_lossy(&permissive.stderr).trim()
    );

    // 2. Establish the flow the cover must kill, and HOLD it open — a closed
    //    socket's state would drain on its own and prove nothing.
    let _flow = TcpStream::connect_timeout(&NON_PERMITTED.parse().unwrap(), SETTLED_TIMEOUT)
        .unwrap_or_else(|e| panic!("NETWORK/ENVIRONMENT problem (not the cover): must reach {NON_PERMITTED}: {e:?}"));
    assert!(
        states().contains(NON_PERMITTED_IP),
        "PRECONDITION: pf must hold a state entry for the flow before the cover engages, or this \
         test proves nothing — pf enabled and a keep-state ruleset loaded, yet `pfctl -s state` \
         does not name {NON_PERMITTED_IP}"
    );

    // 3. Engage the transient cover over that live flow, and read the state
    //    table back while the cover is still the loaded ruleset.
    let dir = tempfile::tempdir().unwrap();
    let cover = engage(PERMITTED.parse().unwrap(), None, dir.path(), None).expect("engage the transient cover");
    let after = states();
    // Restore before asserting: a failure must not leave the machine behind a
    // block-all cover while the panic unwinds.
    drop(cover);

    assert!(
        !after.contains(NON_PERMITTED_IP),
        "a flow to {NON_PERMITTED_IP} still held a pf state entry after the transient cover \
         engaged — pf matches state BEFORE rules, so it keeps flowing past `block out all` until \
         the entry expires (`tcp.established` default 86400s, refreshed per packet). \
         `pfctl -s state` after engage:\n{after}"
    );
}

// loopback across a pf LOAD (the skip-flag-clear window) ==============================================================

/// Failure bound for a loopback datagram the KERNEL may never deliver. pf drops
/// silently under `block-policy drop` — no ICMP, no socket error — so a blocked
/// datagram produces no event at all, only absence. That is the sanctioned
/// exception: the timeout IS the failure signal, and reporting it is the whole
/// point of the probe, not a sleep synchronizing two halves of this test. Same
/// 5s the neighbouring cover tests use.
const DATAGRAM_LOST: std::time::Duration = std::time::Duration::from_secs(5);

/// Run `run` with a lock-step loopback UDP round trip in flight continuously,
/// and report whether any leg of any round trip failed to arrive.
///
/// Returns `run`'s value, the FIRST loss (a human-readable stage, `None` for a
/// clean run) and the number of completed round trips — 0 means the probe never
/// ran and any verdict from it is vacuous.
///
/// A datagram, not a TCP stream, because the two answer different questions. A
/// TCP segment dropped inside a window this narrow is *retransmitted*, so the
/// flow survives and the only trace is a stall to the macOS minimum RTO — which
/// any read bound generous enough not to flake will absorb, leaving a green.
/// A datagram has no retransmit: pf drops it and it is simply gone, so loss is
/// observable directly rather than as latency.
///
/// One thread drives BOTH ends — probe `send` → echo `recv_from` → echo
/// `send_to` → probe `recv` — so there is no second thread to shut down and no
/// shutdown datagram that could itself be dropped and hang the join. Both
/// sockets carry [`DATAGRAM_LOST`], so every leg is bounded and the loop's
/// `stop` check is reached.
fn with_loopback_datagram_probe<R>(run: impl FnOnce() -> R) -> (R, Option<String>, usize) {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};

    let echo = UdpSocket::bind("127.0.0.1:0").expect("bind the loopback echo socket");
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind the loopback probe socket");
    probe
        .connect(echo.local_addr().expect("echo socket addr"))
        .expect("point the probe socket at the echo socket");
    echo.set_read_timeout(Some(DATAGRAM_LOST)).expect("echo read bound");
    probe.set_read_timeout(Some(DATAGRAM_LOST)).expect("probe read bound");

    let stop = AtomicBool::new(false);

    std::thread::scope(|s| {
        // Stops the probe on EVERY exit from this scope, a panic in `run`
        // included — otherwise the unwind skips the `stop.store` below and
        // `thread::scope`'s implicit join waits forever on a thread whose loop
        // condition is still false. Declared first, so it drops last among
        // these locals and therefore always before that join.
        struct StopProbe<'a>(&'a AtomicBool);
        impl Drop for StopProbe<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _stop_probe = StopProbe(&stop);

        let prober = s.spawn(|| {
            let mut buf = [0u8; 8];
            let mut seq = 0u64;
            let mut round_trips = 0usize;
            while !stop.load(Ordering::SeqCst) {
                seq += 1;
                let payload = seq.to_le_bytes();
                // A `block-policy drop` block is silent, so a send normally
                // still reports success; an error here is a dropped datagram
                // all the same, and is reported rather than ignored.
                if let Err(e) = probe.send(&payload) {
                    return (
                        Some(format!("outbound send of datagram {seq} failed: {e:?}")),
                        round_trips,
                    );
                }
                let from = match echo.recv_from(&mut buf) {
                    Ok((8, from)) if buf == payload => from,
                    Ok((n, _)) => return (Some(format!("echo socket read {n} unexpected bytes")), round_trips),
                    Err(e) => {
                        return (
                            Some(format!(
                                "OUTBOUND leg lost: the echo socket never saw datagram {seq} ({e:?})"
                            )),
                            round_trips,
                        )
                    }
                };
                if let Err(e) = echo.send_to(&payload, from) {
                    return (Some(format!("echo send of datagram {seq} failed: {e:?}")), round_trips);
                }
                match probe.recv(&mut buf) {
                    Ok(8) if buf == payload => {}
                    Ok(n) => return (Some(format!("probe socket read {n} unexpected bytes")), round_trips),
                    Err(e) => {
                        return (
                            Some(format!(
                                "RETURN leg lost: the probe socket never saw the echo of datagram {seq} ({e:?})"
                            )),
                            round_trips,
                        )
                    }
                }
                round_trips += 1;
            }
            (None, round_trips)
        });

        let r = run();
        stop.store(true, Ordering::SeqCst);
        let (loss, round_trips) = prober.join().expect("loopback probe thread panicked");
        (r, loss, round_trips)
    })
}

/// Proves the rule half of the loopback exemption ([`LOOPBACK_PASSES`]): a
/// `pfctl -f -` that replaces a still-live blocking cover must not drop
/// loopback while it loads.
///
/// `set skip on lo0` is applied OUTSIDE the rule ticket — `pfctl`'s `main()`
/// clears every interface's skip flag before it parses and before
/// `DIOCXBEGIN`, so from that clear until the new ruleset's own `set skip`
/// ioctl lands, lo0 is filtered again while the OLD ruleset is still
/// authoritative. If that old ruleset is a cover with no lo0 `pass`, loopback
/// meets `block out all` and is silently discarded.
///
/// **The control is what makes this non-vacuous.** The same probe runs twice
/// over the same loads: once with a cover ruleset carrying `set skip on lo0`
/// alone (the pre-fix shape — MUST lose a datagram) and once with the
/// production [`build_pf_ruleset`] (MUST NOT). A green here therefore carries
/// its own proof that the window exists and that the probe can see it, rather
/// than asserting an absence no one demonstrated was observable.
///
/// The guarded leg's loads are followed by `Cover::drop`'s
/// `pfctl -f /etc/pf.conf`, which is the identical window on the identical
/// victim and is the concrete user-visible failure: a covered auto-connect
/// succeeds, and the disengage that should be invisible eats a local
/// datagram.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_load_never_drops_a_loopback_datagram() {
    // Same reliable anycast pair the tests above use; the IP only has to make
    // the two rulesets in a cycle textually different.
    const PERMITTED: &str = "1.1.1.1";
    const ALT: &str = "1.0.0.1";
    const LOADS: usize = 24;

    let dir = tempfile::tempdir().unwrap();
    // A real cover: pf enabled, a blocking ruleset live, state file written.
    // RAII, so every exit path restores `/etc/pf.conf` — the guarded leg below
    // consumes it deliberately, inside the probe.
    let cover = engage(PERMITTED.parse().unwrap(), None, dir.path(), None).expect("engage the transient cover");

    // The pre-fix ruleset shape: `set skip on lo0` and nothing else exempting
    // loopback.
    let unprotected =
        |ip: &str| format!("set block-policy drop\n{LOOPBACK_SKIP}block out all\npass out quick from any to {ip}\n");
    let protected = |ip: &str| build_pf_ruleset(ip.parse().unwrap(), None);
    let load = |text: &str| real_load_ruleset(text).expect("pfctl -f - must load a cover ruleset");
    let run_loads = |mk: &dyn Fn(&str) -> String| {
        for i in 0..LOADS {
            load(&mk(if i % 2 == 0 { ALT } else { PERMITTED }));
        }
    };

    // CONTROL. The prime load matters: the window's victim is the OUTGOING
    // ruleset, so the variant under test has to be the live one already when
    // the first MEASURED load starts.
    load(&unprotected(PERMITTED));
    let ((), control_loss, control_round_trips) = with_loopback_datagram_probe(|| run_loads(&unprotected));

    // GUARDED: the production builder, plus the `/etc/pf.conf` restore.
    load(&protected(PERMITTED));
    let ((), guarded_loss, guarded_round_trips) = with_loopback_datagram_probe(|| {
        run_loads(&protected);
        drop(cover);
    });

    // The control is gated on its LOSS, never on its round-trip count:
    // `with_loopback_datagram_probe` returns on the first loss, so a control
    // that sees the window on datagram 1 legitimately reports zero COMPLETED
    // round trips. Requiring `control_round_trips > 0` would red a control
    // that did exactly what it exists to do, on nothing but the ordering of a
    // thread spawn against a `pfctl` fork. Only the guarded leg needs a
    // round-trip floor, because there a green is an ABSENCE of loss and a
    // probe that never ran would supply one.
    assert!(
        control_loss.is_some(),
        "POSITIVE CONTROL FAILED: {LOADS} `pfctl -f -` loads replacing a live `block out all` cover \
         whose ONLY loopback exemption is `set skip on lo0` lost no datagram across \
         {control_round_trips} round trips. Either this `pfctl` does not clear interface skip flags \
         outside the rule ticket (and the guarded assertion below is vacuous), or the probe cannot \
         see the window — do not silence this by weakening the assertion below; establish which."
    );
    // LOSS FIRST, vacuity second. `with_loopback_datagram_probe` counts a round
    // trip only at the END of a completed iteration and returns on the first
    // loss, so the regression this test exists to catch — a guarded leg that
    // drops datagram 1 — produces BOTH `guarded_loss == Some(..)` AND
    // `guarded_round_trips == 0`. A vacuity-first order would then report "the
    // probe never ran", point the maintainer at the harness, and never print
    // the payload naming the lost datagram and its leg. The floor still guards
    // a green, which is the only verdict it has to: a zero-round-trip run
    // reaches it only with `guarded_loss == None`.
    assert_eq!(
        guarded_loss, None,
        "a loopback datagram was lost across a `pfctl -f -` that replaced a live production cover \
         ({guarded_round_trips} round trips before it) — the control above proves the window is \
         real and visible, so the cover ruleset's `pass ... on lo0 all no state` rules \
         (`LOOPBACK_PASSES`) are missing, stateful, or ordered behind a `quick` block"
    );
    assert!(
        guarded_round_trips > 0,
        "the guarded leg's loopback probe completed no round trip at all, and reported no loss \
         either — the assertion above therefore held over a probe that never ran"
    );
}

/// Loopback must SURVIVE that engage. What keeps the host-wide purge above
/// (`DIOCCLRSTATES`, no `psk_ifname`/`psk_ownername`) from severing every local
/// TCP session on the machine is not the flush's scope but the ruleset's:
/// `set skip on lo0` passes loopback "as if pf was disabled", with no state
/// entry to lose.
///
/// A STATEFUL `pass out quick on lo0 all` would not, and for a reason wider
/// than the purge: pf applies `flags S/SA` by default, so that rule only ever
/// MATCHES a SYN. Any mid-stream segment of an already-established session falls
/// through to `block out all` and is silently dropped under `block-policy drop`
/// whenever it has no state entry to be matched against first — after the purge
/// flushed it, and equally on a host where pf was disabled until this engage
/// enabled it, so the flow never had one. That is why the lo0 passes the
/// ruleset DOES carry ([`LOOPBACK_PASSES`], for a window `set skip` cannot
/// cover) are `no state`: it suppresses that default.
///
/// Asserted end-to-end on a real established loopback connection carried ACROSS
/// a real engage, because the unit test next door
/// (`ruleset_skips_loopback_rather_than_passing_it`) can only pin the ruleset
/// TEXT — it cannot show that the kernel keeps the flow alive.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_engage_does_not_sever_established_loopback_flows() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    const PERMITTED: &str = "1.1.1.1";
    // The failure bound for a segment the KERNEL may never deliver. `pf` drops
    // silently under `block-policy drop` — no RST, no ICMP — so a severed
    // loopback flow produces no event at all, only absence. That is the
    // sanctioned exception: an external verdict that might never arrive, with
    // the timeout as the failure signal surfaced to a human, not a sleep
    // synchronizing two pieces of this test. Same 5s the neighbouring cover
    // tests use for the same reason.
    const SETTLED_TIMEOUT: Duration = Duration::from_secs(5);

    // A real established loopback session, held open across the engage.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let mut client = TcpStream::connect(addr).expect("connect to the loopback listener");
    let (mut server, _) = listener.accept().expect("accept the loopback connection");
    server
        .set_read_timeout(Some(SETTLED_TIMEOUT))
        .expect("set the loopback read bound");

    // Carry a byte BEFORE the engage, so the connection is unambiguously
    // established — and, on a host where pf was already enabled, unambiguously
    // holding a pf state entry — rather than merely handshaked.
    client.write_all(b"a").expect("pre-engage write");
    let mut buf = [0u8; 1];
    server
        .read_exact(&mut buf)
        .expect("NETWORK/ENVIRONMENT problem (not the cover): a pre-cover loopback byte must arrive");

    let dir = tempfile::tempdir().unwrap();
    let cover = engage(PERMITTED.parse().unwrap(), None, dir.path(), None).expect("engage the transient cover");

    // The actual assertion: a MID-STREAM segment, the exact packet a
    // `flags S/SA` pass rule could not match after the purge. Write and read
    // while the cover is still the loaded ruleset.
    let carried = client
        .write_all(b"b")
        .and_then(|()| server.read_exact(&mut buf))
        .map(|()| buf[0]);

    // Restore before asserting, so a failure does not leave the machine behind
    // a block-all cover while the panic unwinds.
    drop(cover);

    assert_eq!(
        carried.as_ref().map_err(|e| e.kind()),
        Ok(&b'b'),
        "an established loopback flow did not survive the transient cover's engage — its \
         `pfctl -F states` purge is host-wide, so the cover's ruleset must exempt lo0 with \
         `set skip on lo0` and NOT a state-bearing `pass` rule, or every local TCP session on the \
         host (databases, dev servers, `ssh -L` forwards, IDE sockets) dies on every covered start"
    );
}
