//! Task 2 Steps 2/2b (refs #868) — the two experiments D3's whole design
//! rests on. Both measure **configd**, not our own code, which is why
//! neither drives `dns_steer`'s dictionary-building helper: reusing it here
//! would make a regression in that helper look like a mechanism failure, the
//! opposite of what these probes exist to isolate.
//!
//! - `macos_dns_global_net_state_session_keys_die_with_their_session`
//!   (Step 2): a raw `SCDynamicStore` experiment. Builds a
//!   `session_keys(true)` store by hand, publishes the same dictionary shape
//!   `dns_steer` publishes, blocks for configd to merge it, drops the store
//!   handle **without** calling `.remove()`, and blocks again for configd to
//!   un-merge it. **This confirms D3's mechanism.** A `Drop`-glue-runs-on-
//!   normal-exit outcome only, deliberately distinct from Step 2b's crash
//!   path below — collapsing the two would prove nothing about `SIGKILL`.
//!   If this fails, D3 is unimplementable as written: **stop and escalate to
//!   Anna** (see this test's own panic messages for why).
//! - `macos_dns_global_net_state_session_keys_die_with_a_killed_process`
//!   (Step 2b): drives the PRODUCTION `dns_steer::engage` — unlike Step 2,
//!   nothing here is exempt from the drive-production-code rule, because
//!   what is under test is whether `engage`'s key dies with a process that
//!   never gets to run so much as one line of `Drop` glue. No new `[[bin]]`
//!   target: this same test binary re-execs itself
//!   (`std::env::current_exe()`) with `HOLE_DNS_STEER_LIFETIME_PROBE_HOLDER`
//!   set, and `main` below branches into [`run_holder`] before
//!   `skuld::run_all` ever runs — the same self-re-exec shape
//!   `dist_harness_panic_hook_tests.rs` uses, chosen over a dedicated
//!   `[[bin]]` because the plan's Task 2 file list names no such target.
//!   The holder calls `engage`, prints a readiness line, and parks forever;
//!   the parent rendezvous on that line (a real event, not a bound), waits
//!   for configd to merge the holder's key, sends `SIGKILL`, reaps the
//!   child, and blocks again for configd to un-merge it. **If this fails,
//!   D3's justification for having no sweep is false — stop and escalate.**
//!
//! Own binary, not a module in the lib test binary: skuld validates that a
//! label is declared once per binary, and the lib already declares `TUN` in
//! `routing/failclosed/lockdown_privileged_tests.rs` (mirrors
//! `gateway_privileged.rs`'s own rationale for the same shape).
//!
//! Runs on the elevated `tun` lane only — writing `SCDynamicStore` `State:`
//! keys needs root, same as the mechanism test in
//! `dns_steer/privileged_tests.rs`. Not `#[ignore]`d; a default unprivileged
//! run fails loud rather than silently skipping.
//!
//! COUPLED NAMES: both tests above carry the literal substring
//! `macos_dns_global_net_state_`, which `.config/nextest.toml`'s
//! `global_net_state` filter matches by substring — renaming either without
//! updating that filter AND the `GLOBAL_NET_STATE` label silently drops it
//! from the group. `cargo xtask verify-global-net-state-labels` (CI,
//! unprivileged) fails loud on that drift.
//!
//! **What a real run does to the machine**: publishes two short-lived
//! synthetic-service DNS keys (one per test, TEST-NET-1 resolvers) and, for
//! Step 2b, spawns and `SIGKILL`s a child process of this same binary.

hole_test_observability::register!();

/// Set only on the child side of Step 2b's self re-exec — see the module
/// doc. Checked in `main` before `skuld::run_all`, mirroring
/// `dist_harness_panic_hook_tests.rs`'s `HOLE_DIST_HARNESS_PANIC_TEST`
/// branch in `crates/common/src/lib.rs::main`.
const HOLDER_ENV: &str = "HOLE_DNS_STEER_LIFETIME_PROBE_HOLDER";

fn main() {
    if std::env::var_os(HOLDER_ENV).is_some() {
        #[cfg(target_os = "macos")]
        {
            macos_impl::run_holder();
            return;
        }
        // `std::process::exit` diverges, so a `return` after this arm would
        // be unreachable on every non-macOS target and rejected under `-D
        // warnings` (caught by Windows CI, since this file must still
        // compile there — see the module doc).
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("{HOLDER_ENV} is only ever set by this macOS-only test's own self re-exec");
            std::process::exit(2);
        }
    }
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// Binds to `.config/nextest.toml`'s `global_net_state` test-group via
/// `cargo xtask verify-global-net-state-labels` — see that guard's own doc
/// for what it checks. Declared unconditionally (not inside the
/// `cfg(target_os = "macos")` module below) so skuld's exactly-one-per-binary
/// check holds on every platform this binary compiles for, mirroring
/// `gateway_privileged.rs`.
#[skuld::label]
const GLOBAL_NET_STATE: skuld::Label;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::{GLOBAL_NET_STATE, HOLDER_ENV, TUN};

    use std::ffi::CString;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use system_configuration::dynamic_store::SCDynamicStoreBuilder;
    use system_configuration::sys::schema_definitions::{
        kSCPropNetDNSSearchOrder, kSCPropNetDNSServerAddresses, kSCPropNetDNSSupplementalMatchDomains,
    };

    /// TEST-NET-1 (RFC 5737), distinct from `dns_steer/privileged_tests.rs`'s
    /// own resolver constant purely for grep-ability across logs — the two
    /// binaries never run concurrently (`serial = TUN` + the
    /// `global_net_state` group's `max-threads = 1`), so reuse would have
    /// been safe too.
    const LIFETIME_PROBE_RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
    const KILLED_PROCESS_RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);

    const DNS_CONFIG_NOTIFY_KEY: &str = "com.apple.system.SystemConfiguration.dns_configuration";

    fn budget(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    fn run(cmd: &str, args: &[&str]) -> String {
        match Command::new(cmd).args(args).output() {
            Ok(out) => format!(
                "$ {cmd} {}\n[{}]\n{}{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ),
            Err(e) => format!("$ {cmd} {}\n[spawn failed] {e}", args.join(" ")),
        }
    }

    fn scutil_dns() -> String {
        run("scutil", &["--dns"])
    }

    /// Every `nameserver[N] : ADDR` line, sorted and deduped — the structural
    /// shape of "which resolvers does this machine use", stable enough to
    /// compare before against after. Duplicated from
    /// `dns_steer/privileged_tests.rs` rather than shared: this file is a
    /// separate binary, and `test_utils` (the crate's one shared privileged-
    /// lane harness module) is explicitly for cross-platform/cross-crate
    /// helpers, not single-file macOS-only FFI wrappers like this one.
    fn nameservers(scutil_dns_output: &str) -> Vec<String> {
        let mut out: Vec<String> = scutil_dns_output
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("nameserver["))
            .map(str::to_owned)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    // configd change notification =====================================================================================

    extern "C" {
        fn notify_register_file_descriptor(
            name: *const libc::c_char,
            notify_fd: *mut libc::c_int,
            flags: libc::c_int,
            out_token: *mut libc::c_int,
        ) -> u32;
        fn notify_cancel(token: libc::c_int) -> u32;
    }

    /// A live registration for configd's DNS-configuration-changed
    /// notification — see the module doc for why every wait here rendezvous
    /// on this rather than on elapsed time.
    struct DnsConfigNotify {
        fd: libc::c_int,
        token: libc::c_int,
    }

    impl DnsConfigNotify {
        fn register() -> Option<Self> {
            let name = CString::new(DNS_CONFIG_NOTIFY_KEY).expect("notify key has no interior NUL");
            let mut fd: libc::c_int = -1;
            let mut token: libc::c_int = 0;
            // SAFETY: `name` is a valid NUL-terminated string that outlives
            // the call; `fd`/`token` are live out-params.
            let status = unsafe { notify_register_file_descriptor(name.as_ptr(), &mut fd, 0, &mut token) };
            (status == 0).then_some(Self { fd, token })
        }

        /// Block until configd posts a DNS-configuration change, or
        /// `deadline` passes. `deadline` is a failure bound on an EXTERNAL
        /// event, not a sync sleep — see the module doc.
        fn wait(&self, deadline: Instant) -> bool {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                let millis = libc::c_int::try_from(remaining.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: single live pollfd, count matches.
                match unsafe { libc::poll(&mut pfd, 1, millis) } {
                    -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                    -1 => return false,
                    0 => return false,
                    _ => {
                        let mut token_be = [0u8; 4];
                        // SAFETY: reading 4 bytes into a 4-byte buffer.
                        let n = unsafe { libc::read(self.fd, token_be.as_mut_ptr().cast(), 4) };
                        return n == 4;
                    }
                }
            }
        }

        /// Block until `scutil --dns` mentioning `needle` equals `want`,
        /// driven by configd's own change posts. Checks the predicate first
        /// so an already-satisfied state needs no event at all — this is
        /// what makes registering AFTER a mutation that may already have
        /// landed (Step 2b registers after the holder's readiness line, not
        /// before its `engage` call) still sound.
        fn settle(&self, deadline: Instant, needle: &str, want: bool) -> bool {
            loop {
                if scutil_dns().contains(needle) == want {
                    return true;
                }
                if !self.wait(deadline) {
                    return scutil_dns().contains(needle) == want;
                }
            }
        }
    }

    impl Drop for DnsConfigNotify {
        fn drop(&mut self) {
            // SAFETY: token was produced by a successful registration.
            unsafe {
                notify_cancel(self.token);
            }
        }
    }

    // Raw dictionary construction (Step 2 ONLY) =======================================================================

    /// The exact dictionary shape `dns_steer::macos::build_dns_dictionary`
    /// publishes, reconstructed by hand rather than called into — Step 2 is
    /// explicitly exempt from the drive-production-code rule (see the module
    /// doc): it is measuring configd's own honouring of `session_keys(true)`,
    /// not our dictionary-building code, so calling the production helper
    /// here would blur that line.
    fn build_dictionary(resolver: Ipv4Addr) -> CFDictionary {
        // SAFETY: schema constants are immortal CFStringRefs owned by the
        // framework.
        let (k_servers, k_domains, k_order) = unsafe {
            (
                CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses),
                CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains),
                CFString::wrap_under_get_rule(kSCPropNetDNSSearchOrder),
            )
        };
        let servers_arr = CFArray::from_CFTypes(&[CFString::new(&resolver.to_string())]);
        let domains = CFArray::from_CFTypes(&[CFString::new("")]);
        let pairs: [(CFString, CFType); 3] = [
            (k_servers, servers_arr.as_CFType()),
            (k_domains, domains.as_CFType()),
            (k_order, CFNumber::from(100_000i32).as_CFType()),
        ];
        let typed = CFDictionary::from_CFType_pairs(&pairs);
        // SAFETY: re-viewing the same dictionary through the untyped alias
        // the property-list API takes; the get-rule retain balances the
        // wrapper.
        unsafe { CFDictionary::wrap_under_get_rule(typed.as_concrete_TypeRef()) }
    }

    // Step 2b's holder side ===========================================================================================

    /// The child side of Step 2b's self re-exec. Calls the PRODUCTION
    /// `engage`, reports readiness, then parks forever — deliberately never
    /// calling `withdraw()` and never returning, so the only way this
    /// process's `Steering` ever goes away is `SIGKILL`, which runs no `Drop`
    /// glue at all. That is the entire point of the probe: it proves the key
    /// dies via the session closing, not via our own cleanup code.
    pub(super) fn run_holder() {
        let resolver = IpAddr::V4(KILLED_PROCESS_RESOLVER);
        match tun_engine::dns_steer::engage(&[resolver]) {
            Ok(steering) => {
                println!("READY key={}", steering.key());
                let _ = io::stdout().flush();
                loop {
                    std::thread::park();
                }
            }
            Err(e) => {
                eprintln!("[holder] engage failed: {e}");
                std::process::exit(2);
            }
        }
    }

    // Step 2: the framework lifetime probe ============================================================================

    /// SHIP GATE (Task 2 Step 2, #868). If this fails, configd does not
    /// honour `session_keys(true)` for a merged DNS entry on a graceful
    /// in-process drop, and D3 is unimplementable as written — **stop and
    /// escalate to Anna**. The fallback (persistent key + owner token +
    /// evidence-gated sweep) is a materially larger design and must not be
    /// improvised; an ungated sweep would violate the resource-ownership
    /// rule this plan carries forward from route ownership.
    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn macos_dns_global_net_state_session_keys_die_with_their_session() {
        let before_dns = scutil_dns();
        let before_nameservers = nameservers(&before_dns);
        println!("[lifetime-probe] before:\n{before_dns}");

        let session = uuid::Uuid::new_v4().to_string();
        let key = format!("State:/Network/Service/{session}/DNS");
        let resolver_str = LIFETIME_PROBE_RESOLVER.to_string();

        let notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");

        let store = SCDynamicStoreBuilder::new("hole-dns-steer-lifetime-probe")
            .session_keys(true)
            .build()
            .expect("HARNESS: open a session_keys(true) SCDynamicStore");

        let dict = build_dictionary(LIFETIME_PROBE_RESOLVER);
        let set_ok = store.set(CFString::new(&key), dict);
        assert!(set_ok, "HARNESS: SCDynamicStore::set failed for {key}");

        let merged = notify.settle(budget(30), &resolver_str, true);
        let merged_dns = scutil_dns();
        println!("[lifetime-probe] after set (merged={merged}):\n{merged_dns}");
        assert!(
            merged,
            "D3 UNIMPLEMENTABLE AS WRITTEN: configd never merged a session_keys(true) key into the \
             derived DNS configuration — stop and escalate to Anna. scutil --dns:\n{merged_dns}"
        );

        // No `.remove()` call — the store handle is simply dropped. This IS
        // the experiment: does the key die with the session on a graceful
        // in-process drop, with zero cooperation beyond letting `store` go
        // out of scope.
        drop(store);

        let unmerged = notify.settle(budget(30), &resolver_str, false);
        let after_dns = scutil_dns();
        let after_nameservers = nameservers(&after_dns);
        println!("[lifetime-probe] after drop (unmerged={unmerged}):\n{after_dns}");

        println!(
            "\n========== macos_dns lifetime-probe VERDICT ==========\n\
             configd merged on set   : {merged}\n\
             configd unmerged on drop: {unmerged}\n\
             ========================================================\n"
        );

        assert!(
            unmerged,
            "D3 UNIMPLEMENTABLE AS WRITTEN: the session key survived the store handle being dropped \
             — stop and escalate to Anna. scutil --dns:\n{after_dns}"
        );
        assert_eq!(
            before_nameservers, after_nameservers,
            "the machine's resolver set changed across the probe; nothing should have moved"
        );
    }

    // Step 2b: the killed-process crash-path probe ====================================================================

    /// SHIP GATE (Task 2 Step 2b, #868). If this fails, a `SIGKILL`ed
    /// process's session key survives it, D3's "no sweep" justification is
    /// false, and the resource-ownership rule in Global Constraints forbids
    /// improvising an ungated sweep to cover the gap — **stop and escalate**.
    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn macos_dns_global_net_state_session_keys_die_with_a_killed_process() {
        let before_dns = scutil_dns();
        let before_nameservers = nameservers(&before_dns);
        println!("[killed-process-probe] before:\n{before_dns}");

        let exe = std::env::current_exe().expect("HARNESS: current_exe");
        let mut child = Command::new(&exe)
            .env(HOLDER_ENV, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("HARNESS: spawn the holder child (self re-exec)");

        // Rendezvous on the child's OWN readiness line — a real event, not a
        // bound.
        let mut stdout = BufReader::new(child.stdout.take().expect("HARNESS: piped stdout"));
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .expect("HARNESS: read the holder child's readiness line");
        assert!(
            line.starts_with("READY"),
            "holder child's first stdout line was not a readiness report: {line:?}"
        );
        println!("[killed-process-probe] holder ready: {}", line.trim_end());

        // Registered AFTER readiness, not before `engage` — sound because
        // `settle` checks the predicate before ever waiting on a
        // notification (see `DnsConfigNotify::settle`'s doc), so an already-
        // merged state by the time we register is still observed correctly.
        let resolver_str = KILLED_PROCESS_RESOLVER.to_string();
        let notify = DnsConfigNotify::register().expect("register for configd's dns_configuration notification");
        let merged = notify.settle(budget(30), &resolver_str, true);
        let merged_dns = scutil_dns();
        println!("[killed-process-probe] after readiness (merged={merged}):\n{merged_dns}");
        assert!(
            merged,
            "PRECONDITION FAILED: the holder child's own `engage()` call never got merged into the \
             DNS configuration, so `SIGKILL` would prove nothing — stop and escalate. \
             scutil --dns:\n{merged_dns}"
        );

        child.kill().expect("HARNESS: SIGKILL the holder child");
        let status = child.wait().expect("HARNESS: reap the killed holder child");
        println!("[killed-process-probe] holder child exit status: {status:?}");

        let unmerged = notify.settle(budget(30), &resolver_str, false);
        let after_dns = scutil_dns();
        let after_nameservers = nameservers(&after_dns);
        println!("[killed-process-probe] after SIGKILL (unmerged={unmerged}):\n{after_dns}");

        let mut stderr = String::new();
        if let Some(mut child_stderr) = child.stderr.take() {
            let _ = child_stderr.read_to_string(&mut stderr);
        }

        println!(
            "\n========== macos_dns killed-process-probe VERDICT ==========\n\
             holder engage merged  : {merged}\n\
             killed via SIGKILL     : true\n\
             configd unmerged       : {unmerged}\n\
             holder stderr          : {stderr:?}\n\
             ==============================================================\n"
        );

        assert!(
            unmerged,
            "D3'S JUSTIFICATION FOR HAVING NO SWEEP IS FALSE: a SIGKILLed process's session key \
             survived it — stop and escalate. scutil --dns:\n{after_dns}\nholder stderr:\n{stderr}"
        );
        assert_eq!(
            before_nameservers, after_nameservers,
            "the machine's resolver set changed across the probe; nothing should have moved"
        );
    }
}
