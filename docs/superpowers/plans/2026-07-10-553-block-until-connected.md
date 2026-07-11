# #553 Block-until-connected (minimal-correct, beta scope) — Implementation Plan

**Goal:** A covered connect that fails leaves the host **blocked, not leaked**,
for as long as the bridge process is alive — closing the widest routine leak
(auto-connect / post-update-reconnect failing mid-start). The user escapes via
Retry or Disconnect.

**Scope:** connect-time only, lockdown-**off** cohort. Reuse the existing
transient fail-closed cover (its first production caller) — no new IPC verb, no
persisted intent, no new recovery seam. The transient cover engages on a covered
start only when the standing lockdown intent is off; a lockdown-armed user's
connect is unchanged from today. Full always-on posture (persisted boot cover,
crash/reboot-durability, cover-abstraction unification) is a tracked follow-up.

**Accepted fail-open windows (all = today's baseline; the user chose
minimal-correct with these shown; each is a keep-open decision, not a silent
defer):**

- pre-login / GUI-launch→Start (no bridge op yet).
- the pre-DoH-resolve instant of a *fresh* covered start (one encrypted DoH RTT
  before the cover engages). A retry while blocked reuses the single held cover
  (no window); a retry to a *different* server runs under it fail-closed (the new
  server is not permitted, so the connect fails and the host stays blocked — the
  user Disconnects to switch servers). Repointing the held cover in place so a
  different-server retry can connect is a tracked follow-up.
- bridge crash while blocked (the existing `recover_cover` sweeps it open on next
  start; standing lockdown is the crash-durable opt-in).
- macOS reboot-durability.
- a covered retry issued *after* the user enabled lockdown while a transient cover
  was held: the held cover is released (warned) and egress is briefly open until
  the standing lockdown cover engages at connect. A rare state-transition edge;
  the clean transient→lockdown handoff is the composable cover in #619.

**Accepted UX scope:** the blocked state is
rendered in the **tray** (status + Retry / Go-Offline); a distinct **dashboard**
blocked indicator is deferred to bindreams/hole#625 (the bridge enforces the
protection and the dashboard truthfully shows "Disconnected", never a false
"Connected"). The user chose minimal-correct / tray-first for the beta.

**Architecture:** The transient cover (`Routing::install_failclosed_cover`,
permit loopback + server, block all else) gains DoH-resolver-IP permits. The
cover is owned in the outer `start_cancellable` scope; DoH resolution is moved
there so `server_ip` is known before the engage; `start_inner` keeps returning
bare `ProxyError` (the cover never crosses its error boundary, so its 14+ error
exits need no change and the retain is un-leakable by construction).

**Tech stack:** Rust (tun-engine WFP/pf, bridge ProxyManager + IPC), TS (webview).

## Global constraints (every task)

- Cover / OS-routing I/O only through the `Routing` trait (clippy
  `disallowed_methods`); changed engage = trait + `SystemRouting` + every mock.
- No `CancellationToken::new()` in `crates/bridge/src`.
- No sleeps / timeout-polls for in-process sync; rendezvous = the
  `routing.install` success edge + the `ProxyStateCell` watch channel.
- Windows WFP: never set `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`; permits weight
  `PERMIT_WEIGHT=15`, block 0, shared sublayer, `FLAG_PERSISTENT`. A
  `RemoteIp(ip)` permit goes on the ONE layer matching the IP's family (v4 →
  ConnectV4, v6 → ConnectV6), mirroring the existing server permit — never both.
  New GUIDs are a fixed budget `cover_resolver_guid(i, is_v6)` for
  `i in 0..MAX_RESOLVERS`, disjoint from all sets AND enumerated by `delete_all`
  so recovery sweeps them (mirror how `swept_lockdown_guids` reaches the App-ID
  GUIDs). Raw FWPM calls `#[allow(clippy::disallowed_methods)]`.
- macOS pf main ruleset is singular; the transient cover loads `-Fa -f -` and
  restores `/etc/pf.conf` on Drop. It never coexists with lockdown here (engaged
  only when lockdown intent off), so no cross-ruleset handoff.
- Tests `#[skuld::test]` + `register!()`; subscribers via
  `garter::tracing_test::set_default_in_current_thread`; privileged real-engage
  gated to the `TUN` lane.
- Blocked-state strings host-free / path-free.

## Cover ownership & lifecycle (the load-bearing contract)

Resolve, engage, and dispose all live in `start_cancellable`; `start_inner` runs
the phases with the OS filters already live.

```
// start_cancellable(config, covered, cancel):
if self.running.is_some() { return Err(AlreadyRunning); }
self.death_reason = None;
let lockdown_on = self.state_dir.as_deref().map(lockdown_state::load_enabled).unwrap_or(false);
// A corrupt/unreadable lockdown-state file resolves to false -> we engage the
// cover: the fail-SAFE direction (blocks rather than leaks).
let want_cover = covered && !lockdown_on;

// Resolve server_ip. If a prior attempt left a cover blocked, resolve UNDER it
// (its resolver permits let the DoH succeed) so a same-server retry never opens
// the host. Only a fresh covered start has the one-RTT pre-resolve window.
let server_ip = Self::resolve_server_ip(config, &bootstrap_querier, &cancel).await
    .inspect_err(|e| self.last_error = Some(e.to_string()))?;

// Engage / reuse the cover for a covered, lockdown-off start.
let cover: Option<R::Cover> = if want_cover {
    match self.blocked_cover.take() {
        // Same server+resolvers as the held cover -> reuse it (no window).
        Some(prev) if prev.covers(server_ip, &config.dns.servers) => Some(prev),
        // Different target -> engage the new one, THEN drop the old (Windows:
        // disjoint GUIDs coexist; macOS: -f - atomically replaces the ruleset).
        Some(prev) => { let c = self.routing.install_failclosed_cover(server_ip, &config.dns.servers); drop(prev); Some(c?) }
        None => Some(self.routing.install_failclosed_cover(server_ip, &config.dns.servers)
                    .inspect_err(|_| warn!("failed to engage fail-closed cover on covered start; host NOT blocked, proceeding open"))?),
    }
} else {
    if let Some(prev) = self.blocked_cover.take() { drop(prev); }  // lockdown now on / uncovered: release
    None
};
let blocking_engaged = cover.is_some();
let result = Self::start_inner(/* … */ server_ip, blocking_engaged, /* … */ cancel).await;
match result {
    Ok(state)                  => { drop(cover); self.running = Some(state); Ok(()) }
    Err(ProxyError::Cancelled) => { drop(cover); Err(ProxyError::Cancelled) }
    Err(e) => { if let Some(c) = cover { self.blocked_cover = Some(c); } self.last_error = Some(e.to_string()); Err(e) }
}
```

- `Cover::covers(server_ip, resolvers) -> bool` is a cheap accessor on the guard
  (the engaged permit set) enabling same-server retry reuse.
- **`stop_with`**: release `blocked_cover` **and** clear `last_error` /
  `death_reason` / the blocked flag **before** the
  `let Some(state) = self.running.take() else { return … }` guard — the blocked
  state is `running == None`, so a Disconnect must both open the host and leave
  the same clean state a normal stop does.
- `blocked_until_connected(&self) -> bool` = `self.blocked_cover.is_some()`.
- `reload` slow path is covered: `stop_with`'s pre-guard release drops the cover;
  the fresh start's engage/reuse block is the second guard.
- Crash while blocked: existing unconditional `recover_cover` sweep opens the
  host on next start (accepted baseline above).

______________________________________________________________________

## Tasks

### Task 1: Transient cover permits resolver IPs — Windows (spec + sweep)

**Files:** modify `crates/tun-engine/src/routing/failclosed/windows.rs`
(`build_cover_spec` ~217, `delete_all` ~884, the GUID budget); test `windows_tests.rs`.
**Produces:** `pub fn build_cover_spec(server_ip: IpAddr, resolver_ips: &[IpAddr]) -> CoverSpec`;
`fn cover_resolver_guid(index: usize, is_v6: bool) -> GUID`; `delete_all` sweeps them.

- [ ] **Step 1 — failing tests:**
  `build_cover_spec_permits_resolver_ips` — build with a v4 + a v6 resolver;
  assert each emits ONE `Permit`/`RemoteIp` filter on the family-matching layer
  only (v4→ConnectV4, v6→ConnectV6), at `PERMIT_WEIGHT`, alongside loopback +
  server permits + weight-0 block. Extend `all_swept_guids_are_mutually_distinct`
  AND `every_emitted_filter_guid_is_in_its_sweep_set` to cover the resolver GUIDs.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** `cover_resolver_guid(i, is_v6)` fixed budget
  `0..MAX_RESOLVERS`; per resolver push one family-matched `permit(...)`; add the
  budget GUIDs to the list `delete_all` iterates (mirror `swept_lockdown_guids`).
- [ ] **Step 4 — run, expect PASS** (incl. both structural invariants).
- [ ] **Step 5 — commit.**

### Task 2: Transient cover permits resolver IPs — macOS ruleset (pure)

**Files:** modify `crates/tun-engine/src/routing/failclosed/macos.rs`
(`build_pf_ruleset` ~38); inline table test.
**Produces:** `pub fn build_pf_ruleset(server_ip: IpAddr, resolver_ips: &[IpAddr]) -> String`.

- [ ] **Step 1 — failing test** `build_pf_ruleset_permits_resolvers` (behavioral,
  mirroring the suite's style — NOT full-string): for server + one resolver (IP
  distinct from server), assert a `pass out quick … to <resolver>` line exists,
  carries `quick`, and its offset precedes the `block out all` default.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** add `resolver_ips`; emit a `pass out quick … to <ip>` per resolver.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit.**

### Task 3: `install_failclosed_cover` resolver arg + `Cover::covers` — facade, trait, mocks

**Files:** modify `crates/tun-engine/src/routing/failclosed.rs` (`engage`,
`Cover::covers`), `crates/tun-engine/src/routing.rs` (trait + `SystemRouting`),
every mock (`ipc_tests.rs`, `proxy_manager_tests.rs`, `foreground_tests.rs`).
**Produces:** `fn install_failclosed_cover(&self, server_ip: IpAddr, resolver_ips: &[IpAddr]) -> Result<Self::Cover, RoutingError>`;
`Cover::covers(&self, server_ip: IpAddr, resolvers: &[IpAddr]) -> bool`.

- [ ] **Step 1 — failing test:** `recover_cover` still sweeps after an engage with
  resolvers (existing behavioral path); mocks record `resolver_ips` +
  `covers`. (The resolver-arg→permit content is proven by Tasks 1/2 on the pure
  builders and by Task 9 on the real engage — no redundant
  `build_cover_spec_for_test` mirror, since the transient engage has no
  resolve-seam to pin, unlike lockdown.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** thread `resolver_ips` through `engage` → builders;
  `Cover::covers` compares the guard's recorded server+resolver set; trait +
  `SystemRouting` + every mock impl.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit.**

### Task 4: `Start.covered` + `Status.blocked_until_connected` (protocol)

**Files:** modify `crates/common/src/protocol.rs`; test `protocol_tests.rs`.

- [ ] **Step 1 — failing test** `start_covered_defaults_false` +
  `status_roundtrips_blocked_flag`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** `Start { …, #[serde(default)] covered: bool }`;
  `Status { …, blocked_until_connected: bool }`; update every construction site
  (grep `Status {` / `Start {`, incl. `tray_tests.rs`, ipc `StatusResponse`).
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit.**

### Task 5: ProxyManager — resolve/engage/subsume/stay-blocked/release

**Files:** modify `crates/bridge/src/proxy_manager.rs`; test `proxy_manager_tests.rs`.
**Produces:** `blocked_until_connected(&self) -> bool`; the ownership contract
above; `blocked_cover: Option<R::Cover>`.

Implementation notes:

- Move DoH resolution (proxy_manager.rs:638-647, with its cancel check) into
  `Self::resolve_server_ip`; give `start_inner` a `server_ip: IpAddr` param.

- **Egress-permit guard (finding 8):** enumerate every outbound connection
  between engage and `routing.install` (977) — plugin onward (→server), ex-ray
  ECH DoH (→`dns.servers`), forwarder self-test (loopback + via SS →server) —
  and confirm each targets only loopback / server / `dns.servers`. Back it with a
  test: assert the built cover's permit set is a superset of the union of those
  targets for a representative config, so a future phase adding an egress to an
  un-permitted IP fails the assertion (not just a prose note).

- **cover_active fold:** `start_inner` gets `blocking_engaged: bool`; predicate
  (~873) = `blocking_engaged || state_dir.map(load_enabled).unwrap_or(false)`.

- Wire the outer contract; `stop_with` pre-guard release + state-clear.

- [ ] **Step 1 — failing tests** (mock counts engage + disengage; harness
  `gate_failure_setup`/`new_manager_with_lockdown` :2441/448):

  - `covered_start_engages_once`; `uncovered_start_never_engages`;
    `covered_start_subsumed_when_lockdown_intent_on`.
  - `covered_start_failure_retains_cover` (`blocked_until_connected()` true).
  - `cancel_releases_cover`; `success_releases_cover`.
  - `user_stop_while_blocked_releases_cover_and_clears_error` (running=None,
    blocked_cover=Some ⇒ dropped, last_error cleared).
  - `same_server_retry_reuses_cover` (no second engage); `different_server_retry_engages_new_before_drop`.
  - `covered_start_without_lockdown_suppresses_probe` **and its control**
    `uncovered_start_runs_probe_rewrites_reason` (mirror the existing
    on/off pair :2464/:2485 — proves suppression is non-vacuous).
  - `cover_permits_all_start_phase_targets` (the egress-permit guard above).

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — implement.**

- [ ] **Step 4 — run, expect PASS:** `cargo nextest run -p hole-bridge`.

- [ ] **Step 5 — commit.**

### Task 6: IPC — plumb `covered`, expose blocked flag

**Files:** modify `crates/bridge/src/ipc.rs`; test `ipc_tests.rs`.

- [ ] **Step 1 — failing test** `handle_start_passes_covered`; `status_exposes_blocked`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** thread `covered` into `start_cancellable`; map
  `blocked_until_connected()` into `StatusResponse`.
- [ ] **Step 4 — run, expect PASS.**
- [ ] **Step 5 — commit.**

### Task 7: GUI state — `blocked_until_connected` through ProxySnapshot

**Files:** modify `crates/hole/src/state.rs`; test `state_tests.rs`.

- [ ] **Step 1 — failing test** `commit_status_carries_blocked`;
  `commit_preserves_blocked`; `blocked_transition_bumps_seq`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** field on `ProxySnapshot` + all three literals;
  `commit_status` sets + change-checks it; `commit` preserves it; `bridge_send`
  Status mapping carries it.
- [ ] **Step 4 — run, expect PASS:** `cargo nextest run -p hole --no-default-features`.
- [ ] **Step 5 — commit.**

### Task 8: GUI — covered latch, blocked-aware reconciler + tray Retry/Disconnect

**Files:** modify `crates/hole/src/tray.rs`, `commands.rs`, `bridge_client.rs`,
`ui/main.ts`, `ui/power-button.ts`; test `tray_tests.rs`.

- Latch path (`connect_silently`/`apply_pending_startup_connect`) sends Start with
  `covered=true`; manual connects `false`.

- `should_apply_pending`: `running:false` + `blocked_until_connected:true` is NOT
  idle-apply (latch already consumed; retry is manual only).

- Blocked tray label (mirror `lockdown_menu_label`) + `ID_BLOCKED_RETRY`
  (covered re-connect) / `ID_BLOCKED_DISCONNECT` (releases → open); widen the TS
  `proxy-state-changed` generic + `applyProxyStateObservation`.

- [ ] **Step 1 — failing tests** `latch_connect_is_covered`;
  `manual_connect_is_uncovered`; `blocked_status_is_not_idle_apply`;
  `blocked_label_offers_retry_disconnect`.

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — implement.**

- [ ] **Step 4 — run, expect PASS** (Rust `-p hole --no-default-features`; TS
  `npm --prefix ui run build && npx --prefix ui vitest run`).

- [ ] **Step 5 — commit.**

### Task 9: Privileged real-engage test (elevated Win + root macOS)

**Files:** extend `failclosed/lockdown_privileged_tests.rs` (or sibling), `TUN`-gated.

- [ ] **Step 1 — failing test** `blocking_cover_blocks_and_releases`: engage the
  REAL cover `(server, resolvers)`; assert egress to a non-permitted IP blocked,
  to a resolver IP allowed; drop releases; then engage + crash-simulate + assert
  `recover_cover` fully sweeps (filters + sublayer + provider gone). Pins the
  no-`CLEAR_ACTION_RIGHT` arbitration + the resolver-GUID sweep budget.
- [ ] **Step 2 — run on the elevated lane, expect FAIL.**
- [ ] **Step 3 — wire.**
- [ ] **Step 4 — run on the elevated lane, expect PASS.**
- [ ] **Step 5 — commit.**

### Wrap

- [ ] Fix the stale `failclosed.rs` / `routing.rs` docstrings describing the
  transient cover as cutover-only → it is now held across the full covered start
  and its permit set must cover all start-phase egress (loopback + server +
  resolvers).
- [ ] Pre-push: `cargo nextest run` + clippy `-D warnings` + fmt; open PR
  (`feat(bridge): block-until-connected fail-closed cover for auto-connect`,
  body `Closes #553`); watch CI green via `gh-ci`. Do NOT merge.

## Follow-ups (filed)

- **bindreams/hole#619** — full always-on posture: persisted boot cover
  (pre-login), crash+reboot durability, generalize the already-multi-cover
  `recover_routes_with` into a reconciler registry, and the macOS composable
  cover. This subsumes the accepted fail-open windows above (pre-login,
  pre-DoH-resolve instant, crash-sweeps-open, macOS reboot) **and** the
  different-server-retry in-place repoint (so a Retry to a new server can connect
  without a Disconnect-first).
- **bindreams/hole#625** — distinct dashboard blocked-state rendering (tray-only
  today).
- macOS lockdown reboot-durability (`Adopt` re-enables nothing) — **#617**.
- macOS lockdown ruleset omits resolver permits → adopted-cover reconnect wedges
  the DoH bootstrap — **#618**.
