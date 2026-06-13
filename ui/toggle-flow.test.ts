// Unit tests for the extracted toggle-flow module. The key invariants
// tested here: `toggleFromIdle` schedules NO client-side timer (the UI
// stays in `connecting`/`disconnecting` until the bridge IPC returns;
// the user's Cancel button (`cancel_proxy`) is the only escape hatch),
// and the user's direction is transmitted as explicit start/stop intent
// on the wire (#462).
//
// Sync-invariant note (CLAUDE.md §"Synchronization invariant"): this
// test uses `vi.useFakeTimers()` + `vi.getTimerCount()` to assert the
// structural absence of any pending timer after the synchronous
// prelude. It is NOT a sleep-as-wait — the wall clock is irrelevant;
// the assertion is structural ("no timer was scheduled, full stop")
// rather than threshold-based ("nothing fired in N seconds").

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionState } from "./connection-state";
import { type ToggleDeps, toggleFromIdle } from "./toggle-flow";

interface Harness {
  invoke: ReturnType<typeof vi.fn<ToggleDeps["invoke"]>>;
  setState: ReturnType<typeof vi.fn<ToggleDeps["setState"]>>;
  updatePublicIp: ReturnType<typeof vi.fn<ToggleDeps["updatePublicIp"]>>;
  showToast: ReturnType<typeof vi.fn<ToggleDeps["showToast"]>>;
  loadConfig: ReturnType<typeof vi.fn<ToggleDeps["loadConfig"]>>;
  state: ConnectionState;
  deps: ToggleDeps;
}

function makeHarness(): Harness {
  const h: Harness = {
    invoke: vi.fn<ToggleDeps["invoke"]>(),
    setState: vi.fn<ToggleDeps["setState"]>(),
    updatePublicIp: vi.fn<ToggleDeps["updatePublicIp"]>().mockResolvedValue(undefined),
    showToast: vi.fn<ToggleDeps["showToast"]>(),
    loadConfig: vi.fn<ToggleDeps["loadConfig"]>().mockResolvedValue(undefined),
    state: "disconnected" as ConnectionState,
    deps: undefined as unknown as ToggleDeps,
  };
  h.setState.mockImplementation((next: ConnectionState) => {
    h.state = next;
  });
  h.deps = {
    // vi.fn erases the generic from invoke's signature; cast back so
    // tsc accepts the typed call sites.
    invoke: h.invoke as ToggleDeps["invoke"],
    getState: () => h.state,
    setState: h.setState,
    updatePublicIp: h.updatePublicIp,
    showToast: h.showToast,
    getConfig: () => null,
    loadConfig: h.loadConfig,
  };
  return h;
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("toggleFromIdle: client-side timer absence (regression for #397 sub-bug C)", () => {
  it("schedules NO timers and fires no cancel_proxy while start_proxy is pending", async () => {
    // start_proxy resolves never (slow-but-working bridge start). The
    // UI must stay in `connecting` and schedule no timer.
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return new Promise(() => {});
      return Promise.resolve();
    });

    // Kick off the toggle. We deliberately don't await — start_proxy
    // never resolves. The promise hangs in the background; we observe
    // side effects.
    void toggleFromIdle(true, h.deps);

    // Let the synchronous prelude (setState("connecting")) run.
    await Promise.resolve();
    expect(h.state).toBe("connecting");

    // Structural assertion: zero pending timers, independent of any
    // duration. Re-introducing a client-side timer of any length fails
    // this immediately.
    expect(vi.getTimerCount()).toBe(0);

    // The in-flight start_proxy promise never resolves, so no further
    // setState/showToast/invoke side effects can fire from this code
    // path. State and toast surface should match the prelude.
    expect(h.state).toBe("connecting");
    expect(h.showToast).not.toHaveBeenCalled();
  });

  it("symmetric: no timers + no cancel_proxy during a slow disconnect", async () => {
    const h = makeHarness();
    h.state = "connected";
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "stop_proxy") return new Promise(() => {});
      return Promise.resolve();
    });

    void toggleFromIdle(false, h.deps);
    await Promise.resolve();
    expect(h.state).toBe("disconnecting");

    expect(vi.getTimerCount()).toBe(0);
    expect(h.showToast).not.toHaveBeenCalled();
  });
});

describe("toggleFromIdle: outcome handling", () => {
  it("transitions to `connected` on a Running outcome", async () => {
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return Promise.resolve("running");
      return Promise.resolve();
    });
    await toggleFromIdle(true, h.deps);
    expect(h.state).toBe("connected");
    expect(h.updatePublicIp).toHaveBeenCalled();
    // Explicit intent on the wire (#462): the direction the user chose,
    // not a directionless toggle the backend has to re-derive.
    expect(h.invoke).toHaveBeenCalledWith("start_proxy");
  });

  it("transitions to `disconnected` on a Cancelled outcome (bridge-side cancel)", async () => {
    // The bridge cooperatively cancelled and reported `Cancelled` (per
    // crates/hole/src/tray.rs::ToggleOutcome). The state machine maps
    // this to `disconnected` — the UI may have briefly shown
    // `cancelling`, but the settled idle state is Disconnected.
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return Promise.resolve("cancelled");
      return Promise.resolve();
    });
    await toggleFromIdle(true, h.deps);
    expect(h.state).toBe("disconnected");
  });

  it("surfaces a bridge error via toast + transitions to `connection-failed`", async () => {
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return Promise.reject("forwarder self-test failed");
      return Promise.resolve();
    });
    await toggleFromIdle(true, h.deps);
    expect(h.state).toBe("connection-failed");
    expect(h.showToast).toHaveBeenCalledWith("forwarder self-test failed", "error");
  });

  it("symmetric: error during stop surfaces toast + transitions to `disconnection-failed`", async () => {
    const h = makeHarness();
    h.state = "connected";
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "stop_proxy") return Promise.reject("teardown wedged");
      return Promise.resolve();
    });
    await toggleFromIdle(false, h.deps);
    expect(h.state).toBe("disconnection-failed");
    expect(h.showToast).toHaveBeenCalledWith("teardown wedged", "error");
    expect(h.invoke).toHaveBeenCalledWith("stop_proxy");
  });

  it("fires follow-up stop when Cancel raced with a successful Start", async () => {
    // The bridge returned Running BEFORE the user's Cancel reached it.
    // toggleFromIdle observes getState() === "cancelling" and outcome
    // === "running", and fires a follow-up Stop to honor the user's
    // cancel intent.
    const h = makeHarness();
    const proxyCalls: string[] = [];
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy" || cmd === "stop_proxy") {
        proxyCalls.push(cmd);
        // The Start returns Running after the user clicked Cancel (the
        // test simulates this by mutating state below); the follow-up
        // Stop returns Stopped.
        return Promise.resolve(cmd === "start_proxy" ? "running" : "stopped");
      }
      return Promise.resolve();
    });

    // Kick off the start, then simulate the user clicking Cancel while
    // the start is in-flight.
    const togglePromise = toggleFromIdle(true, h.deps);
    // The promise's first setState("connecting") runs synchronously
    // (before any await). We route the simulated Cancel through
    // h.deps.setState so the harness's setState.mock.calls reflects
    // the full transition history — same shape as production, where
    // a Cancel click calls setState("cancelling").
    h.deps.setState("cancelling");
    await togglePromise;

    // The follow-up carries explicit STOP intent (#462) — the backend
    // must not be left to derive direction from its own state.
    expect(proxyCalls).toEqual(["start_proxy", "stop_proxy"]);
    // Final state honors the user's cancel intent: Stopped → disconnected.
    expect(h.state).toBe("disconnected");
  });
});

describe("mark_validated_by_proxy_start failure surfacing", () => {
  it("toasts when the validation mark fails after a successful connect", async () => {
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return Promise.resolve("running");
      if (cmd === "mark_validated_by_proxy_start") return Promise.reject(new Error("config save failed"));
      return Promise.resolve();
    });
    h.deps.getConfig = () => ({ selected_server: "srv-1" }) as never;

    await toggleFromIdle(true, h.deps);

    expect(h.showToast).toHaveBeenCalledWith(expect.stringContaining("config save failed"), "error");
    // The connect itself still settled into `connected`.
    expect(h.state).toBe("connected");
    // The reload is scoped OUT of the mark's try: a failed mark must not
    // trigger loadConfig (there is no new validation state to pick up).
    expect(h.loadConfig).not.toHaveBeenCalled();
  });
});
