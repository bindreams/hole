// Unit tests for the extracted toggle-flow module. The key invariant
// tested here is the absence of a client-side `cancel_proxy` timer:
// pre-#397 sub-bug C, `toggleFromIdle` raced toggle_proxy against a
// 15 s setTimeout and fired cancel_proxy on its own initiative,
// producing a false-failure UI on slow-but-working starts. After the
// fix the UI stays in `connecting` until the bridge IPC returns; the
// user's Cancel button is the only escape hatch.
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
    // Cast: Vitest's Mock<G> for a generic-typed signature G erases the
    // generic at the Mock-typed value, so the result type widens to
    // Promise<unknown> at the call site. Asserting back to the original
    // generic shape is the standard escape hatch — the actual runtime
    // behavior is unaffected; we're just informing tsc that this Mock
    // honors the generic signature for production assertion purposes.
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
  it("schedules NO timers and fires no cancel_proxy while toggle_proxy is pending", async () => {
    // toggle_proxy resolves never — simulates a slow-but-working bridge
    // start where the IPC eventually returns Ok but takes longer than
    // the OLD 15 s client timer. Pre-fix this would have spuriously
    // fired cancel_proxy. Post-fix the UI just stays in `connecting`.
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "toggle_proxy") return new Promise(() => {});
      return Promise.resolve();
    });

    // Kick off the toggle. We deliberately don't await — toggle_proxy
    // never resolves. The promise hangs in the background; we observe
    // side effects.
    void toggleFromIdle(true, h.deps);

    // Let the synchronous prelude (setState("connecting")) run.
    await Promise.resolve();
    expect(h.state).toBe("connecting");

    // STRUCTURAL ASSERTION (CLAUDE.md memory "no heuristic checks"):
    // assert that toggleFromIdle scheduled ZERO pending timers after
    // its synchronous prelude. This is invariant to threshold — a
    // future PR that re-introduces a 35 s (or any other duration)
    // client-side timer would fail this check immediately, with no
    // dependence on a magic "advance for X ms then look" number.
    expect(vi.getTimerCount()).toBe(0);

    // The in-flight toggle_proxy promise never resolves, so no further
    // setState/showToast/invoke side effects can fire from this code
    // path. State and toast surface should match the prelude.
    expect(h.state).toBe("connecting");
    expect(h.showToast).not.toHaveBeenCalled();
  });

  it("symmetric: no timers + no cancel_proxy during a slow disconnect", async () => {
    const h = makeHarness();
    h.state = "connected";
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "toggle_proxy") return new Promise(() => {});
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
      if (cmd === "toggle_proxy") return Promise.resolve("running");
      return Promise.resolve();
    });
    await toggleFromIdle(true, h.deps);
    expect(h.state).toBe("connected");
    expect(h.updatePublicIp).toHaveBeenCalled();
  });

  it("surfaces a bridge error via toast + transitions to `connection-failed`", async () => {
    const h = makeHarness();
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "toggle_proxy") return Promise.reject("forwarder self-test failed");
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
      if (cmd === "toggle_proxy") return Promise.reject("teardown wedged");
      return Promise.resolve();
    });
    await toggleFromIdle(false, h.deps);
    expect(h.state).toBe("disconnection-failed");
    expect(h.showToast).toHaveBeenCalledWith("teardown wedged", "error");
  });

  it("fires follow-up stop when Cancel raced with a successful Start", async () => {
    // The bridge returned Running BEFORE the user's Cancel reached it.
    // toggleFromIdle observes getState() === "cancelling" and outcome
    // === "running", and fires a follow-up Stop to honor the user's
    // cancel intent.
    const h = makeHarness();
    let toggleCalls = 0;
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === "toggle_proxy") {
        toggleCalls++;
        // First call (the Start) returns Running after the user
        // clicked Cancel (test simulates this by mutating state below).
        // Second call (the follow-up Stop) returns Stopped.
        return Promise.resolve(toggleCalls === 1 ? "running" : "stopped");
      }
      return Promise.resolve();
    });

    // Kick off the start, then simulate the user clicking Cancel while
    // the start is in-flight.
    const togglePromise = toggleFromIdle(true, h.deps);
    // The promise's first setState("connecting") runs synchronously
    // (before any await). We mutate the state directly to simulate the
    // user's Cancel-button-click side effect (which would normally call
    // setState("cancelling")).
    h.state = "cancelling";
    await togglePromise;

    // The follow-up Stop was fired (two toggle_proxy calls total).
    expect(toggleCalls).toBe(2);
    // Final state honors the user's cancel intent: Stopped → disconnected.
    expect(h.state).toBe("disconnected");
  });
});
