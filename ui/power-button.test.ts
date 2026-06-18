import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./main", () => ({ config: null, loadConfig: vi.fn() }));
vi.mock("./ip-display", () => ({ updatePublicIp: vi.fn().mockResolvedValue(undefined) }));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

beforeEach(() => {
  // vi.resetModules() does NOT re-run the vi.mock factories, so the showToast /
  // updatePublicIp mock fns persist across tests and accumulate calls. Clear all
  // mock call history each test so toast assertions are load-bearing.
  vi.clearAllMocks();
  invokeMock.mockReset();
  document.body.innerHTML = `<button id="power-btn"></button><span id="status-word"></span>`;
  vi.resetModules();
});

// Drain a bounded microtask chain deterministically (no timers) so a settled
// invoke's continuation runs before the assertion.
const flush = async () => {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
};

describe("power-button state machine", () => {
  it("starts in `disconnected`", async () => {
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    expect(getConnectionState()).toBe("disconnected");
  });

  it("transitions to `connecting` on click from `disconnected`", async () => {
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");
  });

  it("transitions to `cancelling` and fires cancel_proxy on click from `connecting`", async () => {
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    // Now in `connecting`; click again.
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("cancelling");
    const cancelCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "cancel_proxy");
    expect(cancelCalls).toHaveLength(1);
  });

  it("updateProxyStatus writes through when current state is idle", async () => {
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    const { state, changed } = updateProxyStatus({ running: true, state_seq: 1 });
    expect(state).toBe("connected");
    expect(changed).toBe(true);
    expect(getConnectionState()).toBe("connected");
  });

  it("updateProxyStatus is a no-op when current state is a transition", async () => {
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    // Now in `connecting`.
    const { changed } = updateProxyStatus({ running: true, state_seq: 1 });
    expect(changed).toBe(false);
    expect(getConnectionState()).toBe("connecting");
  });

  it("drops out-of-order observations (#462: poll and event interleave arbitrarily)", async () => {
    const { initPowerButton, applyProxyStateObservation, getConnectionState } = await import("./power-button");
    initPowerButton();
    applyProxyStateObservation(2, true);
    expect(getConnectionState()).toBe("connected");
    // A poll response computed before the seq-2 commit arrives late:
    applyProxyStateObservation(1, false);
    expect(getConnectionState()).toBe("connected");
  });

  it("event and poll share the seq gate", async () => {
    const { initPowerButton, applyProxyStateObservation, updateProxyStatus, getConnectionState } = await import(
      "./power-button"
    );
    initPowerButton();
    applyProxyStateObservation(3, true); // proxy-state-changed event
    expect(getConnectionState()).toBe("connected");
    const { changed } = updateProxyStatus({ running: false, state_seq: 2 }); // stale poll
    expect(changed).toBe(false);
    expect(getConnectionState()).toBe("connected");
  });

  it("a same-seq re-observation does not clobber a failure cue", async () => {
    // After a failed stop the component shows `disconnection-failed`
    // while the bridge still reports the same (seq, running=true)
    // observation. The seq gate keeps the failure cue visible until the
    // state actually CHANGES (a new seq), instead of repainting it to
    // plain `connected` on the next 5s poll.
    let rejectStop!: (reason: unknown) => void;
    const stopPromise = new Promise<never>((_, reject) => {
      rejectStop = reject;
    });
    const { initPowerButton, applyProxyStateObservation, getConnectionState } = await import("./power-button");
    initPowerButton();
    applyProxyStateObservation(3, true);
    expect(getConnectionState()).toBe("connected");

    invokeMock.mockReturnValueOnce(stopPromise);
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnecting");
    rejectStop("teardown wedged");
    await stopPromise.catch(() => {});
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnection-failed");

    // The next poll re-reports the unchanged truth (still seq 3, still
    // running) — it must not erase the failure cue.
    applyProxyStateObservation(3, true);
    expect(getConnectionState()).toBe("disconnection-failed");
  });

  it("click from `connection-failed` starts a fresh connect (retry path)", async () => {
    // `connection-failed` has no public setter — it is only ever reached
    // by a `start_proxy` rejection on the connect path (the catch arm in
    // toggleFromIdle: disconnected → connecting → connection-failed). So
    // we drive the genuine failure first, then exercise the retry click,
    // rather than synthesizing the state with a back-door setter that
    // would bypass the production transition.
    //
    // First click: start_proxy rejects → the component lands in
    // `connection-failed`. We hold the rejecting promise ourselves so we
    // can await its settlement deterministically (no timeout-bounded poll).
    let rejectStart!: (reason: unknown) => void;
    const firstStart = new Promise<never>((_, reject) => {
      rejectStart = reject;
    });
    invokeMock.mockReturnValueOnce(firstStart);
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    // Synchronous prelude ran: setState("connecting"), then parked on the
    // `await invoke("start_proxy")`.
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");

    // Reject the in-flight start_proxy and wait for the production catch
    // arm (which is registered ahead of this awaited continuation) to run
    // setState("connection-failed"). Awaiting the same settled promise is
    // a deterministic rendezvous, not a sleep.
    rejectStart("connect failed");
    await firstStart.catch(() => {});
    await Promise.resolve();
    expect(getConnectionState()).toBe("connection-failed");

    // The first start_proxy attempt happened and failed; clear the call
    // log so the retry assertion sees only the retry's invoke.
    invokeMock.mockReset();
    // Retry click: `connection-failed` is an idle state with
    // `isEffectivelyOn` false → goingToConnect is true → a fresh Start is
    // attempted. The second start_proxy never resolves so the component
    // parks in `connecting`.
    invokeMock.mockReturnValue(new Promise(() => {}));
    document.getElementById("power-btn")!.click();
    await Promise.resolve();

    expect(getConnectionState()).toBe("connecting");
    // The retry fired start_proxy (a fresh connect), not cancel_proxy.
    const startCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "start_proxy");
    expect(startCalls).toHaveLength(1);
    const cancelCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "cancel_proxy");
    expect(cancelCalls).toHaveLength(0);
  });

  it("click from `disconnection-failed` starts a stop (isEffectivelyOn returns true)", async () => {
    // `disconnection-failed` is the failed-stop idle state. The proxy
    // is still up. `isEffectivelyOn` returns true → goingToConnect
    // is false → the next click attempts another Stop.
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    // Drive to connected first via polling.
    updateProxyStatus({ running: true, state_seq: 1 });
    expect(getConnectionState()).toBe("connected");
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    // From connected, the click triggers a Stop (goingToConnect = false).
    expect(getConnectionState()).toBe("disconnecting");
  });
});

describe("power-button wedge escape (#471)", () => {
  it("cancel_proxy rejection escapes cancelling to connection-failed with a toast", async () => {
    let rejectCancel!: (e: unknown) => void;
    const cancelP = new Promise<never>((_, rej) => {
      rejectCancel = rej;
    });
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return new Promise(() => {}); // never settles
      if (cmd === "cancel_proxy") return cancelP;
      return Promise.resolve();
    });
    const { initPowerButton, getConnectionState } = await import("./power-button");
    const toast = await import("./toast");
    initPowerButton();
    const btn = document.getElementById("power-btn")!;
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("cancelling");

    rejectCancel("bridge unreachable");
    await cancelP.catch(() => {});
    await flush();
    expect(getConnectionState()).toBe("connection-failed");
    expect(toast.showToast).toHaveBeenCalledWith(
      "Couldn't reach the bridge to cancel. The connection may still come up — try again.",
      "error",
    );

    // The escaped state is interactive: a click starts a fresh connect.
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");
  });

  it("a click escapes a wedged cancelling; the late start is fenced, then the gate reconciles", async () => {
    let resolveStart!: (v: string) => void;
    const startP = new Promise<string>((res) => {
      resolveStart = res;
    });
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return startP;
      if (cmd === "cancel_proxy") return new Promise(() => {}); // cancel hangs too
      return Promise.resolve();
    });
    const { initPowerButton, getConnectionState, applyProxyStateObservation } = await import("./power-button");
    const toast = await import("./toast");
    initPowerButton();
    const btn = document.getElementById("power-btn")!;
    btn.click();
    await Promise.resolve();
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("cancelling");
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("connection-failed");
    expect(toast.showToast).toHaveBeenCalledWith(
      "Cancelling is taking too long. The connection may still come up — try again.",
      "error",
    );

    // The wedged start finally resolves running — fenced, no state change.
    resolveStart("running");
    await startP;
    await flush();
    expect(getConnectionState()).toBe("connection-failed");

    // The authoritative observation reconciles the now-idle state to the truth.
    applyProxyStateObservation(1, true);
    expect(getConnectionState()).toBe("connected");
  });

  it("a click escapes a wedged disconnecting; the late stop is fenced, then the gate reconciles", async () => {
    let resolveStop!: (v: string) => void;
    const stopP = new Promise<string>((res) => {
      resolveStop = res;
    });
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === "stop_proxy") return stopP;
      return Promise.resolve();
    });
    const { initPowerButton, getConnectionState, updateProxyStatus, applyProxyStateObservation } = await import(
      "./power-button"
    );
    const toast = await import("./toast");
    initPowerButton();
    updateProxyStatus({ running: true, state_seq: 1 });
    expect(getConnectionState()).toBe("connected");
    const btn = document.getElementById("power-btn")!;
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnecting");
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnection-failed");
    expect(toast.showToast).toHaveBeenCalledWith(
      "Disconnecting is taking too long. The proxy may still be active — try again.",
      "error",
    );

    // The wedged stop finally resolves stopped — fenced, no state change.
    resolveStop("stopped");
    await stopP;
    await flush();
    expect(getConnectionState()).toBe("disconnection-failed");

    // Bridge eventually reports stopped (new seq) — the gate reconciles.
    applyProxyStateObservation(2, false);
    expect(getConnectionState()).toBe("disconnected");
  });

  it("a cancel rejection that lands after the state left cancelling does not clobber", async () => {
    let resolveStart!: (v: string) => void;
    const startP = new Promise<string>((res) => {
      resolveStart = res;
    });
    let resolveStop!: (v: string) => void;
    const stopP = new Promise<string>((res) => {
      resolveStop = res;
    });
    let rejectCancel!: (e: unknown) => void;
    const cancelP = new Promise<never>((_, rej) => {
      rejectCancel = rej;
    });
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === "start_proxy") return startP;
      if (cmd === "stop_proxy") return stopP;
      if (cmd === "cancel_proxy") return cancelP;
      return Promise.resolve();
    });
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    const btn = document.getElementById("power-btn")!;
    btn.click();
    await Promise.resolve();
    btn.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("cancelling");

    // Start succeeded at the bridge → the cancel-race arm fires a follow-up stop.
    resolveStart("running");
    await startP;
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnecting");
    resolveStop("stopped");
    await stopP;
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnected");

    // The cancel now rejects — the guard suppresses any revert.
    rejectCancel("late");
    await cancelP.catch(() => {});
    await flush();
    expect(getConnectionState()).toBe("disconnected");
  });
});
