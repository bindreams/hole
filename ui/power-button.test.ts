import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ProxyStatus } from "./types";

const invokeMock = vi.fn();
const showToastMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./main", () => ({ config: null, loadConfig: vi.fn() }));
vi.mock("./ip-display", () => ({ updatePublicIp: vi.fn().mockResolvedValue(undefined) }));
vi.mock("./toast", () => ({ showToast: (...args: unknown[]) => showToastMock(...args) }));

/// Build a full `ProxyStatus` from the fields a test cares about; the rest
/// default to the "nothing to surface" shape (no error, no invalid filters,
/// unknown caps).
function fullStatus(o: Partial<ProxyStatus> & { running: boolean; state_seq: number }): ProxyStatus {
  return {
    uptime_secs: 0,
    error: null,
    invalid_filters: [],
    udp_proxy_available: null,
    ipv6_bypass_available: null,
    ...o,
  };
}

beforeEach(() => {
  invokeMock.mockReset();
  showToastMock.mockReset();
  document.body.innerHTML = `<button id="power-btn"></button><span id="status-word"></span>`;
  vi.resetModules();
});

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
    const { state, changed } = updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
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
    const { changed } = updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
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
    const { changed } = updateProxyStatus(fullStatus({ running: false, state_seq: 2 })); // stale poll
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
    updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
    expect(getConnectionState()).toBe("connected");
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    // From connected, the click triggers a Stop (goingToConnect = false).
    expect(getConnectionState()).toBe("disconnecting");
  });

  // Death-error toast (#470): exactly once on a genuine connected->stopped
  // transition that carries a reason, fed by BOTH the poll and the event.
  it("toasts once on a death (connected -> disconnected carrying an error)", async () => {
    const { initPowerButton, updateProxyStatus } = await import("./power-button");
    initPowerButton();
    updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
    updateProxyStatus(fullStatus({ running: false, state_seq: 2, error: "proxy task exited unexpectedly" }));
    expect(showToastMock).toHaveBeenCalledTimes(1);
    expect(showToastMock).toHaveBeenCalledWith("proxy task exited unexpectedly", "error");
  });

  it("does not re-toast on a re-observation of the same death (frozen seq)", async () => {
    const { initPowerButton, updateProxyStatus } = await import("./power-button");
    initPowerButton();
    updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
    updateProxyStatus(fullStatus({ running: false, state_seq: 2, error: "boom" }));
    updateProxyStatus(fullStatus({ running: false, state_seq: 2, error: "boom" }));
    expect(showToastMock).toHaveBeenCalledTimes(1);
  });

  it("toasts when the death is seen only via the event (tray reconciler committed it)", async () => {
    const { initPowerButton, applyProxyStateObservation } = await import("./power-button");
    initPowerButton();
    applyProxyStateObservation(1, true); // connected, observed via event
    applyProxyStateObservation(2, false, "proxy task exited unexpectedly"); // death via event
    expect(showToastMock).toHaveBeenCalledTimes(1);
    expect(showToastMock).toHaveBeenCalledWith("proxy task exited unexpectedly", "error");
  });

  it("does not double-toast when the event wins then the poll re-reports", async () => {
    const { initPowerButton, applyProxyStateObservation, updateProxyStatus } = await import("./power-button");
    initPowerButton();
    applyProxyStateObservation(1, true);
    applyProxyStateObservation(2, false, "boom"); // event applies the death
    updateProxyStatus(fullStatus({ running: false, state_seq: 2, error: "boom" })); // poll re-reports
    expect(showToastMock).toHaveBeenCalledTimes(1);
  });

  it("does not toast on a clean stop (error null)", async () => {
    const { initPowerButton, updateProxyStatus } = await import("./power-button");
    initPowerButton();
    updateProxyStatus(fullStatus({ running: true, state_seq: 1 }));
    updateProxyStatus(fullStatus({ running: false, state_seq: 2, error: null }));
    expect(showToastMock).not.toHaveBeenCalled();
  });

  it("does not toast on startup into an already-dead bridge (no transition)", async () => {
    const { initPowerButton, updateProxyStatus } = await import("./power-button");
    initPowerButton(); // starts 'disconnected'
    updateProxyStatus(fullStatus({ running: false, state_seq: 0, error: "proxy task exited unexpectedly" }));
    expect(showToastMock).not.toHaveBeenCalled();
  });

  it("does not toast on a stop observed while in a transition state", async () => {
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click(); // -> connecting (transition)
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");
    updateProxyStatus(fullStatus({ running: false, state_seq: 5, error: "boom" }));
    expect(showToastMock).not.toHaveBeenCalled();
    expect(getConnectionState()).toBe("connecting");
  });

  it("toasts on disconnection-failed -> disconnected with an error (a failed-stop proxy then dies)", async () => {
    // disconnection-failed is an "on" state (proxy still up after a failed
    // stop). If it then dies, the transition into disconnected is a genuine
    // death and must toast.
    let rejectStop!: (reason: unknown) => void;
    const stopPromise = new Promise<never>((_, reject) => {
      rejectStop = reject;
    });
    const { initPowerButton, applyProxyStateObservation, updateProxyStatus, getConnectionState } = await import(
      "./power-button"
    );
    initPowerButton();
    applyProxyStateObservation(3, true);
    invokeMock.mockReturnValueOnce(stopPromise);
    document.getElementById("power-btn")!.click(); // -> disconnecting
    await Promise.resolve();
    rejectStop("teardown wedged");
    await stopPromise.catch(() => {});
    await Promise.resolve();
    expect(getConnectionState()).toBe("disconnection-failed");
    showToastMock.mockClear();

    updateProxyStatus(fullStatus({ running: false, state_seq: 4, error: "proxy task exited unexpectedly" }));
    expect(showToastMock).toHaveBeenCalledTimes(1);
    expect(showToastMock).toHaveBeenCalledWith("proxy task exited unexpectedly", "error");
  });

  it("does not toast on connection-failed -> disconnected with an error (wasOn gate)", async () => {
    // Drive the genuine `connection-failed` via a rejected start (no back-door
    // setter), then a poll observes running=false carrying an error. Because
    // the prior state was OFF (connection-failed), this is not a death and
    // must not toast.
    let rejectStart!: (reason: unknown) => void;
    const firstStart = new Promise<never>((_, reject) => {
      rejectStart = reject;
    });
    invokeMock.mockReturnValueOnce(firstStart);
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    rejectStart("connect failed");
    await firstStart.catch(() => {});
    await Promise.resolve();
    expect(getConnectionState()).toBe("connection-failed");

    // The toggle flow already toasted the start failure; isolate the assertion
    // to whether the subsequent poll observation toasts (it must not).
    showToastMock.mockClear();
    updateProxyStatus(fullStatus({ running: false, state_seq: 7, error: "stale reason" }));
    expect(showToastMock).not.toHaveBeenCalled();
  });
});
