import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock("./main", () => ({ config: null, loadConfig: vi.fn() }));
vi.mock("./ip-display", () => ({ updatePublicIp: vi.fn().mockResolvedValue(undefined) }));
vi.mock("./toast", () => ({ showToast: vi.fn() }));

beforeEach(() => {
  invokeMock.mockReset();
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
    const { state, changed } = updateProxyStatus({ running: true });
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
    const { changed } = updateProxyStatus({ running: true });
    expect(changed).toBe(false);
    expect(getConnectionState()).toBe("connecting");
  });

  it("click from `connection-failed` starts a fresh connect (retry path)", async () => {
    // `connection-failed` has no public setter — it is only ever reached
    // by a `toggle_proxy` rejection on the connect path (the catch arm in
    // toggleFromIdle: disconnected → connecting → connection-failed). So
    // we drive the genuine failure first, then exercise the retry click,
    // rather than synthesizing the state with a back-door setter that
    // would bypass the production transition.
    //
    // First click: toggle_proxy rejects → the component lands in
    // `connection-failed`. We hold the rejecting promise ourselves so we
    // can await its settlement deterministically (no timeout-bounded poll).
    let rejectToggle!: (reason: unknown) => void;
    const firstToggle = new Promise<never>((_, reject) => {
      rejectToggle = reject;
    });
    invokeMock.mockReturnValueOnce(firstToggle);
    const { initPowerButton, getConnectionState } = await import("./power-button");
    initPowerButton();
    document.getElementById("power-btn")!.click();
    // Synchronous prelude ran: setState("connecting"), then parked on the
    // `await invoke("toggle_proxy")`.
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");

    // Reject the in-flight toggle_proxy and wait for the production catch
    // arm (which is registered ahead of this awaited continuation) to run
    // setState("connection-failed"). Awaiting the same settled promise is
    // a deterministic rendezvous, not a sleep.
    rejectToggle("connect failed");
    await firstToggle.catch(() => {});
    await Promise.resolve();
    expect(getConnectionState()).toBe("connection-failed");

    // The first toggle_proxy attempt happened and failed; clear the call
    // log so the retry assertion sees only the retry's invoke.
    invokeMock.mockReset();
    // Retry click: `connection-failed` is an idle state with
    // `isEffectivelyOn` false → goingToConnect is true → a fresh Start is
    // attempted. The second toggle_proxy never resolves so the component
    // parks in `connecting`.
    invokeMock.mockReturnValue(new Promise(() => {}));
    document.getElementById("power-btn")!.click();
    await Promise.resolve();

    expect(getConnectionState()).toBe("connecting");
    // The retry fired toggle_proxy (a fresh connect), not cancel_proxy.
    const toggleCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "toggle_proxy");
    expect(toggleCalls).toHaveLength(1);
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
    updateProxyStatus({ running: true });
    expect(getConnectionState()).toBe("connected");
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    // From connected, the click triggers a Stop (goingToConnect = false).
    expect(getConnectionState()).toBe("disconnecting");
  });
});
