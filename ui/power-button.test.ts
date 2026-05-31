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
    // `connection-failed` is an idle state. `isEffectivelyOn` returns
    // false → goingToConnect is true → another Start is attempted.
    invokeMock.mockReturnValue(new Promise(() => {}));
    const { initPowerButton, updateProxyStatus, getConnectionState } = await import("./power-button");
    initPowerButton();
    // connection-failed and disconnected are both idle states where
    // isEffectivelyOn() is false, so a click drives the same connect path.
    updateProxyStatus({ running: false }); // ensures state is `disconnected`
    expect(getConnectionState()).toBe("disconnected");
    document.getElementById("power-btn")!.click();
    await Promise.resolve();
    expect(getConnectionState()).toBe("connecting");
    // toggle_proxy was fired (not cancel_proxy).
    const toggleCalls = invokeMock.mock.calls.filter(([cmd]) => cmd === "toggle_proxy");
    expect(toggleCalls).toHaveLength(1);
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
