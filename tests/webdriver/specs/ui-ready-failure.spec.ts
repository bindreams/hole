// The harness has to be able to fail. A UI that reports a failed `init()`
// must surface as the handshake's own error, on the first look — not as a
// driver error after the request has been silently re-sent, and never as a
// pass because a later attempt came back clean.

import { assertUiReady } from "../ui-ready";

interface Probe extends Window {
  __bridgeCalls: number;
  __realUiReady?: Window["__holeUiReady"];
}

describe("UI-ready failure reporting", () => {
  beforeEach(async () => {
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__realUiReady = w.__holeUiReady;
      w.__bridgeCalls = 0;
    });
  });

  afterEach(async () => {
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__holeUiReady = w.__realUiReady;
    });
  });

  it("reports a failed init as its own error, without re-asking", async () => {
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__holeUiReady = () => {
        w.__bridgeCalls++;
        return Promise.resolve({ ok: false, error: "injected init failure" });
      };
    });

    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );

    expect(thrown?.message).toBe("UI init failed: injected init failure");
    expect(await browser.execute(() => (window as unknown as Probe).__bridgeCalls)).toBe(1);
  });

  it("reports a rejected bridge promise instead of hanging", async () => {
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__holeUiReady = () => {
        w.__bridgeCalls++;
        return Promise.reject(new Error("bridge rejected"));
      };
    });

    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );

    expect(thrown?.message).toContain("bridge rejected");
    expect(await browser.execute(() => (window as unknown as Probe).__bridgeCalls)).toBe(1);
  });

  it("reports a bridge that throws synchronously instead of hanging", async () => {
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__holeUiReady = () => {
        w.__bridgeCalls++;
        throw new Error("bridge threw");
      };
    });

    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );

    expect(thrown?.message).toContain("bridge threw");
    expect(await browser.execute(() => (window as unknown as Probe).__bridgeCalls)).toBe(1);
  });

  it("reports a malformed bridge result instead of hanging", async () => {
    // The `error` -> `reason` rename reads properties off whatever the
    // bridge resolves with. A shape it does not expect must still reach a
    // disposition; otherwise the call runs out the framework timeout and
    // the reason is lost.
    await browser.execute(() => {
      const w = window as unknown as Probe;
      w.__holeUiReady = () => {
        w.__bridgeCalls++;
        return Promise.resolve(undefined as unknown as { ok: boolean; error: string | null });
      };
    });

    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );

    expect(thrown?.message).toContain("UI init failed:");
    expect(await browser.execute(() => (window as unknown as Probe).__bridgeCalls)).toBe(1);
  });

  it("reports a missing bridge as its own error, without re-asking", async () => {
    await browser.execute(() => {
      delete (window as unknown as Probe).__holeUiReady;
    });

    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );

    expect(thrown?.message).toBe("UI init failed: __holeUiReady not published by ui/main.ts");
    expect(await browser.execute(() => (window as unknown as Probe).__bridgeCalls)).toBe(0);
  });
});
