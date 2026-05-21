// Meta-test for the `__holeUiReady` test seam. If a future refactor
// accidentally removes the wdio.conf.ts `before` hook OR breaks
// `__holeUiReady`'s bundled-bridge wiring, this spec fails loudly
// instead of letting downstream specs return to flake-land.
//
// See bindreams/hole#383 and crates/hole/src/ui_ready.rs.

describe("UI-ready sync", () => {
  it("exposes the __holeUiReady bridge on window", async () => {
    const t = await browser.execute(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return typeof (window as any).__holeUiReady;
    });
    expect(t).toBe("function");
  });

  it("a second wait_ui_ready call returns ok:true immediately (already-latched)", async () => {
    // The wdio.conf.ts `before` hook already awaited __holeUiReady once
    // before this spec started. A second call must resolve immediately
    // with the latched success result — that is the watch-channel
    // semantic and the basis on which downstream specs trust that the
    // app is initialized.
    const result = await browser.executeAsync<{
      ok: boolean;
      error: string | null;
    }>((done) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).__holeUiReady().then(done);
    });
    expect(result.ok).toBe(true);
    expect(result.error).toBeNull();
  });
});
