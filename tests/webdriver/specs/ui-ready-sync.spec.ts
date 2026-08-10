// Meta-test for the `__holeUiReady` test seam. If a future refactor
// accidentally unhooks the readiness gate OR breaks `__holeUiReady`'s
// bundled-bridge wiring, this spec fails loudly instead of letting
// downstream specs return to flake-land.

import { GATE_MARKER } from "../root-hooks";
import { assertUiReady, execute } from "../ui-ready";

describe("UI-ready sync", () => {
  it("ran the readiness gate before this spec", async () => {
    // `mochaOpts.require` is what pulls root-hooks.ts in. Dropping it would
    // otherwise just quietly un-gate every spec file.
    const gated = await execute<boolean, [string]>(
      browser,
      (marker) => (window as unknown as Record<string, boolean>)[marker] === true,
      GATE_MARKER,
    );
    expect(gated).toBe(true);
  });

  it("exposes the __holeUiReady bridge on window", async () => {
    const t = await execute<string>(browser, () => typeof window.__holeUiReady);
    expect(t).toBe("function");
  });

  it("a second call returns the same settled result", async () => {
    // The readiness gate already awaited __holeUiReady once before this spec
    // started. The bridge hands out this document's already-settled init
    // promise, so a second call resolves with the same success — the basis
    // on which downstream specs trust that the app is initialized.
    const thrown = await assertUiReady(browser).then(
      () => null,
      (e: Error) => e,
    );
    expect(thrown).toBeNull();
  });
});
