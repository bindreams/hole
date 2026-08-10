// Mocha root-hook plugin: the UI-readiness gate every spec file runs behind.
//
// It lives here rather than in wdio.conf.ts's `before` because wdio's
// `executeHooksWithArgs` catches a config hook's exception, logs it, and
// resolves — a gate that throws there is a log line, not a verdict, and the
// run stays green. A Mocha root hook fails the spec file it guards.
// specs/ui-ready-sync.spec.ts asserts the gate is still wired in.

import { assertUiReady, execute, openDashboard } from "./ui-ready";

/// Set on the browser once the gate has run, so a spec can prove it did.
export const GATE_MARKER = "__holeUiReadyGate";

export const mochaHooks = {
  async beforeAll() {
    await openDashboard(browser);
    await assertUiReady(browser);
    await execute<void, [string]>(
      browser,
      (marker) => {
        (window as unknown as Record<string, boolean>)[marker] = true;
      },
      GATE_MARKER,
    );
  },
};
