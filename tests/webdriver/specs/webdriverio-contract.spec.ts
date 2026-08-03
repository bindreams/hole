// Characterizes what webdriverio does with an `executeAsync` result whose
// keys collide with the W3C error envelope, and pins the boundary against
// dependency bumps.
//
// `isSuccessfulResponse` (node_modules/webdriver) reads a 200 response as a
// failure when its `value` carries a truthy `error`, `stackTrace` or
// `stacktrace`. The result is then thrown as a `WebDriverError` and the whole
// request is re-sent `connectionRetryCount` (3) times with a 0/500/1000 ms
// backoff — a ~1.5 s poll the caller never asked for, and a value it never
// sees. `tests/webdriver/ui-ready.ts` makes such a payload a compile error;
// this spec is the runtime half of that guard: it probes the very list the
// type is derived from, so the two cannot drift apart.
//
// These probes deliberately call `browser.executeAsync` raw — the typed
// helper exists precisely to reject the colliding shapes below.

import { W3C_ERROR_KEYS } from "../ui-ready";

interface ProbeResult {
  /** Times the driver actually executed the script (retries included). */
  attempts: number;
  outcome: "resolved" | "rejected";
  value: unknown;
}

async function probe(payload: Record<string, unknown>): Promise<ProbeResult> {
  await browser.execute(() => {
    (window as unknown as { __probeAttempts: number }).__probeAttempts = 0;
  });
  const outcome = await browser
    .executeAsync((p: Record<string, unknown>, done: (r: unknown) => void) => {
      (window as unknown as { __probeAttempts: number }).__probeAttempts++;
      done(p);
    }, payload)
    .then(
      (value) => ({ outcome: "resolved" as const, value }),
      (err) => ({ outcome: "rejected" as const, value: err }),
    );
  const attempts = await browser.execute(() => (window as unknown as { __probeAttempts: number }).__probeAttempts);
  return { attempts, ...outcome };
}

describe("executeAsync payloads vs the W3C error envelope", () => {
  for (const key of W3C_ERROR_KEYS) {
    it(`treats a truthy \`${key}\` as a driver error and retries the command`, async () => {
      const result = await probe({ ok: true, [key]: "sentinel" });
      expect(result.outcome).toBe("rejected");
      // 1 original + connectionRetryCount (3). The value is discarded.
      expect(result.attempts).toBe(4);
    });
  }

  // `message` participates in the error envelope but is not itself a
  // trigger; if a bump promotes it to one, this fails and the reserved
  // set in ui-ready.ts has to grow.
  for (const key of ["message", "reason"]) {
    it(`returns a payload keyed \`${key}\` verbatim, on the first attempt`, async () => {
      const result = await probe({ ok: false, [key]: "sentinel" });
      expect(result.outcome).toBe("resolved");
      expect(result.value).toEqual({ ok: false, [key]: "sentinel" });
      expect(result.attempts).toBe(1);
    });
  }
});
