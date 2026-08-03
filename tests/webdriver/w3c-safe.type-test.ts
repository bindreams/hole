// Type-level tests for the `W3cSafe` guard in ui-ready.ts. There is nothing
// to run: `tsc --noEmit -p tests/webdriver` (the `Frontend check` CI job) is
// the assertion, and an `@ts-expect-error` that stops erroring fails it as an
// unused directive. specs/webdriverio-contract.spec.ts covers what the
// rejected payloads do at runtime.

import { execute, executeAsync } from "./ui-ready";

declare const browser: WebdriverIO.Browser;

export function accepts() {
  executeAsync<{ ok: boolean; reason: string | null }>(browser, (done) => done({ ok: true, reason: null }));
  execute<{ ok: boolean; reason: string | null }>(browser, () => ({ ok: true, reason: null }));
  execute<string>(browser, () => "plain values are fine");
}

export function rejectsACollidingPayload() {
  // @ts-expect-error — `error` is a W3C error-envelope key.
  executeAsync<{ ok: boolean; error: string | null }>(browser, (done) => done({ ok: true, error: null }));
  // @ts-expect-error — same key, on the synchronous endpoint.
  execute<{ ok: boolean; error: string | null }>(browser, () => ({ ok: true, error: null }));
  // @ts-expect-error — `stacktrace` and its camelCase variant too.
  execute<{ stacktrace: string }>(browser, () => ({ stacktrace: "x" }));
  // @ts-expect-error
  execute<{ stackTrace: string }>(browser, () => ({ stackTrace: "x" }));
}

export function acceptsACleanUnion() {
  executeAsync<{ ok: true } | { ok: false; reason: string }>(browser, (done) => done({ ok: true }));
  execute<{ ok: true } | { ok: false; reason: string }>(browser, () => ({ ok: true }));
}

export function rejectsAUnionThatHidesTheKey() {
  // `keyof` a union is only its shared keys, so these pass an undistributed
  // check while still carrying `error` on the branch that matters.
  // @ts-expect-error — the failure branch collides.
  executeAsync<{ ok: true } | { ok: false; error: string }>(browser, (done) => done({ ok: false, error: "boom" }));
  // @ts-expect-error — same union, on the synchronous endpoint.
  execute<{ ok: true } | { ok: false; error: string }>(browser, () => ({ ok: false, error: "boom" }));
}

export function rejectsAnOmittedPayloadType() {
  // Without an explicit argument the payload is unchecked, so the wrappers
  // refuse to be called that way.
  // @ts-expect-error — payload type not given.
  executeAsync(browser, (done) => done({ ok: true, error: null }));
  // @ts-expect-error — payload type not given.
  execute(browser, () => ({ ok: true, error: null }));
}
