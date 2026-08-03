// The webdriver side of the UI-readiness handshake.
//
// See `ui/main.ts` for the page side and CONTRIBUTING.md for the rules the
// handshake has to satisfy (no sleeps, no timeout-polls).

declare global {
  interface Window {
    // Mirrors the declaration in ui/main.ts; the two TypeScript projects
    // do not share a tsconfig.
    __holeUiReady?: () => Promise<{ ok: boolean; error: string | null }>;
  }
}

/// The dashboard document, served from hole.exe's embedded assets. Windows
/// only — so is the E2E (`tauri:options.application` is `hole.exe`).
export const DASHBOARD_URL = "http://tauri.localhost/index.html";

/// Keys webdriverio's `isSuccessfulResponse` reads out of a response `value`
/// to decide the command failed. A result carrying any of them with a truthy
/// value is thrown as a `WebDriverError` and the request is re-sent
/// `connectionRetryCount` times — the caller sees a driver error, or a later
/// attempt's value, instead of the one it returned.
export const W3C_ERROR_KEYS = ["error", "stacktrace", "stackTrace"] as const;
type W3cErrorKey = (typeof W3C_ERROR_KEYS)[number];

const REJECTION =
  "payload type must be given explicitly and must not carry the W3C error-envelope keys (error/stacktrace/stackTrace); webdriverio would read this result as a driver error and retry the command";

/// `T`, or a `string` that no payload is assignable to. Distributes, so a
/// union is checked member by member (`keyof` a union is only its shared
/// keys, which would let `{ok: true} | {ok: false, error: string}` through).
export type W3cSafe<T> = T extends unknown
  ? Extract<keyof T, W3cErrorKey> extends never
    ? T
    : typeof REJECTION
  : never;

/// Default for the payload type parameter. `T` has no inference site in
/// either wrapper below, so an omitted type argument would otherwise be
/// unchecked; this one carries a reserved key and is rejected like any other.
type PayloadTypeRequired = { error: never };

/// `browser.execute`, restricted to results webdriverio hands back verbatim
/// (`isSuccessfulResponse` inspects the response `value` whichever endpoint
/// produced it). A colliding result is a compile error, not a silent retry.
export function execute<T = PayloadTypeRequired, A extends unknown[] = []>(
  browser: WebdriverIO.Browser,
  script: (...args: A) => W3cSafe<T>,
  ...args: A
): Promise<T> {
  type Script = Parameters<WebdriverIO.Browser["execute"]>[0];
  return browser.execute(script as Script, ...args) as Promise<T>;
}

/// `browser.executeAsync`, restricted the same way: a colliding payload makes
/// `done` unusable.
export function executeAsync<T = PayloadTypeRequired>(
  browser: WebdriverIO.Browser,
  script: (done: (result: W3cSafe<T>) => void) => void,
): Promise<T> {
  // `W3cSafe<T>` is `T` for every payload that gets past the check above;
  // TypeScript cannot see that through the conditional type. Called as a
  // method — wdio's command wrapper reads `this`.
  type Script = Parameters<WebdriverIO.Browser["executeAsync"]>[0];
  return browser.executeAsync(script as Script) as Promise<T>;
}

/// Navigate to the dashboard document.
///
/// The app navigates the webview to `DASHBOARD_URL` itself, asynchronously,
/// after window creation — and the webdriver session attaches before that
/// lands. The pre-navigation document is `about:blank`, which reports
/// `readyState === "complete"` and has no bridge on it, so there is nothing
/// in it to wait on. Driving the navigation makes the document load the
/// rendezvous: WebDriver's navigate command returns only once the document is
/// complete, and `ui/main.ts` is a module script, so it has evaluated and
/// published `__holeUiReady` by then.
export async function openDashboard(browser: WebdriverIO.Browser): Promise<void> {
  await browser.url(DASHBOARD_URL);
}

/// Park until `ui/main.ts`'s `init()` has settled in the current document,
/// and throw if it failed. Requires [`openDashboard`] to have run.
export async function assertUiReady(browser: WebdriverIO.Browser): Promise<void> {
  const result = await executeAsync<{ ok: boolean; reason: string | null }>(browser, (done) => {
    const ready = window.__holeUiReady;
    if (typeof ready !== "function") {
      done({ ok: false, reason: "__holeUiReady not published by ui/main.ts" });
      return;
    }
    // Every outcome has to reach `done`, or the call hangs to the framework
    // timeout instead of reporting what went wrong. The `error` -> `reason`
    // rename reads properties off the bridge's result, so a malformed one
    // throws inside the chain rather than rejecting it.
    try {
      Promise.resolve(ready())
        .then((r) => ({ ok: r.ok, reason: r.error }))
        .catch((e: unknown) => ({ ok: false, reason: String(e) }))
        .then(done);
    } catch (e) {
      done({ ok: false, reason: String(e) });
    }
  });
  if (!result.ok) {
    throw new Error(`UI init failed: ${result.reason}`);
  }
}
