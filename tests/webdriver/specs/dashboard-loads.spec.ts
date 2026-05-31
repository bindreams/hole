// Regression gate: the dashboard webview must load the bundled frontend,
// not WebView2's "localhost refused to connect" error page.
//
// Failure modes this guards against:
// - hole.exe compiled with `cfg(dev)` ON (missing `tauri/custom-protocol`),
//   so it tries `http://localhost:1420/` at runtime → connection refused.
// - `ui/dist/` missing / empty at build time, so embedded assets are empty
//   and the dashboard navigates to a stub or fallback URL.
//
// The wdio.conf.ts `before` hook parks the suite until `init()` in
// ui/main.ts has signaled completion via the `wait_ui_ready` Tauri
// command. By the time these specs run, the page is loaded and the
// app's init() has finished — no per-test wait needed.

describe("Dashboard window", () => {
  it("loads the bundled HTML (not the WebView2 error page)", async () => {
    // ui/index.html line 6 sets <title>Hole Dashboard</title>. WebView2's
    // error page title is something like "Hmm — can't reach this page".
    expect(await browser.getTitle()).toBe("Hole Dashboard");
  });

  it("renders the server-list container from the bundled DOM", async () => {
    // #server-list lives at ui/index.html:22 — present iff index.html was
    // actually served from embedded assets.
    expect(await $("#server-list").isExisting()).toBe(true);
  });
});
