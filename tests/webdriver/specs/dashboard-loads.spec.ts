// Regression gate: the dashboard webview must load the bundled frontend,
// not WebView2's "localhost refused to connect" error page.
//
// The failure mode this guards: `ui/dist/` missing or empty at build time, so
// the embedded assets serve nothing at `DASHBOARD_URL`. The other failure
// mode — a release binary built without `tauri/custom-protocol`, which points
// the webview at `http://localhost:1420/` — is a compile error in
// crates/hole/src/main.rs, not something a spec can observe: the gate drives
// the navigation, so no spec sees the app's own choice of URL.
//
// The Mocha root hook (tests/webdriver/root-hooks.ts) navigates to the
// dashboard document and parks the suite until `init()` in ui/main.ts has
// settled. By the time these specs run, the page is loaded and the app's
// init() has finished — no per-test wait needed.

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
