// Regression gate for #372 — the dashboard webview must load the bundled
// frontend, not WebView2's "localhost refused to connect" error page.
//
// Failure modes this guards against:
// - hole.exe compiled with `cfg(dev)` ON (missing `tauri/custom-protocol`),
//   so it tries `http://localhost:1420/` at runtime → connection refused.
// - `ui/dist/` missing / empty at build time, so embedded assets are empty
//   and the dashboard navigates to a stub or fallback URL.

describe("Dashboard window", () => {
  it("loads the bundled HTML (not the WebView2 error page)", async () => {
    // ui/index.html line 6 sets <title>Hole Dashboard</title>. WebView2's
    // error page title is something like "Hmm — can't reach this page".
    const title = await browser.getTitle();
    expect(title).toBe("Hole Dashboard");
  });

  it("renders the server-list container from the bundled DOM", async () => {
    // #server-list lives at ui/index.html:22 — present iff index.html was
    // actually served from embedded assets.
    const list = await $("#server-list");
    await list.waitForExist({ timeout: 5000 });
    expect(await list.isExisting()).toBe(true);
  });
});
