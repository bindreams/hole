import { type ChildProcess, spawn } from "node:child_process";
import path from "node:path";
import type { Options } from "@wdio/types";

let tauriDriver: ChildProcess;

export const config: Options.Testrunner = {
  runner: "local",
  // tauri-driver listens on 127.0.0.1:4444 (its default). wdio MUST know
  // this — without `hostname`+`port`, it tries to spawn a real browser
  // session and fails with "No browserName defined in capabilities". See
  // bindreams/hole#372.
  hostname: "127.0.0.1",
  port: 4444,
  autoCompileOpts: {
    tsNodeOpts: {
      project: path.join(__dirname, "tsconfig.json"),
    },
  },
  specs: ["./specs/**/*.spec.ts"],
  maxInstances: 1,
  capabilities: [
    {
      "tauri:options": {
        application: process.env.HOLE_TEST_APP_PATH ?? path.resolve(__dirname, "../../target/release/hole.exe"),
        args: ["--show-dashboard"],
      },
    } as any,
  ],
  framework: "mocha",
  mochaOpts: {
    ui: "bdd",
    timeout: 30000,
  },
  reporters: ["spec"],

  // Wait for the UI to signal it has finished `init()` (success or
  // failure). Synchronizes the test run with the UI's initialization
  // state via an explicit Tauri-command bridge in
  // crates/hole/src/ui_ready.rs. `executeAsync` parks the driver
  // until `done()` is called from the page-side script. The Mocha
  // 30s `timeout` above is the framework-level failure bound (it
  // covers WebView2-itself-broken — an external-event-might-never-
  // happen scenario; not the synchronization).
  //
  // See bindreams/hole#383 for the flake that motivated this.
  async before() {
    const result = await browser.executeAsync<{
      ok: boolean;
      error: string | null;
    }>((done) => {
      // The webdriver session can establish before ui/main.ts has
      // executed its module-level `window.__holeUiReady = ...`
      // assignment. If `document.readyState !== "complete"` we wait
      // for the `load` event — all scripts have run by then — and
      // then call the bridge. Event-driven (no polling).
      type ReadyFn = () => Promise<{ ok: boolean; error: string | null }>;
      const go = () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ready = (window as any).__holeUiReady as ReadyFn | undefined;
        if (typeof ready !== "function") {
          done({
            ok: false,
            error: "__holeUiReady not exposed by ui/main.ts after page load",
          });
          return;
        }
        ready()
          .then(done)
          .catch((e: unknown) => done({ ok: false, error: String(e) }));
      };
      if (document.readyState === "complete") {
        go();
      } else {
        window.addEventListener("load", go, { once: true });
      }
    });
    if (!result.ok) {
      throw new Error(`UI init failed: ${result.error}`);
    }
  },

  onPrepare() {
    // Discard tauri-driver's stdio — keeping the pipes open would block
    // tauri-driver if it ever writes more than the pipe buffer (~64 KB
    // on Windows) without anyone reading. The WDIO/Mocha output already
    // covers the test side; tauri-driver itself is rarely the failing
    // piece.
    tauriDriver = spawn("tauri-driver", [], { stdio: "ignore" });
  },

  onComplete() {
    tauriDriver?.kill();
  },
};
