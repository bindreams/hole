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
