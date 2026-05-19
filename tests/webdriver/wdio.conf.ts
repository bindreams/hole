import { type ChildProcess, spawn } from "node:child_process";
import path from "node:path";
import type { Options } from "@wdio/types";

let tauriDriver: ChildProcess;

export const config: Options.Testrunner = {
  runner: "local",
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
    tauriDriver = spawn("tauri-driver", [], {
      stdio: ["ignore", "pipe", "pipe"],
    });
  },

  onComplete() {
    tauriDriver?.kill();
  },
};
