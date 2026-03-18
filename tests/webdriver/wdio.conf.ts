import type { Options } from "@wdio/types";
import { spawn, ChildProcess } from "child_process";
import path from "path";

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
        application: path.resolve(
          __dirname,
          "../../target/release/hole.exe"
        ),
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
