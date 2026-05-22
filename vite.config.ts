/// <reference types="vitest/config" />
import { defineConfig } from "vite";

export default defineConfig({
  root: "ui",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  test: {
    // jsdom so toast tests can manipulate `document.body`.
    environment: "jsdom",
    // Vitest infers the test root from vite's `root`; restate the include
    // explicitly so a future `root` change doesn't silently strand tests.
    include: ["**/*.test.ts"],
  },
});
