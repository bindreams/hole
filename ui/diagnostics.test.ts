import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Config, Server } from "./types";

// We swap the mocked config between tests via a mutable holder so each
// case can present a different selected_server + validation shape to
// updateDiagnostics. The vi.mock factory runs once per resetModules
// re-import — `mainMock.config` is read on each module load.
const mainMock = { config: null as Config | null };
vi.mock("./main", () => ({
  get config() {
    return mainMock.config;
  },
}));
vi.mock("./servers", () => ({ statusTooltipFor: () => "test tooltip" }));

function makeServerWithValidation(validation: Server["validation"]): Config {
  return {
    servers: [
      {
        id: "s1",
        name: "test",
        server: "1.2.3.4",
        server_port: 443,
        method: "aes-256-gcm",
        password: "p",
        validation,
      },
    ],
    selected_server: "s1",
    filters: [],
    local_port: 1080,
    local_port_http: 1081,
    proxy_server_enabled: false,
    proxy_socks5: true,
    proxy_http: false,
    on_startup: "disconnected",
    theme: "dark",
    dns: { enabled: true, servers: ["1.1.1.1"], protocol: "https" },
    diagnostic_plugin_tap: false,
  };
}

beforeEach(() => {
  mainMock.config = null;
  document.body.innerHTML = `
    <span id="diag-app"></span>
    <span id="diag-bridge"></span>
    <span id="diag-network"></span>
    <span id="diag-vpn-server"></span>
    <span id="diag-internet"></span>
  `;
  vi.resetModules();
});

describe("updateDiagnostics", () => {
  it("applies ok/error/unknown CSS classes per poll data", async () => {
    const { initDiagnostics, updateDiagnostics } = await import("./diagnostics");
    initDiagnostics();
    updateDiagnostics({
      app: "ok",
      bridge: "error",
      network: "unknown",
      vpn_server: "unknown",
      internet: "unknown",
    });
    expect(document.getElementById("diag-app")!.className).toBe("nd ok");
    expect(document.getElementById("diag-bridge")!.className).toBe("nd error");
    expect(document.getElementById("diag-network")!.className).toBe("nd unknown");
  });

  it("vpn_server + internet stay unknown when no server is selected", async () => {
    const { initDiagnostics, updateDiagnostics } = await import("./diagnostics");
    initDiagnostics();
    // Even if the poll reports ok, with no selected server in config, the
    // vpn_server + internet dots stay gray — they're computed from the
    // selected server's persisted validation state, not the poll.
    updateDiagnostics({
      app: "ok",
      bridge: "ok",
      network: "ok",
      vpn_server: "ok",
      internet: "ok",
    });
    expect(document.getElementById("diag-vpn-server")!.className).toBe("nd unknown");
    expect(document.getElementById("diag-internet")!.className).toBe("nd unknown");
  });

  it("reachable with real latency → vpn_server + internet both 'ok'", async () => {
    mainMock.config = makeServerWithValidation({
      tested_at: "2026-01-01T00:00:00Z",
      outcome: { kind: "reachable", latency_ms: 123 },
    });
    const { initDiagnostics, updateDiagnostics } = await import("./diagnostics");
    initDiagnostics();
    updateDiagnostics({
      app: "ok",
      bridge: "ok",
      network: "ok",
      vpn_server: "unknown",
      internet: "unknown",
    });
    expect(document.getElementById("diag-vpn-server")!.className).toBe("nd ok");
    expect(document.getElementById("diag-internet")!.className).toBe("nd ok");
  });

  it("validated-on-connect (latency=0 sentinel) → vpn_server 'ok' but internet stays 'unknown'", async () => {
    // LATENCY_VALIDATED_ON_CONNECT is the sentinel for "we know the VPN
    // handshake succeeded because the connect itself worked, but we
    // never ran the sentinel HTTP probe." vpn_server should light green;
    // internet stays gray because we have no positive evidence of
    // end-to-end reachability through the tunnel.
    mainMock.config = makeServerWithValidation({
      tested_at: "2026-01-01T00:00:00Z",
      outcome: { kind: "reachable", latency_ms: 0 },
    });
    const { initDiagnostics, updateDiagnostics } = await import("./diagnostics");
    initDiagnostics();
    updateDiagnostics({
      app: "ok",
      bridge: "ok",
      network: "ok",
      vpn_server: "unknown",
      internet: "unknown",
    });
    expect(document.getElementById("diag-vpn-server")!.className).toBe("nd ok");
    expect(document.getElementById("diag-internet")!.className).toBe("nd unknown");
  });

  it("non-reachable validation → vpn_server 'error', internet stays 'unknown'", async () => {
    // A failed validation lights vpn_server red. Internet never goes
    // red — gray-only — because absence of evidence ≠ evidence of
    // absence for end-to-end reachability.
    mainMock.config = makeServerWithValidation({
      tested_at: "2026-01-01T00:00:00Z",
      outcome: { kind: "tcp_refused" },
    });
    const { initDiagnostics, updateDiagnostics } = await import("./diagnostics");
    initDiagnostics();
    updateDiagnostics({
      app: "ok",
      bridge: "ok",
      network: "ok",
      vpn_server: "unknown",
      internet: "unknown",
    });
    expect(document.getElementById("diag-vpn-server")!.className).toBe("nd error");
    expect(document.getElementById("diag-internet")!.className).toBe("nd unknown");
  });
});
