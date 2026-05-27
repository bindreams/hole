import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./main", () => ({ config: null }));
vi.mock("./servers", () => ({ statusTooltipFor: () => "test tooltip" }));

beforeEach(() => {
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
});
