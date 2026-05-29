import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = `
    <span id="stat-downloaded"></span>
    <span id="stat-uploaded"></span>
    <span id="stat-download-speed"></span>
    <span id="stat-upload-speed"></span>
    <span id="stat-uptime"></span>
  `;
});

describe("updateStats", () => {
  it("writes formatted byte counts, speeds, and uptime", async () => {
    const { initStats, updateStats } = await import("./stats");
    initStats();
    updateStats({
      bytes_in: 1024 * 1024 * 1024,
      bytes_out: 1024 * 1024,
      speed_in_bps: 50_000_000,
      speed_out_bps: 2_500_000,
      uptime_secs: 8000,
    });
    expect(document.getElementById("stat-downloaded")!.textContent).toBe("1.00 GB");
    expect(document.getElementById("stat-uploaded")!.textContent).toBe("1.0 MB");
    expect(document.getElementById("stat-download-speed")!.textContent).toBe("50 Mbps");
    expect(document.getElementById("stat-upload-speed")!.textContent).toBe("2.5 Mbps");
    expect(document.getElementById("stat-uptime")!.textContent).toBe("2h 13m");
  });
});
