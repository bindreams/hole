import { describe, expect, it } from "vitest";
import { formatBytes, formatSpeed, formatUptime } from "./formatting";

describe("formatBytes", () => {
  it("returns bytes (no scaling) below 1 KB", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });
  it("scales through KB / MB / GB at 1024 thresholds", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GB");
  });
});

describe("formatSpeed", () => {
  it("returns '0 Kbps' for sub-1Kbps input", () => {
    expect(formatSpeed(0)).toBe("0 Kbps");
    expect(formatSpeed(500)).toBe("0 Kbps");
  });
  it("scales through Kbps / Mbps tiers", () => {
    expect(formatSpeed(2_000)).toBe("2 Kbps");
    expect(formatSpeed(2_500_000)).toBe("2.5 Mbps");
    expect(formatSpeed(50_000_000)).toBe("50 Mbps");
    expect(formatSpeed(200_000_000)).toBe("200 Mbps");
  });
});

describe("formatUptime", () => {
  it("returns '--' for non-positive uptime", () => {
    expect(formatUptime(0)).toBe("--");
    expect(formatUptime(-1)).toBe("--");
  });
  it("formats seconds-only / minute+seconds / hour+minutes shapes", () => {
    expect(formatUptime(42)).toBe("42s");
    expect(formatUptime(125)).toBe("2m 5s");
    expect(formatUptime(8000)).toBe("2h 13m");
  });
});
