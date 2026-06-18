import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  document.body.innerHTML = `
    <div class="nd unknown" id="cap-udp"></div>
    <div class="nd unknown" id="cap-ipv6"></div>`;
  vi.resetModules();
});

describe("capability dots (#470)", () => {
  it("shows ok / warning when connected", async () => {
    const { initCapabilities, setCapabilityFlags } = await import("./capabilities");
    initCapabilities();
    setCapabilityFlags(true, false, true);
    expect(document.getElementById("cap-udp")!.className).toContain("ok");
    expect(document.getElementById("cap-ipv6")!.className).toContain("error");
  });

  it("shows neutral when disconnected regardless of the flags", async () => {
    const { initCapabilities, setCapabilityFlags } = await import("./capabilities");
    initCapabilities();
    setCapabilityFlags(true, true, false);
    expect(document.getElementById("cap-udp")!.className).toContain("unknown");
    expect(document.getElementById("cap-ipv6")!.className).toContain("unknown");
  });

  it("keeps the last-known value on a null (unknown) flag while connected", async () => {
    const { initCapabilities, setCapabilityFlags } = await import("./capabilities");
    initCapabilities();
    setCapabilityFlags(true, true, true); // both available
    setCapabilityFlags(null, null, true); // unknown arm — must not erase
    expect(document.getElementById("cap-udp")!.className).toContain("ok");
    expect(document.getElementById("cap-ipv6")!.className).toContain("ok");
  });

  it("resets last-known on disconnect so a reconnect starts unknown, not stale", async () => {
    const { initCapabilities, setCapabilityFlags } = await import("./capabilities");
    initCapabilities();
    setCapabilityFlags(true, true, true); // connection A: available
    setCapabilityFlags(true, true, false); // disconnect
    setCapabilityFlags(null, null, true); // connection B, first poll is an unknown arm
    expect(document.getElementById("cap-udp")!.className).toContain("unknown");
    expect(document.getElementById("cap-udp")!.className).not.toContain("ok");
  });
});
