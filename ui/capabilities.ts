// Capability indicators (#470): two sidebar dots showing whether the current
// connection supports UDP proxying and IPv6 bypass. Informational only — they
// gate no connection logic. Fed every status poll.

let udpEl: HTMLElement | null = null;
let ipv6El: HTMLElement | null = null;

/// Last-known values, reset on disconnect so a reconnect to a different server
/// starts "unknown" instead of showing the previous connection's capabilities.
let lastUdp: boolean | null = null;
let lastIpv6: boolean | null = null;

export function initCapabilities(): void {
  udpEl = document.getElementById("cap-udp");
  ipv6El = document.getElementById("cap-ipv6");
}

function paint(el: HTMLElement | null, value: boolean | null, label: string): void {
  if (!el) return;
  if (value === null) {
    // Unknown — leave the dot as-is (keeps last-known while connected, or the
    // neutral dot when disconnected).
    return;
  }
  el.className = value ? "nd ok" : "nd error";
  el.title = value ? `${label}: available` : `${label}: unavailable on this connection`;
}

/// Update both dots from a status poll. `udp`/`ipv6` are `null` when the bridge
/// could not vouch this poll (a non-Status arm) — keep the last-known value.
/// When disconnected, the dots are neutral and last-known is cleared.
export function setCapabilityFlags(udp: boolean | null, ipv6: boolean | null, running: boolean): void {
  if (!running) {
    lastUdp = null;
    lastIpv6 = null;
    if (udpEl) {
      udpEl.className = "nd unknown";
      udpEl.title = "UDP proxy: not connected";
    }
    if (ipv6El) {
      ipv6El.className = "nd unknown";
      ipv6El.title = "IPv6 bypass: not connected";
    }
    return;
  }
  if (udp !== null) lastUdp = udp;
  if (ipv6 !== null) lastIpv6 = ipv6;
  paint(udpEl, lastUdp, "UDP proxy");
  paint(ipv6El, lastIpv6, "IPv6 bypass");
}
