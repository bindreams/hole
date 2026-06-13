// Public-IP display: country flag + IP address + copy-to-clipboard.
// Fetches via the `get_public_ip` Tauri command.

import { invoke } from "@tauri-apps/api/core";
import { setCountryFlag } from "./country-flag";
import { showToast } from "./toast";
import type { PublicIpData } from "./types";

let ipText: HTMLElement | null = null;
let countryFlag: HTMLElement | null = null;
let copyIpBtn: HTMLElement | null = null;
let currentIp = "";

/** Initialize: bind DOM refs + wire the copy button. */
export function initIpDisplay(): void {
  ipText = document.getElementById("ip-text");
  countryFlag = document.getElementById("country-flag");
  copyIpBtn = document.getElementById("copy-ip-btn");
  copyIpBtn?.addEventListener("click", handleCopyIp);
}

/** Refetch the public IP via Tauri and repaint the badge + address. */
export async function updatePublicIp(): Promise<void> {
  try {
    const data = await invoke<PublicIpData>("get_public_ip");
    // Only commit a real IP to `currentIp` — the displayed "unknown"
    // fallback is human-readable text, not a value the user would ever
    // want pasted from their clipboard.
    currentIp = data.ip || "";
    if (countryFlag) setCountryFlag(countryFlag, data.country_code);
    if (ipText && countryFlag) {
      // Structure: <span class="country-flag fi fis fi-XX" id="country-flag" title="XX"></span> ip.addr
      ipText.replaceChildren(countryFlag, document.createTextNode(` ${data.ip || "unknown"}`));
    }
  } catch (err) {
    console.error("get_public_ip failed:", err);
    // Never keep a possibly pre-VPN value on failure (#464): clear the
    // copyable IP and show a placeholder distinct from the empty-success
    // "unknown".
    currentIp = "";
    if (countryFlag) setCountryFlag(countryFlag, "");
    if (ipText && countryFlag) {
      ipText.replaceChildren(countryFlag, document.createTextNode(" --"));
    }
  }
}

function handleCopyIp(): void {
  if (!currentIp) return;
  navigator.clipboard.writeText(currentIp).then(
    () => showToast("IP address copied.", "success"),
    (err) => {
      console.error("clipboard write failed:", err);
      showToast(`Copy failed: ${err}`, "error");
    },
  );
}
