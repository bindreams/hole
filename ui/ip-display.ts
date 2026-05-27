// Public-IP display: country flag + IP address + copy-to-clipboard.
// Fetches via the `get_public_ip` Tauri command.

import { invoke } from "@tauri-apps/api/core";
import { setCountryFlag } from "./country-flag";
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
    const ip = data.ip || "unknown";
    currentIp = ip;
    if (countryFlag) setCountryFlag(countryFlag, data.country_code);
    if (ipText && countryFlag) {
      // Structure: <span class="country-flag fi fis fi-XX" id="country-flag" title="XX"></span> ip.addr
      ipText.replaceChildren(countryFlag, document.createTextNode(` ${ip}`));
    }
  } catch (err) {
    console.error("get_public_ip failed:", err);
  }
}

function handleCopyIp(): void {
  if (!currentIp) return;
  navigator.clipboard.writeText(currentIp).catch((err) => {
    console.error("clipboard write failed:", err);
  });
}
