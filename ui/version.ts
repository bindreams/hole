// Version footer — paints `Hole vX.Y.Z` (or fallback `Hole`) into
// #version-footer using the Tauri app-version API.

import { getVersion } from "@tauri-apps/api/app";

/** Initialize: fetch version + paint footer. */
export async function initVersion(): Promise<void> {
  const versionFooter = document.getElementById("version-footer");
  if (!versionFooter) return;
  try {
    const version = await getVersion();
    versionFooter.textContent = `Hole v${version}`;
  } catch {
    versionFooter.textContent = "Hole";
  }
}
