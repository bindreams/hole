// Stats table — paints download/upload bytes, speeds, and uptime into the
// #stat-* elements. Pulls human-readable formatting from ./formatting.

import { formatBytes, formatSpeed, formatUptime } from "./formatting";
import type { Metrics } from "./types";

let statDownloaded: HTMLElement | null = null;
let statUploaded: HTMLElement | null = null;
let statDownloadSpeed: HTMLElement | null = null;
let statUploadSpeed: HTMLElement | null = null;
let statUptime: HTMLElement | null = null;

/** Initialize: bind DOM refs. Must be called once at startup. */
export function initStats(): void {
  statDownloaded = document.getElementById("stat-downloaded");
  statUploaded = document.getElementById("stat-uploaded");
  statDownloadSpeed = document.getElementById("stat-download-speed");
  statUploadSpeed = document.getElementById("stat-upload-speed");
  statUptime = document.getElementById("stat-uptime");
}

/** Repaint the stats table from a fresh Metrics snapshot. */
export function updateStats(metrics: Metrics): void {
  if (statDownloaded) statDownloaded.textContent = formatBytes(metrics.bytes_in);
  if (statUploaded) statUploaded.textContent = formatBytes(metrics.bytes_out);
  if (statDownloadSpeed) statDownloadSpeed.textContent = formatSpeed(metrics.speed_in_bps);
  if (statUploadSpeed) statUploadSpeed.textContent = formatSpeed(metrics.speed_out_bps);
  if (statUptime) statUptime.textContent = formatUptime(metrics.uptime_secs);
}
