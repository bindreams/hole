// Pure formatting helpers for byte counts, transfer speeds, and durations.
// Used by the stats table + graph scale label; extracted from sidebar.ts
// for unit testability.

/** Format a byte count to a human-readable string (e.g. "1.24 GB"). */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Format a bits-per-second value to a human-readable speed string. */
export function formatSpeed(bps: number): string {
  const mbps = bps / 1_000_000;
  if (mbps >= 100) return `${Math.round(mbps)} Mbps`;
  if (mbps >= 10) return `${mbps.toFixed(0)} Mbps`;
  if (mbps >= 1) return `${mbps.toFixed(1)} Mbps`;
  const kbps = bps / 1_000;
  if (kbps >= 1) return `${kbps.toFixed(0)} Kbps`;
  return "0 Kbps";
}

/** Format seconds to a human-readable uptime string (e.g. "2h 14m"). */
export function formatUptime(totalSecs: number): string {
  if (totalSecs <= 0) return "--";
  const h = Math.floor(totalSecs / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  const s = totalSecs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
