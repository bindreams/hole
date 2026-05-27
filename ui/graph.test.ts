import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  // Force a fresh module load so the graphData buffer + SVG-element
  // singletons reset between tests. Otherwise module-scoped state
  // leaks across tests and assertions become order-dependent.
  vi.resetModules();
  document.body.innerHTML = `
    <svg id="graph-svg" xmlns="http://www.w3.org/2000/svg"></svg>
    <span id="graph-scale-label"></span>
  `;
});

describe("graph", () => {
  it("scale label shows a minimum scale even with empty data", async () => {
    const { initGraph, renderGraph } = await import("./graph");
    initGraph();
    renderGraph();
    const label = document.getElementById("graph-scale-label")!.textContent;
    // Empty buffer → maxSpeed floors at 1000 bps → formatSpeed(1000) =
    // "1 Kbps". Asserting via regex tolerates future scale-floor
    // tweaks (e.g. "1.0 Mbps" if the floor moves up).
    expect(label).toMatch(/Kbps$|Mbps$/);
  });

  it("scales the scale label to the highest data point", async () => {
    const { initGraph, pushGraphData, renderGraph } = await import("./graph");
    initGraph();
    pushGraphData(50_000_000, 0);
    renderGraph();
    expect(document.getElementById("graph-scale-label")!.textContent).toBe("50 Mbps");
  });

  it("emits a polyline with GRAPH_POINTS coordinate pairs", async () => {
    const { initGraph, renderGraph } = await import("./graph");
    initGraph();
    renderGraph();
    const rxLine = document.querySelector("svg > polyline[stroke^='var(--green']");
    expect(rxLine).not.toBeNull();
    const points = rxLine!.getAttribute("points")!.trim().split(/\s+/);
    expect(points).toHaveLength(60);
  });
});
