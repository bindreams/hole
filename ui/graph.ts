// Throughput graph — circular buffer + SVG renderer. Owns the
// #graph-svg and #graph-scale-label DOM elements.

import { formatSpeed } from "./formatting";

const GRAPH_POINTS = 60;
const SVG_W = 220;
const SVG_H = 80;
const SVG_NS = "http://www.w3.org/2000/svg";

interface DataPoint {
  speedIn: number;
  speedOut: number;
}

const graphData: DataPoint[] = [];
for (let i = 0; i < GRAPH_POINTS; i++) graphData.push({ speedIn: 0, speedOut: 0 });

let graphSvg: HTMLElement | null = null;
let graphScaleLabel: HTMLElement | null = null;
let rxFill: SVGPathElement | null = null;
let rxLine: SVGPolylineElement | null = null;
let txFill: SVGPathElement | null = null;
let txLine: SVGPolylineElement | null = null;

/** Initialize the graph: bind DOM refs, set up SVG elements. Must be called once at startup. */
export function initGraph(): void {
  graphSvg = document.getElementById("graph-svg");
  graphScaleLabel = document.getElementById("graph-scale-label");
  if (!graphSvg || !graphScaleLabel) return;

  rxFill = document.createElementNS(SVG_NS, "path");
  rxFill.setAttribute("fill", "var(--graph-fill-rx)");
  rxFill.setAttribute("stroke", "none");

  rxLine = document.createElementNS(SVG_NS, "polyline");
  rxLine.setAttribute("fill", "none");
  rxLine.setAttribute("stroke", "var(--green)");
  rxLine.setAttribute("stroke-width", "1.5");
  rxLine.setAttribute("stroke-linejoin", "round");

  txFill = document.createElementNS(SVG_NS, "path");
  txFill.setAttribute("fill", "var(--graph-fill-tx)");
  txFill.setAttribute("stroke", "none");

  txLine = document.createElementNS(SVG_NS, "polyline");
  txLine.setAttribute("fill", "none");
  txLine.setAttribute("stroke", "var(--amber)");
  txLine.setAttribute("stroke-width", "1.5");
  txLine.setAttribute("stroke-linejoin", "round");

  graphSvg.appendChild(rxFill);
  graphSvg.appendChild(txFill);
  graphSvg.appendChild(rxLine);
  graphSvg.appendChild(txLine);

  renderGraph();
}

/** Append a fresh data point and discard the oldest. */
export function pushGraphData(speedIn: number, speedOut: number): void {
  graphData.shift();
  graphData.push({ speedIn, speedOut });
}

/** Recompute SVG paths from the current buffer + repaint the scale label. */
export function renderGraph(): void {
  if (!graphScaleLabel || !rxFill || !rxLine || !txFill || !txLine) return;

  let maxSpeed = 0;
  for (const pt of graphData) {
    if (pt.speedIn > maxSpeed) maxSpeed = pt.speedIn;
    if (pt.speedOut > maxSpeed) maxSpeed = pt.speedOut;
  }
  if (maxSpeed < 1000) maxSpeed = 1000;

  graphScaleLabel.textContent = formatSpeed(maxSpeed);

  const stepX = SVG_W / (GRAPH_POINTS - 1);
  let rxPts = "";
  let txPts = "";
  let rxFillD = `M0,${SVG_H}`;
  let txFillD = `M0,${SVG_H}`;

  for (let i = 0; i < GRAPH_POINTS; i++) {
    const x = (i * stepX).toFixed(1);
    const yRx = (SVG_H - (graphData[i].speedIn / maxSpeed) * SVG_H).toFixed(1);
    const yTx = (SVG_H - (graphData[i].speedOut / maxSpeed) * SVG_H).toFixed(1);
    rxPts += `${x},${yRx} `;
    txPts += `${x},${yTx} `;
    rxFillD += ` L${x},${yRx}`;
    txFillD += ` L${x},${yTx}`;
  }

  rxFillD += ` L${SVG_W},${SVG_H} Z`;
  txFillD += ` L${SVG_W},${SVG_H} Z`;

  rxLine.setAttribute("points", rxPts.trim());
  txLine.setAttribute("points", txPts.trim());
  rxFill.setAttribute("d", rxFillD);
  txFill.setAttribute("d", txFillD);
}
