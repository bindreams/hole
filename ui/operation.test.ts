import { describe, expect, it, vi } from "vitest";
import { OperationGate } from "./operation";

describe("OperationGate", () => {
  it("runs settle and is current for the latest operation", () => {
    const gate = new OperationGate();
    const op = gate.begin();
    const write = vi.fn();
    op.settle(write);
    expect(write).toHaveBeenCalledTimes(1);
    expect(op.isCurrent()).toBe(true);
  });

  it("a superseded operation's settle is a no-op and it is not current", () => {
    const gate = new OperationGate();
    const first = gate.begin();
    gate.begin(); // supersedes `first`
    const write = vi.fn();
    first.settle(write);
    expect(write).not.toHaveBeenCalled();
    expect(first.isCurrent()).toBe(false);
  });
});
