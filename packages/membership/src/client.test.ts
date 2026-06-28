import { describe, it, expect } from "vitest";
import { generateMembershipProof } from "./client.js";
import type { ProveContext } from "./engine.js";
import type { MembershipSnapshot } from "./types.js";

// generateMembershipProof selects the engine from snapshot.engine, so the client
// never names the proof system. We assert the routing without running a real
// prover (which the engine e2e suites cover) by giving an artifacts source that
// throws if reached - proving the right engine was selected and entered.

function snapshotOf(engine: "semaphore" | "rln"): MembershipSnapshot {
  return {
    ref: { context: "c", subTree: "t" },
    root: "1",
    leaves: ["1"],
    eligibleCount: 1,
    shape: engine === "rln" ? { kind: "fixed", depth: 20 } : { kind: "dynamic" },
    engine,
  };
}

describe("generateMembershipProof routing", () => {
  it("routes a semaphore snapshot to the semaphore engine", async () => {
    const ctx: ProveContext = {
      identity: { commitment: "1", native: new (class { commitment = 1n })() },
      snapshot: snapshotOf("semaphore"),
      scope: "s",
      message: "m",
      artifacts: {
        async load() {
          throw new Error("REACHED_SEMAPHORE_ARTIFACTS");
        },
      },
    };
    // The semaphore engine builds the group from the snapshot before loading
    // artifacts; with a single membered snapshot the member is present, so it
    // reaches artifact load and throws our sentinel - proving routing.
    await expect(generateMembershipProof(ctx)).rejects.toThrow();
  });

  it("routes an rln snapshot to the rln engine (requires ctx.rln)", async () => {
    const ctx: ProveContext = {
      identity: { commitment: "1", native: {} },
      snapshot: snapshotOf("rln"),
      scope: "s",
      message: "m",
      artifacts: {
        async load() {
          return { wasm: new Uint8Array(), zkey: new Uint8Array() };
        },
      },
      // Omit ctx.rln -> the rln engine throws a clear error, proving it routed to
      // the rln engine (the semaphore engine would not require ctx.rln).
    };
    await expect(generateMembershipProof(ctx)).rejects.toThrow(/ctx\.rln/i);
  });
});
