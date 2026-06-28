import { describe, it, expect } from "vitest";
import { Group } from "@semaphore-protocol/group";
import { computeRoot, sanitizeLeaves, MERKLE_TREE_DEPTH } from "./merkle.js";

describe("depth-20 RLN merkle root", () => {
  it("uses the fixed circuit depth", () => {
    expect(MERKLE_TREE_DEPTH).toBe(20);
  });

  it("computeRoot equals the v3 depth-20 Group root as a bigint", () => {
    const leaves = [111n, 222n, 333n];
    const group = new Group(99n, MERKLE_TREE_DEPTH, [...leaves]);
    expect(group.depth).toBe(20);
    expect(computeRoot(99n, leaves)).toBe(BigInt(group.root));
  });

  it("is a fixed golden value for a known leaf set (tripwire)", () => {
    // Pinned depth-20 root for rlnIdentifier=12345, leaves=[1,2,3]. A drift here
    // means the tree/hash math moved and existing membership proofs would break.
    expect(computeRoot(12345n, [1n, 2n, 3n])).toBe(
      BigInt(new Group(12345n, MERKLE_TREE_DEPTH, [1n, 2n, 3n]).root),
    );
    // Snapshot the literal so a future dependency bump cannot silently change it.
    expect(computeRoot(12345n, [1n, 2n, 3n])).toBe(
      20398829964165053586018577998309851408943128334022996966777195371370254608267n,
    );
  });

  it("is order-sensitive and deterministic", () => {
    expect(computeRoot(1n, [1n, 2n])).toBe(computeRoot(1n, [1n, 2n]));
    expect(computeRoot(1n, [1n, 2n])).not.toBe(computeRoot(1n, [2n, 1n]));
  });

  it("sanitizeLeaves accepts plain decimals, the legacy bigint suffix, and bigints unchanged", () => {
    // Valid decimal leaves (the only thing real providers pass) are unchanged, so
    // the byte-for-byte RLN tree math for real usage is preserved.
    expect(sanitizeLeaves(["123n", "456", 789n])).toEqual([123n, 456n, 789n]);
  });

  it("sanitizeLeaves REJECTS a malformed (non-decimal) leaf instead of stripping it (fail-closed)", () => {
    // FIX C: "1x2x3" must NOT silently become 123 (which would shift the root).
    expect(() => sanitizeLeaves(["1x2x3"])).toThrow(/malformed leaf/i);
    expect(() => sanitizeLeaves(["12.34"])).toThrow(/malformed leaf/i);
    expect(() => sanitizeLeaves(["0xdeadbeef"])).toThrow(/malformed leaf/i);
    expect(() => sanitizeLeaves(["-5"])).toThrow(/malformed leaf/i);
    expect(() => sanitizeLeaves([""])).toThrow(/malformed leaf/i);
    // A valid leaf next to a malformed one still throws (no partial coercion).
    expect(() => sanitizeLeaves(["123", "1x2"])).toThrow(/malformed leaf/i);
  });
});
