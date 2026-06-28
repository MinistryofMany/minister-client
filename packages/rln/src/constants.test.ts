import { describe, it, expect } from "vitest";
import { poseidon1, poseidon2 } from "poseidon-lite";
import {
  GOLDEN_VECTORS,
  MERKLE_TREE_DEPTH,
  PINNED_POSEIDON_LITE_VERSION,
  SNARK_FIELD_SIZE,
} from "./constants.js";
import { getIdentityCommitmentFromSecret } from "./shamir.js";
import { getRateCommitmentHash } from "./field.js";

// Tripwire: assert the golden Poseidon vectors against the INSTALLED poseidon-lite.
// If poseidon-lite is ever bumped off 0.2.0 and the permutation shifts, these
// fail loudly instead of silently invalidating every commitment / nullifier / root.
describe("poseidon-lite golden-vector tripwire", () => {
  it("poseidon-lite is pinned to exactly 0.2.0", async () => {
    const pkg = (await import("poseidon-lite/package.json", { with: { type: "json" } })).default as {
      version: string;
    };
    expect(pkg.version).toBe(PINNED_POSEIDON_LITE_VERSION);
    expect(PINNED_POSEIDON_LITE_VERSION).toBe("0.2.0");
  });

  it("poseidon1 matches the frozen golden vector", () => {
    expect(poseidon1([12345n])).toBe(GOLDEN_VECTORS.poseidon1_secret_12345);
    expect(getIdentityCommitmentFromSecret(12345n)).toBe(GOLDEN_VECTORS.poseidon1_secret_12345);
  });

  it("poseidon2 matches the frozen rate-commitment golden vector", () => {
    expect(poseidon2([123n, 1n])).toBe(GOLDEN_VECTORS.poseidon2_rateCommitment_123_1);
    expect(getRateCommitmentHash(123n, 1)).toBe(GOLDEN_VECTORS.poseidon2_rateCommitment_123_1);
  });

  it("exposes the frozen field size and circuit depth", () => {
    expect(SNARK_FIELD_SIZE).toBe(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    );
    expect(MERKLE_TREE_DEPTH).toBe(20);
  });
});
