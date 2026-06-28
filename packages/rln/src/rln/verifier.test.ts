import { describe, it, expect } from "vitest";
import { verifyRlnProof, type VerifyRlnProofParams } from "./verifier.js";
import { staticArtifactSource } from "./artifacts.js";
import type { ArtifactSource } from "./artifacts.js";
import type { RlnProof } from "./proof.js";

// Offline guard: no proving artifacts and no SNARK math here. This pins the
// fail-CLOSED contract that expectedRoot is REQUIRED, so a consumer can never
// omit it and accept a proof against any root the prover chose.
describe("verifyRlnProof requires expectedRoot (fail-closed membership pin)", () => {
  const dummyArtifacts: ArtifactSource = staticArtifactSource({
    prover: { wasm: "unused.wasm", zkey: "unused.zkey" },
    verificationKey: {},
  });

  const baseParams = {
    rlnIdentifier: 1n,
    proof: { snarkProof: { publicSignals: { root: "5", x: "7" } } } as unknown as RlnProof,
    signalHash: 7n,
    epoch: 1n,
    currentEpoch: 1n,
  };

  it("throws TypeError when expectedRoot is omitted at runtime", async () => {
    await expect(
      // Force the missing-field case past the compile-time required type.
      verifyRlnProof(baseParams as unknown as VerifyRlnProofParams, dummyArtifacts),
    ).rejects.toThrow(TypeError);
  });

  it("rejects (returns false) when the proof root differs from expectedRoot", async () => {
    await expect(
      verifyRlnProof({ ...baseParams, expectedRoot: 6n }, dummyArtifacts),
    ).resolves.toBe(false);
  });
});
