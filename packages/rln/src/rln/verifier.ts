import { RLNVerifier } from "rlnjs";
import type { RLNFullProof, VerificationKey } from "rlnjs";
import type { ArtifactSource, RlnVerificationKey } from "./artifacts.js";
import type { RlnProof } from "./proof.js";

export interface VerifyRlnProofParams {
  rlnIdentifier: bigint;
  proof: RlnProof;
  /** Expected signal hash (x) recomputed from the message by the caller. */
  signalHash: bigint;
  /** Epoch claimed by the message. */
  epoch: bigint;
  /** Server's current epoch = floor(now / rateLimit). */
  currentEpoch: bigint;
  /** Allowed epoch skew on each side. Default 1 (matches the legacy verifier). */
  epochErrorRange?: bigint;
  /**
   * The room/group Merkle root the proof MUST match. REQUIRED: the Groth16 proof
   * binds to whatever root the prover chose, so without pinning it here a prover
   * could stuff a single-leaf tree with their own rate-commitment and bypass
   * membership. The caller must supply the server's authoritative current root.
   */
  expectedRoot: bigint;
}

/** Reconstruct the rlnjs RLNFullProof shape from the plain public struct. */
function toRlnjsProof(proof: RlnProof): RLNFullProof {
  return proof as unknown as RLNFullProof;
}

/**
 * Verify an RLN proof. Reproduces the legacy four checks byte-for-byte (epoch
 * window, signal-hash match, Merkle-root match, SNARK verification), normalizing
 * the root to BigInt before comparing. The verification key is injected via
 * `artifacts` rather than read from a hard-coded circuits package.
 */
export async function verifyRlnProof(
  params: VerifyRlnProofParams,
  artifacts: ArtifactSource,
): Promise<boolean> {
  const {
    rlnIdentifier,
    proof,
    signalHash,
    epoch,
    currentEpoch,
    epochErrorRange = 1n,
    expectedRoot,
  } = params;

  if (typeof expectedRoot !== "bigint") {
    throw new TypeError("verifyRlnProof requires expectedRoot (the authoritative group root).");
  }

  if (epoch < currentEpoch - epochErrorRange || epoch > currentEpoch + epochErrorRange) {
    return false;
  }
  if (signalHash !== BigInt(proof.snarkProof.publicSignals.x)) {
    return false;
  }
  if (expectedRoot !== BigInt(proof.snarkProof.publicSignals.root)) {
    return false;
  }
  const key = (await artifacts.verificationKey()) as RlnVerificationKey;
  const verifier = new RLNVerifier(key as VerificationKey);
  return verifier.verifyProof(rlnIdentifier, toRlnjsProof(proof));
}
