import { RLNProver } from "rlnjs";
import type { RLNFullProof } from "rlnjs";
import { merkleProofForLeaf } from "./merkle.js";
import type { ArtifactSource } from "./artifacts.js";
import type { RlnProof } from "./proof.js";

/**
 * Inputs to generate an RLN proof. All bigints - no Semaphore/rlnjs type is
 * exposed. The caller supplies the room's leaf set (rate commitments, as bigint
 * or stored string) and the prover builds the depth-20 Merkle proof internally,
 * so the zk-kit MerkleProof never crosses the public surface.
 */
export interface GenerateRlnProofInputs {
  rlnIdentifier: bigint;
  /** The RLN identity secret (poseidon2([nullifier, trapdoor])). */
  identitySecret: bigint;
  userMessageLimit: bigint;
  messageId: bigint;
  /** The full room leaf set (rate commitments) the proof is anchored to. */
  leaves: readonly (string | bigint)[];
  /** This member's leaf within `leaves` (= getRateCommitmentHash(commitment, limit)). */
  leaf: bigint;
  /** Signal hash (x) from calculateSignalHash. */
  x: bigint;
  epoch: bigint;
}

/** Convert the rlnjs RLNFullProof to the plain, bigint/string-only public struct. */
function toPublicProof(full: RLNFullProof): RlnProof {
  const ps = full.snarkProof.publicSignals;
  const pr = full.snarkProof.proof;
  return {
    snarkProof: {
      proof: {
        pi_a: pr.pi_a.map(String),
        pi_b: pr.pi_b.map((row) => row.map(String)),
        pi_c: pr.pi_c.map(String),
        protocol: String(pr.protocol),
        curve: String(pr.curve),
      },
      publicSignals: {
        x: String(ps.x),
        externalNullifier: String(ps.externalNullifier),
        y: String(ps.y),
        root: String(ps.root),
        nullifier: String(ps.nullifier),
      },
    },
    epoch: BigInt(full.epoch),
    rlnIdentifier: BigInt(full.rlnIdentifier),
  };
}

/**
 * Generate an RLN proof. The math is byte-for-byte the Discreetly v2 path
 * (rlnjs RLNProver over the depth-20 circuit); only the artifact loading is
 * injected via `artifacts` instead of a hard-coded circuits package.
 */
export async function generateRlnProof(
  inputs: GenerateRlnProofInputs,
  artifacts: ArtifactSource,
): Promise<RlnProof> {
  const { wasm, zkey } = await artifacts.prover();
  const merkleProof = merkleProofForLeaf(inputs.rlnIdentifier, inputs.leaves, inputs.leaf);
  const prover = new RLNProver(wasm, zkey);
  const full = await prover.generateProof({
    rlnIdentifier: inputs.rlnIdentifier,
    identitySecret: inputs.identitySecret,
    userMessageLimit: inputs.userMessageLimit,
    messageId: inputs.messageId,
    merkleProof,
    x: inputs.x,
    epoch: inputs.epoch,
  });
  return toPublicProof(full);
}
