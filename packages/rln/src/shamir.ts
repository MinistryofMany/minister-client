import { ZqField } from "ffjavascript";
import { poseidon1 } from "poseidon-lite";

// BN254 scalar field used by the RLN circuit.
const SNARK_FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
const Fq = new ZqField(SNARK_FIELD_SIZE);

/**
 * Recovers the RLN identity secret (the line's y-intercept) from two messages
 * sent in the same epoch (a rate-limit collision).
 */
export function shamirRecovery(x1: bigint, x2: bigint, y1: bigint, y2: bigint): bigint {
  const slope = Fq.div(Fq.sub(y2, y1), Fq.sub(x2, x1));
  const privateKey = Fq.sub(y1, Fq.mul(slope, x1));
  return Fq.normalize(privateKey);
}

export function getIdentityCommitmentFromSecret(secret: bigint): bigint {
  return poseidon1([secret]);
}
