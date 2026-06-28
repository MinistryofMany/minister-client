/**
 * Frozen constants + golden vectors for the RLN quarantine island.
 *
 * This file is a TRIPWIRE. The RLN circuit, Shamir recovery, and rate-commitment
 * leaf hash are all bound to specific Poseidon outputs over the BN254 scalar
 * field. poseidon-lite is pinned to 0.2.0 (no caret) across this package; a
 * future 0.4.x could silently change the permutation and break every commitment,
 * nullifier, and Merkle root without any obvious error. The golden vectors below
 * are asserted in constants.test.ts against the INSTALLED poseidon-lite so any
 * drift fails the test suite loudly.
 *
 * Do not "fix" a failing golden vector by editing the expected value - a changed
 * value means the hashing math moved and the island is no longer compatible with
 * existing data and circuits.
 */

/** BN254 scalar field size used by the RLN circuit (and ffjavascript ZqField). */
export const SNARK_FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/** RLN circuit Merkle tree depth (fixed by the compiled depth-20 circuit). */
export const MERKLE_TREE_DEPTH = 20;

/** Exact poseidon-lite major.minor.patch this island is pinned to. */
export const PINNED_POSEIDON_LITE_VERSION = "0.2.0";

/**
 * Golden Poseidon vectors. Each is an input -> expected field element, computed
 * by the audited Discreetly v2 stack on poseidon-lite 0.2.0. Asserted against
 * the installed poseidon-lite in constants.test.ts.
 */
export const GOLDEN_VECTORS = {
  /** poseidon1([12345n]) - getIdentityCommitmentFromSecret(12345n). */
  poseidon1_secret_12345:
    4267533774488295900887461483015112262021273608761099826938271132511348470966n,
  /** poseidon2([123n, 1n]) - getRateCommitmentHash(123n, 1). */
  poseidon2_rateCommitment_123_1:
    1825367215715080944898610730329185918884251567885580835209236772238472514878n,
} as const;
