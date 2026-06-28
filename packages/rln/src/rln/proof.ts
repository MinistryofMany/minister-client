/**
 * Public, bigint/string-only RLN proof structs. These are structurally identical
 * to rlnjs's `RLNFullProof` but defined with our OWN field types so the public
 * d.ts never references rlnjs. The proof is plain data (no class instances), so a
 * value crosses the boundary by structure - the island stays a black box.
 */

/** A decimal (or 0x-hex) field element serialized as a string, as rlnjs emits. */
export type FieldString = string;

/** Groth16 proof points, exactly the shape snarkjs/rlnjs produce. */
export interface Groth16Proof {
  pi_a: FieldString[];
  pi_b: FieldString[][];
  pi_c: FieldString[];
  protocol: string;
  curve: string;
}

/** RLN circuit public signals. */
export interface RlnPublicSignals {
  x: FieldString;
  externalNullifier: FieldString;
  y: FieldString;
  root: FieldString;
  nullifier: FieldString;
}

/** SNARK proof + its public signals. */
export interface RlnSnarkProof {
  proof: Groth16Proof;
  publicSignals: RlnPublicSignals;
}

/** Full RLN proof. Mirrors rlnjs `RLNFullProof` structurally; bigint-only public type. */
export interface RlnProof {
  snarkProof: RlnSnarkProof;
  epoch: bigint;
  rlnIdentifier: bigint;
}
