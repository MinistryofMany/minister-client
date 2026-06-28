import { Group } from "@semaphore-protocol/group";
import type { MerkleProof } from "@zk-kit/incremental-merkle-tree";
import { MERKLE_TREE_DEPTH } from "../constants.js";

export { MERKLE_TREE_DEPTH };

/**
 * Strips the legacy BigInt `n` suffix (and any stray non-digits) from stored
 * identity/rate-commitment strings before they enter the tree.
 */
export function sanitizeLeaves(identities: readonly (string | bigint)[]): bigint[] {
  return identities.map((i) => BigInt(String(i).replace(/\D/g, "")));
}

/**
 * Build the fixed-depth-20 v3 Group. PRIVATE: the Group object never leaves this
 * package - callers receive bigint roots and plain merkle-proof structs only.
 */
export function buildGroup(rlnIdentifier: bigint, leaves: readonly (string | bigint)[]): Group {
  return new Group(rlnIdentifier, MERKLE_TREE_DEPTH, sanitizeLeaves(leaves));
}

/** The Merkle root of the room's leaf set, as a bigint (no Group type leak). */
export function computeRoot(rlnIdentifier: bigint, leaves: readonly (string | bigint)[]): bigint {
  return BigInt(buildGroup(rlnIdentifier, leaves).root);
}

/**
 * Build a Merkle proof for `leaf` within the room's leaf set. PRIVATE - returns
 * the raw zk-kit MerkleProof consumed only by the internal RLN prover; it is not
 * part of the public surface.
 */
export function merkleProofForLeaf(
  rlnIdentifier: bigint,
  leaves: readonly (string | bigint)[],
  leaf: bigint,
): MerkleProof {
  const group = buildGroup(rlnIdentifier, leaves);
  return group.generateMerkleProof(group.indexOf(leaf));
}
