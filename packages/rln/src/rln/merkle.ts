import { Group } from "@semaphore-protocol/group";
import type { MerkleProof } from "@zk-kit/incremental-merkle-tree";
import { MERKLE_TREE_DEPTH } from "../constants.js";

export { MERKLE_TREE_DEPTH };

/**
 * Normalize stored identity/rate-commitment values to bigints before they enter
 * the tree.
 *
 * Accepts a plain decimal string (optionally with the legacy BigInt `n` suffix,
 * e.g. "123n") or a bigint. REJECTS (throws) any other shape: a malformed leaf
 * like "1x2x3" must NOT be silently coerced - stripping non-digits would turn it
 * into "123" and shift the Merkle root (fail-closed). Real providers only ever
 * pass valid decimal leaves, so the byte-for-byte RLN tree math is unchanged;
 * only malformed input now fails loudly.
 */
export function sanitizeLeaves(identities: readonly (string | bigint)[]): bigint[] {
  return identities.map((i) => {
    if (typeof i === "bigint") return i;
    // Optional leading minus is rejected (leaves are field elements >= 0); accept
    // a run of decimal digits with an optional legacy trailing `n`.
    const s = i.trim();
    if (!/^\d+n?$/.test(s)) {
      throw new Error(
        `sanitizeLeaves: malformed leaf ${JSON.stringify(i)} is not a decimal value; ` +
          `refusing to coerce it (a silent strip would shift the Merkle root).`,
      );
    }
    return BigInt(s.endsWith("n") ? s.slice(0, -1) : s);
  });
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
