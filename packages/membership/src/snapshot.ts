// Live snapshot construction: turn a provider's eligible leaf set into a frozen
// { root, ordered leaves, count } snapshot, using the engine to map commitments
// to leaves and to compute the root. This is FreedInk currentMembership +
// Discreetly computeRoot, unified, and is the single place root computation
// happens, so the live store and createMembership.current cannot diverge.

import type { ProofEngine } from "./engine.js";
import { orderLeaves } from "./order.js";
import { resolveEngineParams } from "./provider.js";
import type { MerkleGroupProvider } from "./provider.js";
import type { Leaf, MembershipSnapshot, TreeRef } from "./types.js";

/**
 * Compute the current live snapshot for a tree: the deterministically-ordered,
 * exclusion-filtered leaf set the provider returns, plus the root the engine
 * derives from it. The leaves the provider returns are ALREADY engine-mapped
 * (the provider stores rate commitments for RLN, bare ic for Semaphore), so we
 * brand them through the engine's `toLeaf` only when we must map an ic; here we
 * trust the provider's `leaf` and brand it for the engine via the engine's own
 * root computation, which accepts branded leaves.
 *
 * Banned-exclusion (control 2) happens INSIDE the provider's `listEligible`: a
 * just-banned member is omitted from the returned set, so the root computed here
 * is a new root they cannot prove against. This function does not re-filter; it
 * trusts the provider's exclusion seam (the definitional per-app boundary).
 */
export async function currentSnapshot(
  provider: MerkleGroupProvider,
  engine: ProofEngine,
  ref: TreeRef,
): Promise<MembershipSnapshot> {
  if (engine.kind !== provider.engine) {
    throw new Error(
      `engine/provider mismatch: provider.engine=${provider.engine} but engine.kind=${engine.kind}.`,
    );
  }
  const params = await resolveEngineParams(provider, ref.context);
  const eligible = await provider.listEligible(ref);
  const ordered = orderLeaves(eligible);

  // The provider's `leaf` is the engine-mapped value. We re-mint it through the
  // engine's `toLeaf` from the commitment so the brand is established by the
  // single audited boundary (asSemaphoreLeaf / asRlnLeaf) rather than trusting a
  // raw string, and so a provider that returned an unmapped leaf cannot smuggle
  // a wrong leaf past the engine. toLeaf is deterministic and equals the
  // provider's leaf for a correct provider (asserted by the engine round-trip
  // tests).
  const leaves: Leaf[] = ordered.map((e) => engine.toLeaf(e.commitment, params));
  const root = await engine.computeRoot(leaves, provider.shape, params);

  return {
    ref,
    root,
    leaves: leaves as unknown as string[],
    eligibleCount: leaves.length,
    shape: provider.shape,
    engine: provider.engine,
  };
}
