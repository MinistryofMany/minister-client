// The optional persistence seam: SnapshotStore, plus the package-shipped
// liveSnapshotStore that recomputes the root live and never persists.
//
// This is the key move that unifies "stored snapshot" (FreedInk/Deforum) and
// "live recomputed root" (Discreetly) behind one verify(): both become "resolve
// the root to a snapshot via the SnapshotStore." FreedInk's store reads a row;
// the live store recomputes. The package never branches on "does this app
// persist snapshots."

import { currentSnapshot } from "./snapshot.js";
import type { MerkleGroupProvider } from "./provider.js";
import type { FieldString, MembershipSnapshot, TreeRef } from "./types.js";
import type { ProofEngine } from "./engine.js";

/** Options for resolving a proof root to a snapshot. */
export interface GetByRootOptions {
  /**
   * When true, the resolved snapshot's root must equal the CURRENT live root of
   * the tree, not merely a historically-known snapshot of it. This is the
   * banned-exclusion enforcement at verify time (control 2): a just-banned member
   * who proves against the stale pre-ban root is rejected. The store recomputes
   * the live root AT MOST ONCE per call (the live store needs no second
   * recompute; the persisted store does exactly one to compare).
   */
  requireCurrentRoot?: boolean;
}

/** Discriminated result of resolving a root. Distinguishes "no such snapshot for
 *  this tree" from "known but no longer the current root" so the engine returns
 *  the right VerifyFailure. */
export type GetByRootResult =
  | { found: true; snapshot: MembershipSnapshot }
  | { found: false; stale: boolean };

export interface SnapshotStore {
  /**
   * Persist a frozen snapshot idempotently. Returns the stored snapshot (with
   * snapshotId). Idempotent on (context, subTree, root) - re-freezing an
   * unchanged tree is a no-op insert (verified: FreedInk refreshSnapshot skips
   * insert if a row with same (blog, cap, root) exists).
   */
  put(snapshot: MembershipSnapshot): Promise<MembershipSnapshot>;

  /**
   * Resolve a proof's root to a snapshot, PINNED to (context, subTree). The pin
   * is the R1 authorization control: a proof's root is only honored against the
   * tree it was frozen for (verified: getSnapshotByRoot(blogId, capability,
   * root)). When `requireCurrentRoot` is set, the snapshot is returned only if
   * its root is the tree's current live root.
   */
  getByRoot(
    ref: TreeRef,
    root: FieldString,
    opts?: GetByRootOptions,
  ): Promise<GetByRootResult>;
}

// ---------------------------------------------------------------------------
// liveSnapshotStore - the Discreetly path: no persistence, root recomputed live.
// ---------------------------------------------------------------------------

/**
 * Package-provided SnapshotStore for apps that never persist snapshots
 * (Discreetly). `put()` is a no-op echo; `getByRoot()` recomputes the live root
 * from the provider ONCE and returns a synthetic snapshot iff the requested root
 * equals that live root. This reproduces Discreetly's
 * `expectedRoot = computeRoot(live leaves)` check (verified verify-message.ts)
 * behind the same interface FreedInk uses, so verify() has one code path.
 *
 * Because the live store has no notion of a "historical" snapshot, the live root
 * IS the only acceptable root: `requireCurrentRoot` is therefore always
 * effectively true here, and a non-current root resolves to `{ found:false,
 * stale:true }`. The recompute happens exactly once per getByRoot - there is no
 * second recompute for the requireCurrentRoot check (the design's live-store
 * cost risk).
 *
 * The engine defaults to the shipped engine for `provider.engine`; pass an
 * explicit engine to override (e.g. a custom-configured one).
 */
export function liveSnapshotStore(
  provider: MerkleGroupProvider,
  engine?: ProofEngine,
): SnapshotStore {
  return {
    async put(snapshot: MembershipSnapshot): Promise<MembershipSnapshot> {
      // No persistence: echo the snapshot back unchanged (no snapshotId).
      return snapshot;
    },

    async getByRoot(
      ref: TreeRef,
      root: FieldString,
      _opts?: GetByRootOptions,
    ): Promise<GetByRootResult> {
      const eng = engine ?? (await resolveShippedEngine(provider));
      // ONE recompute of the live root.
      const live = await currentSnapshot(provider, eng, ref);
      if (live.root !== root) {
        // The live store has no history, so any non-current root is stale.
        return { found: false, stale: true };
      }
      return { found: true, snapshot: live };
    },
  };
}

/**
 * Lazily resolve the shipped engine matching a provider's `engine`. Imported
 * lazily to avoid a static import cycle (engines import the store's TYPES only).
 * engineFor is itself async (the rln engine sits behind a dynamic import), so
 * this awaits through both hops.
 */
async function resolveShippedEngine(provider: MerkleGroupProvider): Promise<ProofEngine> {
  const { engineFor } = await import("./engines/index.js");
  return await engineFor(provider.engine);
}
