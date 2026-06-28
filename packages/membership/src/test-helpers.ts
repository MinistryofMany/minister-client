// Test-only helpers (NOT part of the public surface; imported only by tests, so
// the entry-point-only tsup build never bundles it into dist).
//
// An in-memory persisted SnapshotStore (the FreedInk/Deforum shape: reads a row,
// pins on (context, subTree, root)) used to exercise the persisted-store path and
// the R1 authorization pin. The package ships only liveSnapshotStore by design;
// apps implement their own persisted store over their ORM, so this reference one
// lives with the tests.

import type { GetByRootOptions, GetByRootResult, SnapshotStore } from "./store.js";
import { currentSnapshot } from "./snapshot.js";
import type { ProofEngine } from "./engine.js";
import type { MerkleGroupProvider } from "./provider.js";
import type { FieldString, MembershipSnapshot, TreeRef } from "./types.js";

function key(ref: TreeRef, root: FieldString): string {
  // The R1 coordinate: (context, subTree, root). A proof's root is honored only
  // against the tree it was frozen for. The pipe separator is a delimiter the
  // app-defined ids do not contain in tests.
  return [ref.context, ref.subTree, root].join("|");
}

/**
 * An in-memory persisted store. When `liveProvider` + `engine` are supplied, a
 * `requireCurrentRoot` lookup recomputes the live root ONCE and rejects a row
 * whose root is no longer current (the FreedInk requireCurrentRoot semantics).
 */
export function inMemorySnapshotStore(opts?: {
  liveProvider?: MerkleGroupProvider;
  engine?: ProofEngine;
}): SnapshotStore & { size(): number } {
  const rows = new Map<string, MembershipSnapshot>();
  let seq = 0;

  return {
    size() {
      return rows.size;
    },

    async put(snapshot: MembershipSnapshot): Promise<MembershipSnapshot> {
      const k = key(snapshot.ref, snapshot.root);
      const existing = rows.get(k);
      if (existing) return existing; // idempotent on (context, subTree, root)
      seq += 1;
      const stored: MembershipSnapshot = { ...snapshot, snapshotId: `snap-${seq}` };
      rows.set(k, stored);
      return stored;
    },

    async getByRoot(
      ref: TreeRef,
      root: FieldString,
      o?: GetByRootOptions,
    ): Promise<GetByRootResult> {
      const found = rows.get(key(ref, root));
      if (!found) return { found: false, stale: false };
      if (o?.requireCurrentRoot && opts?.liveProvider && opts?.engine) {
        // Recompute the live root ONCE and compare.
        const live = await currentSnapshot(opts.liveProvider, opts.engine, ref);
        if (live.root !== root) return { found: false, stale: true };
      }
      return { found: true, snapshot: found };
    },
  };
}
