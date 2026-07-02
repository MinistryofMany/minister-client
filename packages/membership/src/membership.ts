// createMembership - the server-side composition entry point.
//
// Wires a provider + (optional) store + (optional) engine into { current,
// refresh, verify }. `current` computes the live snapshot; `refresh` freezes +
// persists it idempotently; `verify` checks a proof against the resolved
// snapshot and returns the nullifier. This is FreedInk currentMembership +
// refreshSnapshot + verifyMembership and Discreetly computeRoot + verify-message,
// unified behind the seams.

import { engineFor } from "./engines/index.js";
import type { MembershipProof, ProofEngine, VerifyContext, VerifyResult } from "./engine.js";
import type { MerkleGroupProvider } from "./provider.js";
import { currentSnapshot } from "./snapshot.js";
import { liveSnapshotStore } from "./store.js";
import type { SnapshotStore } from "./store.js";
import type { MembershipSnapshot, TreeRef } from "./types.js";

export interface MembershipConfig {
  provider: MerkleGroupProvider;
  /** Defaults to liveSnapshotStore(provider, engine) when omitted (Discreetly
   *  path). FreedInk/Deforum pass a persisted store. */
  store?: SnapshotStore;
  /** Defaults to the shipped engine matching provider.engine. */
  engine?: ProofEngine<MembershipProof>;
}

export interface Membership {
  /** Compute the current live snapshot for a tree (root + ordered leaves +
   *  count). FreedInk currentMembership + Discreetly computeRoot, unified. */
  current(ref: TreeRef): Promise<MembershipSnapshot>;

  /**
   * Freeze + persist the current snapshot via the store (idempotent). For the
   * live store this is `current()` with a no-op put. Returns the persisted
   * snapshot. Mirrors FreedInk refreshSnapshot.
   *
   * Banned-exclusion (control 2): because `current()` reads the provider's
   * already-exclusion-filtered leaf set, a refresh AFTER a ban yields a NEW root
   * the just-banned member cannot prove against - and verify with
   * requireCurrentRoot rejects any older root.
   */
  refresh(ref: TreeRef): Promise<MembershipSnapshot>;

  /** Server: verify a proof against the resolved snapshot, return the nullifier.
   *  The store is injected by the package; the caller never passes it. */
  verify(ctx: Omit<VerifyContext, "store">): Promise<VerifyResult>;
}

export function createMembership(config: MembershipConfig): Membership {
  // An EXPLICIT engine is validated synchronously, exactly as before. The
  // defaulted engine cannot mismatch (engineFor returns the engine matching
  // provider.engine by construction), so the guard only needs the explicit case.
  if (config.engine && config.engine.kind !== config.provider.engine) {
    throw new Error(
      `createMembership: provider.engine=${config.provider.engine} but engine.kind=${config.engine.kind}.`,
    );
  }

  // The DEFAULT engine is resolved lazily (memoized) because engineFor is async:
  // the rln engine sits behind a dynamic import so a semaphore-only consumer
  // never loads the @ministryofmany/rln island. createMembership itself stays
  // synchronous; every method that needs the engine is already async.
  let lazyEngine: Promise<ProofEngine<MembershipProof>> | null = null;
  const resolveEngine = (): Promise<ProofEngine<MembershipProof>> =>
    (lazyEngine ??= config.engine
      ? Promise.resolve(config.engine)
      : engineFor(config.provider.engine));

  // liveSnapshotStore resolves the shipped engine itself when none is given.
  const store = config.store ?? liveSnapshotStore(config.provider, config.engine);

  return {
    async current(ref: TreeRef): Promise<MembershipSnapshot> {
      return currentSnapshot(config.provider, await resolveEngine(), ref);
    },

    async refresh(ref: TreeRef): Promise<MembershipSnapshot> {
      const snap = await currentSnapshot(config.provider, await resolveEngine(), ref);
      return store.put(snap);
    },

    async verify(ctx: Omit<VerifyContext, "store">): Promise<VerifyResult> {
      const engine = await resolveEngine();
      return engine.verify({ ...ctx, store });
    },
  };
}
