// The two shipped engines + a resolver from EngineKind to the engine.
//
// PACKAGING BOUNDARY (Stage 0 of the FreedInk migration): ./rln.js transitively
// imports @ministryofmany/rln (rlnjs + Semaphore v3 + the depth-20 circuit). A
// static import here dragged that island into EVERY consumer's graph - including
// semaphore-only SSR consumers that never select the RLN engine. So the rln
// module is loaded ONLY via a memoized dynamic import when a consumer actually
// selects the rln backend; the semaphore engine stays fully static/sync.
// @ministryofmany/rln is an OPTIONAL peer dependency: rln consumers install it
// alongside this package (or import @ministryofmany/membership/rln statically).

import type { EngineKind } from "../types.js";
import type { MembershipProof, ProofEngine, RlnProof } from "../engine.js";
import { semaphoreEngine } from "./semaphore.js";

export { semaphoreEngine } from "./semaphore.js";

let rlnLoad: Promise<ProofEngine<RlnProof>> | null = null;

/**
 * Lazily load the shipped RLN engine (memoized). This is the ONLY sanctioned
 * runtime path from the package root to ./rln.js; it fails with a clear error
 * when the optional peer @ministryofmany/rln is not installed. RLN consumers who
 * prefer a static import use the @ministryofmany/membership/rln subpath instead.
 */
export function loadRlnEngine(): Promise<ProofEngine<RlnProof>> {
  rlnLoad ??= (async () => {
    try {
      const { rlnEngine } = await import("./rln.js");
      return rlnEngine;
    } catch (err) {
      throw new Error(
        "the rln engine requires the optional peer dependency @ministryofmany/rln; " +
          "install it alongside @ministryofmany/membership to use the rln backend",
        { cause: err },
      );
    }
  })();
  return rlnLoad;
}

/** Resolve the shipped engine for an EngineKind. Used to default
 *  createMembership / liveSnapshotStore to the engine matching provider.engine.
 *  ASYNC because the rln engine is behind the lazy import above; the semaphore
 *  branch resolves immediately from the static module. */
export async function engineFor(kind: EngineKind): Promise<ProofEngine<MembershipProof>> {
  switch (kind) {
    case "semaphore":
      return semaphoreEngine as ProofEngine<MembershipProof>;
    case "rln":
      return (await loadRlnEngine()) as ProofEngine<MembershipProof>;
    default: {
      // Exhaustiveness guard: a new EngineKind must add a case here.
      const never: never = kind;
      throw new Error(`unknown engine kind: ${String(never)}`);
    }
  }
}
