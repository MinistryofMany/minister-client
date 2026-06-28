// The two shipped engines + a resolver from EngineKind to the engine.

import type { EngineKind } from "../types.js";
import type { MembershipProof, ProofEngine } from "../engine.js";
import { semaphoreEngine } from "./semaphore.js";
import { rlnEngine } from "./rln.js";

export { semaphoreEngine } from "./semaphore.js";
export { rlnEngine } from "./rln.js";

/** Resolve the shipped engine for an EngineKind. Used to default
 *  createMembership / liveSnapshotStore to the engine matching provider.engine. */
export function engineFor(kind: EngineKind): ProofEngine<MembershipProof> {
  switch (kind) {
    case "semaphore":
      return semaphoreEngine as ProofEngine<MembershipProof>;
    case "rln":
      return rlnEngine as ProofEngine<MembershipProof>;
    default: {
      // Exhaustiveness guard: a new EngineKind must add a case here.
      const never: never = kind;
      throw new Error(`unknown engine kind: ${String(never)}`);
    }
  }
}
