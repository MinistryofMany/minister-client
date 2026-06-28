// @minister/membership/client - client-only proof generation.
//
// Exported from a separate subpath so the heavy prover deps (the Semaphore proof
// WASM / the RLN circuit) stay out of server bundles, matching FreedInk's
// lazy-import + Discreetly's transpilePackages split. The server entry point
// (the package root) never imports this module.

import { engineFor } from "./engines/index.js";
import type { MembershipProof, ProveContext } from "./engine.js";

export type {
  MembershipProof,
  ProveContext,
  SemaphoreProof,
  RlnProof,
} from "./engine.js";
export type { ArtifactSource } from "./artifacts.js";
export { hashPinnedArtifactSource, staticArtifactSource } from "./artifacts.js";

/**
 * Generate a membership proof for the given context. The engine is selected from
 * `snapshot.engine` so the client never has to name the proof system: a snapshot
 * frozen under the Semaphore engine yields a Semaphore proof, one frozen under
 * the RLN engine yields an RLN proof. The returned proof carries its `kind`.
 */
export async function generateMembershipProof(ctx: ProveContext): Promise<MembershipProof> {
  const engine = engineFor(ctx.snapshot.engine);
  return engine.prove(ctx);
}
