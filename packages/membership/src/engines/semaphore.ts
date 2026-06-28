// semaphoreEngine - vanilla Semaphore v4 over @minister/identity.
//
// toLeaf is the identity (the leaf IS the bare identity commitment); the tree is
// a dynamic LeanIMT (new Group(), depth grows with the member count). This is
// FreedInk's machinery, lifted: buildProof (client) + verifyMembership (server),
// byte-for-byte. The Semaphore prover/verifier (@semaphore-protocol/proof) is
// LAZY-imported so it never lands in a server bundle at module-eval time
// (verified: FreedInk SSR-excludes it and lazy-imports).

import { Group } from "@semaphore-protocol/group";
import type { Identity } from "@semaphore-protocol/identity";
import type {
  ProofEngine,
  ProveContext,
  SemaphoreProof,
  VerifyContext,
  VerifyResult,
} from "../engine.js";
import { hashToField } from "../hash.js";
import type { EngineParams } from "../provider.js";
import { asSemaphoreLeaf } from "../types.js";
import type { FieldString, IdentityCommitment, Leaf, TreeShape } from "../types.js";

/** Narrow the opaque @minister/identity `native` handle to a v4 Identity. The
 *  identity package documents `native` as a pure v4 Identity for this engine. */
function asV4Identity(native: unknown): Identity {
  // Structural check: a v4 Identity exposes a bigint `commitment` getter. We do
  // not deep-validate (the identity is the caller's own per-context identity from
  // @minister/identity); we only fail loudly if it is plainly not one.
  const maybe = native as { commitment?: unknown };
  if (maybe == null || typeof maybe !== "object" || typeof maybe.commitment === "undefined") {
    throw new Error("semaphoreEngine: identity.native is not a Semaphore v4 Identity.");
  }
  return native as Identity;
}

/**
 * Lazy-load the v4 group + proof prover. The proof package eagerly pulls
 * snarkjs; importing it at module scope crashes SSR bundling (verified). Memoized
 * after the first call so a session pays the import cost once.
 */
type GenerateProof = typeof import("@semaphore-protocol/proof").generateProof;
let proverLoad: Promise<{ generateProof: GenerateProof }> | null = null;
function loadProver() {
  proverLoad ??= (async () => {
    const { generateProof } = await import("@semaphore-protocol/proof");
    return { generateProof };
  })();
  return proverLoad;
}

type VerifyProof = typeof import("@semaphore-protocol/proof").verifyProof;
let verifierLoad: Promise<{ verifyProof: VerifyProof }> | null = null;
function loadVerifier() {
  verifierLoad ??= (async () => {
    const { verifyProof } = await import("@semaphore-protocol/proof");
    return { verifyProof };
  })();
  return verifierLoad;
}

function buildGroup(leaves: readonly Leaf[]): Group {
  const g = new Group();
  // IMPORTANT: do NOT re-sort. The provider returned the canonical order and the
  // package preserved it; re-sorting here would change the root (verified).
  for (const leaf of leaves) g.addMember(BigInt(leaf));
  return g;
}

export const semaphoreEngine: ProofEngine<SemaphoreProof> = {
  kind: "semaphore",

  toLeaf(commitment: IdentityCommitment, _params: EngineParams): Leaf {
    // Semaphore: the leaf IS the bare identity commitment. Branded so it cannot
    // be substituted for an RLN leaf (control 3: engine isolation).
    return asSemaphoreLeaf(commitment);
  },

  async computeRoot(leaves: readonly Leaf[], shape: TreeShape, _params: EngineParams) {
    if (shape.kind !== "dynamic") {
      throw new Error(
        `semaphoreEngine expects a dynamic tree shape; got ${shape.kind}. The fixed-depth ` +
          `discipline belongs to the RLN engine.`,
      );
    }
    if (leaves.length === 0) {
      // FreedInk represents the empty tree's root as '0' (verified
      // currentMembership: root = identities.length === 0 ? '0' : ...).
      return "0";
    }
    return buildGroup(leaves).root.toString();
  },

  async prove(ctx: ProveContext): Promise<SemaphoreProof> {
    const identity = asV4Identity(ctx.identity.native);
    const { generateProof } = await loadProver();

    // Rebuild the group from the snapshot's ordered leaves (NOT re-sorted) so the
    // Merkle root matches what the server stored.
    const group = new Group();
    for (const leaf of ctx.snapshot.leaves) group.addMember(BigInt(leaf));

    const scopeField = await hashToField(ctx.scope);
    const messageField = await hashToField(ctx.message);

    const leafIndex = group.indexOf(identity.commitment);
    if (leafIndex < 0) {
      throw new Error("semaphoreEngine.prove: identity is not a member of the snapshot.");
    }
    const merkleProof = group.generateMerkleProof(leafIndex);
    const depth = merkleProof.siblings.length || 1;
    const { wasm, zkey } = await ctx.artifacts.load(depth);

    const proof = await generateProof(
      identity,
      merkleProof,
      messageField,
      scopeField,
      depth,
      // @zk-kit/artifacts types SnarkArtifacts as { wasm: string; zkey: string }
      // (URLs), but the underlying snarkjs fastfile reader also accepts a
      // Uint8Array (an in-memory file). We pass integrity-verified bytes, so this
      // cast reflects the real runtime contract (verified: identical cast in
      // FreedInk buildProof).
      { wasm, zkey } as unknown as { wasm: string; zkey: string },
    );

    return {
      kind: "semaphore",
      merkleTreeDepth: Number(proof.merkleTreeDepth),
      merkleTreeRoot: proof.merkleTreeRoot.toString(),
      nullifier: proof.nullifier.toString(),
      message: proof.message.toString(),
      scope: proof.scope.toString(),
      points: proof.points.map((p) => p.toString()),
    };
  },

  async verify(ctx: VerifyContext): Promise<VerifyResult> {
    const proof = ctx.proof;
    if (proof.kind !== "semaphore") {
      return { ok: false, reason: "engine-mismatch" };
    }

    // R1 pin (control 1): resolve the proof's root to a snapshot PINNED to
    // (context, subTree). A proof bound to one tree's root cannot pass a
    // different tree/role check, because the store only returns a snapshot whose
    // ref matches AND whose root equals the proof root.
    // SAFE DEFAULT (fail-closed): requireCurrentRoot defaults to TRUE. A
    // persisted-store consumer who forgets the flag still rejects a just-banned
    // member's pre-ban snapshot. An explicit `false` is honored for the
    // deliberately-lenient historical-root mode (FreedInk comments tolerate stale
    // snapshots).
    const resolved = await ctx.store.getByRoot(ctx.ref, proof.merkleTreeRoot, {
      requireCurrentRoot: ctx.requireCurrentRoot ?? true,
    });
    if (!resolved.found) {
      // The store distinguishes "no such snapshot for this tree" from "known but
      // no longer the current root" so we return the right failure.
      return { ok: false, reason: resolved.stale ? "stale-root" : "unknown-snapshot" };
    }
    const snapshot = resolved.snapshot;
    if (snapshot.engine !== "semaphore") {
      return { ok: false, reason: "engine-mismatch" };
    }

    // FIX B (defense-in-depth): the store contract is that getByRoot returns a
    // snapshot whose root equals the requested root. Enforce it explicitly so a
    // future SnapshotStore that returns a wrong-root row cannot weaken the R1 pin.
    // (The RLN engine already forces snapshot.root as expectedRoot; this makes the
    // Semaphore engine equally strict.)
    if (snapshot.root !== proof.merkleTreeRoot) {
      return { ok: false, reason: "invalid-proof" };
    }

    const expectedScope = (await hashToField(ctx.expectedScope)).toString();
    const expectedMessage = (await hashToField(ctx.expectedMessage)).toString();
    if (proof.scope !== expectedScope) return { ok: false, reason: "scope-mismatch" };
    if (proof.message !== expectedMessage) return { ok: false, reason: "message-mismatch" };

    const { verifyProof } = await loadVerifier();
    const ok = await verifyProof(
      proof as unknown as Parameters<typeof verifyProof>[0],
    );
    if (!ok) return { ok: false, reason: "invalid-proof" };

    const nullifier: FieldString = proof.nullifier;
    return { ok: true, nullifier, snapshot };
  },
};
