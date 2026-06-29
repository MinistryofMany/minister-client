// rlnEngine - RLN (rate-limiting nullifier) over @ministryofmany/rln.
//
// toLeaf is the rate commitment poseidon2(ic, userMessageLimit) (NOT the bare
// commitment); the tree is the fixed depth-20 v3 Group. This is Discreetly's
// machinery, lifted: generateRlnProof (client) + verifyRlnProof (server),
// byte-for-byte, with @ministryofmany/rln as the v3 + rlnjs quarantine island so no v3
// type leaks into this package's public surface.
//
// CRITICAL (control 1, R1 for RLN): rlnEngine.verify passes the SNAPSHOT ROOT as
// @ministryofmany/rln verifyRlnProof's `expectedRoot` (a required arg after the harden
// phase). Even though the Groth16 proof binds the root in publicSignals, the
// package still pins it to the snapshot resolved by (context, subTree), so a
// proof bound to one tree cannot pass a different tree/role check.

import {
  computeRoot as rlnComputeRoot,
  getRateCommitmentHash,
  calculateSignalHash,
  generateRlnProof,
  verifyRlnProof,
  staticArtifactSource,
} from "@ministryofmany/rln";
import type { RlnProof as IslandRlnProof } from "@ministryofmany/rln";
import type {
  ProofEngine,
  ProveContext,
  RlnProof,
  VerifyContext,
  VerifyResult,
} from "../engine.js";
import type { EngineParams } from "../provider.js";
import { asRlnLeaf } from "../types.js";
import type { FieldString, IdentityCommitment, Leaf, TreeShape } from "../types.js";

/** Narrow EngineParams to the RLN branch or throw - the RLN engine cannot run
 *  without rlnIdentifier + userMessageLimit (which the discriminated provider
 *  type already forces an RLN provider to supply). */
function rlnParams(params: EngineParams): { rlnIdentifier: FieldString; userMessageLimit: number } {
  if (params.engine !== "rln") {
    throw new Error(`rlnEngine requires rln EngineParams; got engine=${params.engine}.`);
  }
  return { rlnIdentifier: params.rlnIdentifier, userMessageLimit: params.userMessageLimit };
}

/**
 * Structural guard for the @ministryofmany/rln plain proof struct. The proof crosses
 * the boundary as `unknown`; we verify it has the publicSignals fields the
 * verifier reads BEFORE trusting any of them (the design's "guard before trusting
 * any field"). Returns the typed island proof or null if malformed.
 */
function asIslandProof(full: unknown): IslandRlnProof | null {
  if (full == null || typeof full !== "object") return null;
  const p = full as Partial<IslandRlnProof>;
  const sp = p.snarkProof;
  if (sp == null || typeof sp !== "object") return null;
  const ps = sp.publicSignals;
  if (ps == null || typeof ps !== "object") return null;
  if (
    typeof ps.x !== "string" ||
    typeof ps.y !== "string" ||
    typeof ps.root !== "string" ||
    typeof ps.nullifier !== "string" ||
    typeof ps.externalNullifier !== "string"
  ) {
    return null;
  }
  if (typeof p.epoch === "undefined" || typeof p.rlnIdentifier === "undefined") return null;
  return full as IslandRlnProof;
}

export const rlnEngine: ProofEngine<RlnProof> = {
  kind: "rln",

  toLeaf(commitment: IdentityCommitment, params: EngineParams): Leaf {
    const { userMessageLimit } = rlnParams(params);
    // RLN leaf = rate commitment poseidon2(ic, userMessageLimit). Branded as an
    // RlnLeaf so a bare v4 commitment can never flow into the depth-20 tree
    // (control 3: engine isolation). This is byte-for-byte
    // @ministryofmany/rln getRateCommitmentHash.
    const rate = getRateCommitmentHash(BigInt(commitment), userMessageLimit);
    return asRlnLeaf(rate.toString());
  },

  async computeRoot(leaves: readonly Leaf[], shape: TreeShape, params: EngineParams) {
    if (shape.kind !== "fixed") {
      throw new Error(
        `rlnEngine expects a fixed tree shape (depth 20); got ${shape.kind}. The dynamic ` +
          `discipline belongs to the Semaphore engine.`,
      );
    }
    const { rlnIdentifier } = rlnParams(params);
    // @ministryofmany/rln computeRoot builds the fixed depth-20 v3 Group internally and
    // returns a bigint root; never exposes the Group object.
    const root = rlnComputeRoot(BigInt(rlnIdentifier), leaves as unknown as string[]);
    return root.toString();
  },

  async prove(ctx: ProveContext): Promise<RlnProof> {
    if (!ctx.rln) {
      throw new Error("rlnEngine.prove requires ctx.rln (rlnIdentifier, userMessageLimit, ...).");
    }
    const { rlnIdentifier, userMessageLimit, identitySecret, epoch } = ctx.rln;
    const messageId = ctx.rln.messageId ?? 0n;

    // This member's rate-commitment leaf, recomputed from the v4 commitment.
    const leaf = getRateCommitmentHash(BigInt(ctx.identity.commitment), userMessageLimit);
    const x = calculateSignalHash(ctx.message);

    // The depth-20 circuit is fixed, so depth is conventionally 20 for the
    // artifact source. @ministryofmany/rln owns the Merkle proof construction.
    const { wasm, zkey } = await ctx.artifacts.load(20);
    const islandArtifacts = staticArtifactSource({ prover: { wasm, zkey } });

    const proof = await generateRlnProof(
      {
        rlnIdentifier: BigInt(rlnIdentifier),
        identitySecret: BigInt(identitySecret),
        userMessageLimit: BigInt(userMessageLimit),
        messageId,
        leaves: ctx.snapshot.leaves,
        leaf,
        x,
        epoch,
      },
      islandArtifacts,
    );

    return { kind: "rln", full: proof };
  },

  async verify(ctx: VerifyContext): Promise<VerifyResult> {
    const proof = ctx.proof;
    if (proof.kind !== "rln") {
      return { ok: false, reason: "engine-mismatch" };
    }
    if (!ctx.rln) {
      return { ok: false, reason: "missing-rln-params" };
    }
    const island = asIslandProof(proof.full);
    if (!island) {
      return { ok: false, reason: "invalid-proof" };
    }

    // R1 pin (control 1): resolve the proof's root to a snapshot PINNED to
    // (context, subTree). The resolved snapshot's root becomes the expectedRoot
    // forced into verifyRlnProof below.
    // SAFE DEFAULT (fail-closed): requireCurrentRoot defaults to TRUE so a
    // persisted-store consumer who forgets the flag still rejects a just-banned
    // member's pre-ban snapshot. An explicit `false` is honored for the
    // deliberately-lenient historical-root mode.
    const resolved = await ctx.store.getByRoot(ctx.ref, island.snarkProof.publicSignals.root, {
      requireCurrentRoot: ctx.requireCurrentRoot ?? true,
    });
    if (!resolved.found) {
      return { ok: false, reason: resolved.stale ? "stale-root" : "unknown-snapshot" };
    }
    const snapshot = resolved.snapshot;
    if (snapshot.engine !== "rln") {
      return { ok: false, reason: "engine-mismatch" };
    }

    // RLN re-derives the signal hash (x) from the expected message and matches it
    // against the proof's x (verified: signalHash !== x -> reject).
    const expectedX = calculateSignalHash(ctx.expectedMessage);

    const islandVerifyArtifacts = staticArtifactSource({
      verificationKey: ctx.rln.verificationKey,
    });

    let ok = false;
    try {
      ok = await verifyRlnProof(
        {
          rlnIdentifier: BigInt(ctx.rln.rlnIdentifier),
          proof: island,
          signalHash: expectedX,
          epoch: island.epoch,
          currentEpoch: ctx.rln.currentEpoch,
          epochErrorRange: ctx.rln.epochErrorRange ?? 1n,
          // The authoritative root is the SNAPSHOT's root, not a caller input.
          expectedRoot: BigInt(snapshot.root),
        },
        islandVerifyArtifacts,
      );
    } catch {
      // A thrown error here means a malformed envelope / missing key; treat as an
      // invalid proof rather than crashing the request path.
      return { ok: false, reason: "invalid-proof" };
    }

    if (!ok) {
      // verifyRlnProof folds four checks (epoch window, signal-hash match,
      // root match, SNARK) into one boolean. Disambiguate the two cheap,
      // caller-actionable ones so the consumer can log/alert precisely; the rest
      // collapse to invalid-proof.
      const ps = island.snarkProof.publicSignals;
      const epochErrorRange = ctx.rln.epochErrorRange ?? 1n;
      if (
        island.epoch < ctx.rln.currentEpoch - epochErrorRange ||
        island.epoch > ctx.rln.currentEpoch + epochErrorRange
      ) {
        return { ok: false, reason: "bad-epoch" };
      }
      if (expectedX !== BigInt(ps.x)) {
        return { ok: false, reason: "bad-signal" };
      }
      return { ok: false, reason: "invalid-proof" };
    }

    const ps = island.snarkProof.publicSignals;
    const nullifier: FieldString = ps.nullifier;
    return {
      ok: true,
      nullifier,
      snapshot,
      rln: { epoch: island.epoch, x: ps.x, y: ps.y },
    };
  },
};
