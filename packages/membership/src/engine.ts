// The proof-engine seam.
//
// Each engine fixes the proof payload type, the identity-commitment -> leaf
// mapping, the depth discipline, and prove/verify. Both engines ship in the
// package; an app picks one via its provider's `engine`. The engine isolates the
// proof system so FreedInk's call sites only ever see SemaphoreProof and
// Discreetly's only ever see RlnProof - the RLN epoch/x/y and the Semaphore
// points never leak into the other consumer.

import type { ArtifactSource } from "./artifacts.js";
import type { EngineParams } from "./provider.js";
import type { SnapshotStore } from "./store.js";
import type {
  EngineKind,
  FieldString,
  IdentityCommitment,
  Leaf,
  MembershipSnapshot,
  TreeRef,
  TreeShape,
} from "./types.js";
import type { SemaphoreIdentityLike } from "@minister/identity";

/**
 * Vanilla Semaphore proof payload - EXACTLY FreedInk's ProofPayload (verified
 * client/semaphore.ts + server/semaphore.ts IncomingProof).
 */
export interface SemaphoreProof {
  kind: "semaphore";
  merkleTreeDepth: number;
  merkleTreeRoot: FieldString;
  nullifier: FieldString;
  /** hashToField(message). */
  message: FieldString;
  /** hashToField(scope). */
  scope: FieldString;
  points: FieldString[];
}

/**
 * RLN proof payload - wraps the @minister/rln plain proof struct. The package
 * does not re-type rlnjs internals; the RlnEngine guards `full` before trusting
 * any field. `full` is the bigint/string-only `RlnProof` the island emits.
 */
export interface RlnProof {
  kind: "rln";
  /** The @minister/rln RlnProof, structurally. Typed as unknown at the boundary;
   *  the RlnEngine narrows + guards it. */
  full: unknown;
}

export type MembershipProof = SemaphoreProof | RlnProof;

/** What the client must hold to generate a proof. */
export interface ProveContext {
  /** The member's per-context Semaphore identity (from @minister/identity).
   *  Opaque here; the engine narrows it to the proof system's identity type. */
  identity: SemaphoreIdentityLike;
  /** The snapshot the proof binds to (leaves + root + shape). */
  snapshot: MembershipSnapshot;
  /** Pre-hash scope; the engine applies hashToField (verified). */
  scope: string;
  /** Pre-hash message; the engine applies hashToField (verified). */
  message: string;
  /** Injectable WASM/zkey. */
  artifacts: ArtifactSource;
  /** RLN-only extras; ignored by the Semaphore engine. */
  rln?: {
    rlnIdentifier: FieldString;
    userMessageLimit: number;
    /** RLN identity secret (poseidon2([nullifier, trapdoor])); the v4 identity
     *  has no RLN secret, so an RLN prover supplies it explicitly. */
    identitySecret: FieldString;
    epoch: bigint;
    messageId?: bigint;
  };
}

/** What the server passes to verify, BEFORE the package injects the store. */
export interface VerifyContext {
  ref: TreeRef;
  proof: MembershipProof;
  /** Pre-hash scope; the engine re-derives + compares (verified). */
  expectedScope: string;
  /** Pre-hash message. */
  expectedMessage: string;
  /** Resolves proof.root -> snapshot (stored or live). */
  store: SnapshotStore;
  /**
   * When true, require the proof root to equal the CURRENT live root, not just
   * any known snapshot of this tree (verified: FreedInk requireCurrentRoot kills
   * the stale-root-after-revoke vector). Always effectively true for the live
   * store. This is the banned-exclusion enforcement at verify time (control 2).
   */
  requireCurrentRoot?: boolean;
  /**
   * RLN-only: epoch window + identifier + the Groth16 verification key. Ignored
   * by the Semaphore engine. The `expectedRoot` is NOT a caller input: the
   * package supplies it from the RESOLVED SNAPSHOT (the authoritative root), so
   * the RLN verifier always pins the snapshot root even though RLN also binds the
   * root in publicSignals. This is the R1 pin holding for the RLN engine (control
   * 1): a Deforum role-A proof cannot pass a role-B check, because the snapshot is
   * resolved by (context, subTree) and its root is forced as expectedRoot.
   */
  rln?: {
    currentEpoch: bigint;
    epochErrorRange?: bigint;
    rlnIdentifier: FieldString;
    /** The parsed RLN Groth16 verification key (the @minister/rln
     *  RlnVerificationKey JSON). Required to run the SNARK verification. */
    verificationKey: Record<string, unknown>;
  };
}

export type VerifyFailure =
  // root not found for (context, subTree) - the R1 pin (verified FreedInk 400).
  | "unknown-snapshot"
  // requireCurrentRoot and root != live root (verified).
  | "stale-root"
  | "scope-mismatch"
  | "message-mismatch"
  // RLN window (verified).
  | "bad-epoch"
  // RLN signal hash != x (verified).
  | "bad-signal"
  // SNARK verify failed / malformed envelope (verified).
  | "invalid-proof"
  // proof.kind != snapshot.engine, or wrong engine for the tree.
  | "engine-mismatch"
  // RLN params (rlnIdentifier / epoch) were not supplied to verify.
  | "missing-rln-params";

export type VerifyResult =
  | {
      ok: true;
      nullifier: FieldString;
      snapshot: MembershipSnapshot;
      /** RLN exposes epoch + x,y for Shamir collision detection (verified).
       *  Undefined for Semaphore. */
      rln?: { epoch: bigint; x: FieldString; y: FieldString };
    }
  | { ok: false; reason: VerifyFailure };

/**
 * The proof-engine contract. `P` narrows the proof payload to the engine's own
 * type so a consumer that wants RLN gets RLN's full contract (epoch window,
 * expectedRoot, Shamir x/y) without Semaphore consumers paying for it.
 */
export interface ProofEngine<P extends MembershipProof = MembershipProof> {
  readonly kind: EngineKind;

  /**
   * Map an identity commitment to the leaf value stored in the tree.
   *  - semaphore: ic => ic (returns a branded SemaphoreLeaf).
   *  - rln:       ic => poseidon2(ic, userMessageLimit) (returns a branded
   *    RlnLeaf), so a v4 leaf can never flow into the depth-20 RLN tree.
   */
  toLeaf(commitment: IdentityCommitment, params: EngineParams): Leaf;

  /**
   * Build the in-memory group + root from an ordered leaf set, honoring the
   * TreeShape.
   *  - semaphore: new Group() (dynamic LeanIMT).
   *  - rln:       depth-20 group via @minister/rln computeRoot.
   */
  computeRoot(leaves: readonly Leaf[], shape: TreeShape, params: EngineParams): Promise<FieldString>;

  /** Client: generate the proof. */
  prove(ctx: ProveContext): Promise<P>;

  /**
   * Server: verify. Resolves the snapshot via ctx.store, runs the engine's
   * checks, returns the nullifier. Throws nothing for EXPECTED failures - returns
   * { ok: false, reason }. Throws only on truly unexpected conditions (e.g. a
   * missing artifact verification key).
   */
  verify(ctx: VerifyContext): Promise<VerifyResult>;
}
