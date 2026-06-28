// The mandatory per-app seam: MerkleGroupProvider.
//
// This is the storage-agnostic source of truth for "the current eligible,
// exclusion-filtered leaf set of this tree." It is FreedInk's
// currentEligibleIdentities and Discreetly's
// membershipLeaf.findMany({ revokedAt: null }) generalized. Each app implements
// it once over its own ORM; everything else in the package is logic over its
// output.

import type {
  ContextId,
  EngineKind,
  FieldString,
  IdentityCommitment,
  TreeRef,
  TreeShape,
} from "./types.js";

/**
 * One eligible member's leaf, as the provider returns it.
 *
 * `leaf` is the value stored in the tree (engine-mapped: the bare identity
 * commitment for Semaphore, the rate commitment for RLN). `commitment` is the
 * underlying identity commitment, kept for callers that need the ic itself
 * (revocation, indexOf). They are EQUAL for Semaphore and DIFFER for RLN.
 */
export interface EligibleLeaf {
  /** The value stored in the tree (engine-mapped). Raw decimal string here; the
   *  engine brands it (`asSemaphoreLeaf` / `asRlnLeaf`) when it builds the root. */
  leaf: FieldString;
  /** The underlying identity commitment. */
  commitment: IdentityCommitment;
  /**
   * Optional provider-supplied sort keys. The package sorts by these in order
   * when present, giving a deterministic, replica-independent root WITHOUT the
   * package knowing the app's schema. FreedInk supplies
   * [userCreatedAtMs, userId, deviceCreatedAtMs, idc] (verified). Discreetly may
   * omit (it relies on the provider's own return order). The comparator is
   * byte-specified in order.ts.
   */
  orderKeys?: ReadonlyArray<string | number>;
}

/** Discriminated engine parameters supplied by the provider. */
export type EngineParams =
  | { engine: "semaphore" }
  | {
      engine: "rln";
      /** The room/group RLN identifier (verified Room.rlnIdentifier). */
      rlnIdentifier: FieldString;
      /** Per-member message limit; the second poseidon2 input of the rate
       *  commitment leaf (verified getRateCommitmentHash). */
      userMessageLimit: number;
    };

/**
 * The fields every provider shares, regardless of engine. `engineParams` is
 * declared here as OPTIONAL so the Semaphore branch can omit it; the RLN branch
 * below overrides it to REQUIRED. The discriminated `MerkleGroupProvider` union
 * is what callers see, so a Semaphore provider may skip `engineParams` while an
 * RLN provider cannot typecheck without it.
 */
interface MerkleGroupProviderBase {
  /** The depth discipline for trees this provider serves. Constant per provider:
   *  FreedInk -> {kind:'dynamic'}; Discreetly -> {kind:'fixed', depth:20}. */
  readonly shape: TreeShape;

  /** The proof engine these trees use. */
  readonly engine: EngineKind;

  /**
   * Return the CURRENT eligible leaf set for a tree, with bans/revocations
   * already excluded. The one method that encodes each app's divergent exclusion
   * + ordering logic.
   *  - FreedInk: active blog_members holding the capability x active
   *    user_identities, sorted by (userCreatedAt,userId,deviceCreatedAt,idc).
   *  - Discreetly: membershipLeaf where revokedAt IS NULL (banned memberships
   *    have all leaves pruned), mapped to rateCommitment.
   *  - Deforum: members whose user-sub-forum nullifier is not banned and whose
   *    device leaf is not revoked.
   */
  listEligible(ref: TreeRef): Promise<EligibleLeaf[]>;
}

/** A Semaphore-backed provider. `engineParams` is optional: Semaphore needs no
 *  per-context parameters (toLeaf is the identity). */
export interface SemaphoreGroupProvider extends MerkleGroupProviderBase {
  readonly engine: "semaphore";
  /** Optional; if present it must report `{ engine: 'semaphore' }`. */
  engineParams?(context: ContextId): Promise<{ engine: "semaphore" }>;
}

/**
 * An RLN-backed provider. `engineParams` is STRUCTURALLY REQUIRED (control:
 * "engineParams REQUIRED when engine===rln via a discriminated provider type so
 * an RLN provider cannot typecheck without it"). RLN needs the rlnIdentifier +
 * userMessageLimit to map an identity commitment to its rate-commitment leaf and
 * to build the depth-20 group; without them the engine cannot run, so the type
 * makes their absence a compile error rather than a runtime surprise.
 */
export interface RlnGroupProvider extends MerkleGroupProviderBase {
  readonly engine: "rln";
  engineParams(context: ContextId): Promise<{
    engine: "rln";
    rlnIdentifier: FieldString;
    userMessageLimit: number;
  }>;
}

/**
 * The mandatory per-app seam. A discriminated union on `engine`: a `semaphore`
 * provider may omit `engineParams`; an `rln` provider must supply it. The apps
 * keep their existing exclusion semantics entirely inside `listEligible` - this
 * is where the apps cannot share code and must each ship a provider.
 */
export type MerkleGroupProvider = SemaphoreGroupProvider | RlnGroupProvider;

/**
 * Resolve the engine parameters for a provider + context, defaulting a Semaphore
 * provider that omits `engineParams` to `{ engine: 'semaphore' }`. Centralizes
 * the "Semaphore params are trivial" default so each engine does not re-derive
 * it.
 */
export async function resolveEngineParams(
  provider: MerkleGroupProvider,
  context: ContextId,
): Promise<EngineParams> {
  if (provider.engine === "rln") {
    return provider.engineParams(context);
  }
  if (provider.engineParams) {
    return provider.engineParams(context);
  }
  return { engine: "semaphore" };
}
