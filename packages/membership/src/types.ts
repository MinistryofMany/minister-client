// Core domain types for @minister/membership.
//
// These are the on-the-wire / in-DB shapes the three consumer apps (FreedInk,
// Discreetly, Deforum) already use, lifted to one vocabulary. Everything is a
// decimal string at this boundary: every donor app stores idc / root / nullifier
// as text (verified), never as a bigint.

/**
 * A field-element-bearing decimal string (a bigint serialized via `toString()`).
 * Never a bigint on the wire/DB.
 */
export type FieldString = string;

/**
 * A Semaphore identity commitment, decimal string. The bare public commitment
 * (poseidon hash of the identity's public key).
 */
export type IdentityCommitment = FieldString;

/**
 * Opaque, app-defined identifier of a membership context.
 *  - FreedInk: blogId.
 *  - Discreetly: roomId.
 *  - Deforum: subforumId.
 * Always a string PK.
 */
export type ContextId = string;

/**
 * Names the sub-tree WITHIN a context. The single highest-value authorization
 * input (design R1): a proof binds a root but NOT which tree it belongs to, so
 * the server pins the lookup to (context, subTree, root). Free-form string so a
 * new sub-tree never needs an enum migration.
 *  - FreedInk: 'author' | 'comment'
 *  - Discreetly: a single conventional value, e.g. 'room'
 *  - Deforum: a role slug, or 'anon:<action>' for per-anon-action trees.
 */
export type SubTree = string;

/** A context + sub-tree pair - the full coordinate of one Merkle group. */
export interface TreeRef {
  context: ContextId;
  subTree: SubTree;
}

/** The proof system a tree is built/verified under. */
export type EngineKind = "semaphore" | "rln";

/** Depth discipline for a tree. */
export type TreeShape =
  // FreedInk: depth = current siblings length (dynamic LeanIMT, no fixed depth).
  | { kind: "dynamic" }
  // Discreetly RLN: depth 20 (verified MERKLE_TREE_DEPTH on the compiled circuit).
  | { kind: "fixed"; depth: number };

// ---------------------------------------------------------------------------
// Engine isolation: brand the two engines' leaf values so they are NOMINALLY
// distinct (control 3). A bare identity commitment (the Semaphore v4 leaf) and a
// rate commitment (the RLN v3 leaf) are BOTH decimal strings, so without a brand
// the compiler would let a v4 leaf flow into the depth-20 RLN tree and silently
// produce a wrong-but-valid root. The brand makes that a type error.
//
// The brand is a phantom property: it exists only in the type system and is never
// present at runtime, so a `SemaphoreLeaf` is still just a string on the wire.
// ---------------------------------------------------------------------------

declare const SEMAPHORE_LEAF_BRAND: unique symbol;
declare const RLN_LEAF_BRAND: unique symbol;

/** A Semaphore v4 tree leaf: the bare identity commitment. Branded so it cannot
 *  be substituted for an RLN leaf. */
export type SemaphoreLeaf = FieldString & { readonly [SEMAPHORE_LEAF_BRAND]: true };

/** An RLN v3 tree leaf: the rate commitment poseidon2(ic, userMessageLimit).
 *  Branded so it cannot be substituted for a Semaphore leaf. */
export type RlnLeaf = FieldString & { readonly [RLN_LEAF_BRAND]: true };

/**
 * A tree leaf value AS STORED in the group, for either engine. The branded
 * sub-types (`SemaphoreLeaf`, `RlnLeaf`) are what each engine produces and
 * consumes; `Leaf` is the un-narrowed union used where the engine is not yet
 * known (e.g. a snapshot's stored leaf list). The brands are checked statically;
 * `asSemaphoreLeaf` / `asRlnLeaf` are the only sanctioned ways to mint a branded
 * leaf from a raw string.
 */
export type Leaf = SemaphoreLeaf | RlnLeaf;

/** Mint a branded Semaphore leaf from a raw decimal string. The single audited
 *  entry point that crosses the brand boundary for the v4 engine. */
export function asSemaphoreLeaf(value: FieldString): SemaphoreLeaf {
  return value as SemaphoreLeaf;
}

/** Mint a branded RLN leaf from a raw decimal string. The single audited entry
 *  point that crosses the brand boundary for the RLN engine. */
export function asRlnLeaf(value: FieldString): RlnLeaf {
  return value as RlnLeaf;
}

/**
 * A frozen membership snapshot: a root plus the EXACT ordered leaf set that
 * produced it, with excluded (banned/revoked) commitments already removed.
 * Mirrors FreedInk's blog_member_snapshots row (root + identities[] +
 * eligibleCount, verified).
 */
export interface MembershipSnapshot {
  ref: TreeRef;
  root: FieldString;
  /**
   * Ordered leaves (engine-mapped). Order is load-bearing: the client MUST NOT
   * re-sort (FreedInk buildProof "do NOT re-sort"). The provider owns the order
   * via `orderKeys`; the package preserves it.
   */
  leaves: FieldString[];
  eligibleCount: number;
  /** Identifier of the snapshot row when persisted (FreedInk/Deforum); undefined
   *  for the live store (Discreetly). */
  snapshotId?: string;
  /** Engine + shape this snapshot was built under, so a verifier can reject a
   *  proof generated against the wrong proof system / depth. */
  shape: TreeShape;
  engine: EngineKind;
}
