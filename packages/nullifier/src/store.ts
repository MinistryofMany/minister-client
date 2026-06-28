/**
 * Type-level replay / uniqueness contract for nullifiers.
 *
 * The actual persistence stays APP-SIDE (each app owns its ORM, table, and
 * uniqueness index). This module defines only the shape that store must
 * implement, so the two existing replay models in the ecosystem are both
 * expressible behind one interface:
 *
 *  1. Insert-or-reject (FreedInk). A single UNIQUE index over
 *     (context, nullifier) makes a second use fail closed. See
 *     `post_reviews_version_nullifier_key` UNIQUE(post_version_id, nullifier)
 *     and `post_comments_version_nullifier_key` UNIQUE(post_version_id,
 *     nullifier) in FreedInk `src/lib/db/schema.ts`. This maps to
 *     `NullifierStore` below: `claim()` returns `{ status: "fresh" }` on the
 *     first use and `{ status: "replay" }` (no payload) on any reuse.
 *
 *  2. Slashable collision (Discreetly RLN). The same nullifier reused with a
 *     DIFFERENT signal is not a benign replay but a rate-limit breach that
 *     reveals a Shamir share. See `services/api/src/messaging/collision.ts`
 *     (`checkCollision` -> `new` | `duplicate` | `collision`, keyed on
 *     (roomId, epoch, nullifier) and comparing the stored share `x`). This maps
 *     to `SlashableNullifierStore` below, whose `claim()` distinguishes a true
 *     replay (same share point) from a slashable collision (different share
 *     point), returning the prior point so the caller can run Shamir recovery.
 *
 * Both are uniqueness checks over a (context, nullifier) pair; they differ only
 * in what a SECOND observation means and what it carries. App stores implement
 * whichever fits; the contract keeps the semantics explicit and fail-closed.
 */

/** A nullifier value plus the context it is scoped to. */
export interface NullifierKey {
  /**
   * The scope this nullifier is anchored to (e.g. a post-version id, room id,
   * or sub-forum id). Distinct contexts share no uniqueness namespace.
   */
  contextId: string;
  /** The derived nullifier, as a decimal string (a BN254 field element). */
  nullifier: string;
}

/** Result of a plain replay check: first use is fresh, any reuse is a replay. */
export type ClaimResult =
  | { status: "fresh" }
  | { status: "replay" };

/**
 * Insert-or-reject store (FreedInk shape). `claim` records the (context,
 * nullifier) pair iff it is unseen and reports whether it was fresh. It MUST be
 * atomic (e.g. an INSERT guarded by a UNIQUE index, catching the unique
 * violation as a replay) so concurrent claims of the same key cannot both win.
 */
export interface NullifierStore {
  claim(key: NullifierKey): Promise<ClaimResult>;
}

/** A Shamir share point recovered from a stored proof, used for slashing. */
export interface SharePoint {
  x: string;
  y: string;
}

/**
 * Result of a slashable claim (Discreetly RLN shape):
 * - `fresh`: first observation of this (context, nullifier) at this share point.
 * - `replay`: same nullifier AND same share point `x` -> a benign duplicate.
 * - `collision`: same nullifier, DIFFERENT share point -> a rate-limit breach;
 *   `prior` carries the previously stored point so the caller can run Shamir
 *   secret recovery and slash the offender.
 */
export type SlashableClaimResult =
  | { status: "fresh" }
  | { status: "replay" }
  | { status: "collision"; prior: SharePoint };

/**
 * Slashable store (Discreetly RLN shape). `claim` records the (context,
 * nullifier, share-point) and distinguishes a benign replay from a slashable
 * collision. Must be atomic for the same reasons as `NullifierStore`.
 */
export interface SlashableNullifierStore {
  claim(key: NullifierKey, point: SharePoint): Promise<SlashableClaimResult>;
}
