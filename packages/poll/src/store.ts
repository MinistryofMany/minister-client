// Injectable persistence seams. No ORM lives in this package: the consumer owns
// its database, tables, and indexes. The package defines only the shapes those
// stores must satisfy, and the security-critical one - the one-vote guard - is
// expressed as an insert-or-reject contract the store MUST implement atomically.

import type { FieldString } from "@minister/membership";
import type { Poll, StoredVote } from "./types.js";

/**
 * Poll record persistence. CRUD over the Poll aggregate, plus a lifecycle
 * update. `Config` is the question type's config shape; a heterogeneous store
 * may use `Poll<unknown>`.
 */
export interface PollStore<Config = unknown> {
  get(pollId: string): Promise<Poll<Config> | null>;
  create(poll: Poll<Config>): Promise<void>;
  /** Persist a new lifecycle stage for an existing poll. */
  setLifecycle(pollId: string, lifecycle: Poll<Config>["lifecycle"]): Promise<void>;
}

/**
 * Result of an attempted vote insert. `fresh` means this (pollId, nullifier) was
 * unseen and is now recorded; `replay` means the member already cast in this poll
 * (the one-vote guard fired) and NOTHING was written.
 */
export type CastOutcome = { status: "fresh" } | { status: "replay" };

/**
 * Vote persistence AND the unstuffability guard. The security property lives
 * here: `castOnce` MUST be atomic and enforce UNIQUE(pollId, nullifier) so that
 *
 *   1. a second cast from the same member (same per-poll nullifier) is rejected
 *      ("replay"), and
 *   2. a nullifier minted for poll A cannot be inserted under poll B - because
 *      the per-poll nullifier is derived from (handle, pollId), poll B simply
 *      never sees poll A's value, and even an attacker who lifts the raw string
 *      is scoped by the pollId column of the UNIQUE index.
 *
 * Implement it as an INSERT guarded by a UNIQUE(pollId, nullifier) index,
 * catching the unique violation and reporting "replay" - exactly the FreedInk
 * insert-or-reject model and the @minister/nullifier NullifierStore contract.
 * A non-atomic check-then-insert is a stuffing vulnerability (two concurrent
 * casts could both pass the check); the contract REQUIRES atomicity.
 */
export interface VoteStore<T = unknown> {
  /**
   * Atomically record a vote iff its (pollId, nullifier) is unseen.
   * On "fresh" the vote is persisted; on "replay" nothing is written.
   */
  castOnce(pollId: string, vote: StoredVote<T>): Promise<CastOutcome>;

  /** All recorded votes for a poll, for tally / resolve. */
  list(pollId: string): Promise<StoredVote<T>[]>;

  /**
   * Count of DISTINCT recorded nullifiers for a poll. Since each nullifier is a
   * distinct verified voter and the store is UNIQUE on it, this is the
   * distinct-verified-voter count surfaced in every result view (polling.md
   * credibility surface). Equivalent to `list(pollId).length`; provided
   * separately so a store can answer it with a cheap COUNT.
   */
  count(pollId: string): Promise<number>;

  /**
   * Replace the stored payload for an existing (pollId, nullifier). Used ONLY by
   * the commit-reveal type to attach a reveal to a member's existing committed
   * row; it MUST NOT create a new row (the member already consumed their one
   * vote at commit time). Returns false if no such row exists.
   */
  update(pollId: string, nullifier: FieldString, vote: T): Promise<boolean>;
}
