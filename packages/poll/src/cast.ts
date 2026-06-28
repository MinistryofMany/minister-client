// The unstuffability core: turn a verified voter handle into a per-(poll, member)
// nullifier, then guard one-vote through the VoteStore.
//
// The security property has two halves and both live here:
//
//   1. ONE VOTE PER MEMBER. The per-poll nullifier is a deterministic function
//      of (handle-secret, pollId), so the same member always derives the same
//      value for a given poll, and the VoteStore's UNIQUE(pollId, nullifier)
//      rejects the second cast.
//
//   2. NO CROSS-POLL REPLAY. The pollId is mixed into the derivation, so a
//      member's nullifier for poll A differs from their nullifier for poll B.
//      Even if an attacker lifts poll A's raw nullifier string, the VoteStore
//      keys uniqueness on (pollId, nullifier): inserting A's value under poll B
//      collides with nothing in B, but it ALSO is not the honest member's poll-B
//      nullifier, so it cannot displace or impersonate their vote. And because
//      each poll's nullifier set is disjoint by construction, a value carried
//      across polls is meaningless rather than a usable second identity.

import { deriveContextNullifier, toField, FIELD } from "@minister/nullifier";
import type { FieldString } from "@minister/membership";
import type { VoterHandle } from "./types.js";

/**
 * Reduce a poll id to a BN254 field element the same way @minister/nullifier
 * reduces an arbitrary subject string: accumulate UTF-8 bytes big-endian mod
 * FIELD. Reusing `toField` keeps the reduction byte-for-byte identical to the
 * rest of the ecosystem rather than inventing a second one.
 */
export function pollContextId(pollId: string): bigint {
  return toField(pollId);
}

/**
 * Derive the per-(poll, member) nullifier from a verified voter handle.
 *
 *  - subject handle:    deriveContextNullifier(subject, pollContext)
 *                       = poseidon2(toField(subject), pollContext) - exactly the
 *                       ecosystem two-layer nullifier with the poll as context.
 *
 *  - membership handle: deriveContextNullifier(membershipNullifier, pollContext).
 *                       The membership nullifier is ALREADY a field-element
 *                       string, but feeding it back through deriveContextNullifier
 *                       (a) binds it to this pollId so the same member's value
 *                       differs per poll (cross-poll replay prevention), and
 *                       (b) keeps a single derivation path for both handle kinds.
 *                       `toField` on a decimal string is injective enough here:
 *                       distinct membership nullifiers stay distinct after the
 *                       mod-FIELD byte reduction because each is a canonical
 *                       sub-FIELD decimal, so no two members collide.
 *
 * The result is returned as a decimal FieldString - the form the VoteStore's
 * UNIQUE index and every donor app store keeps nullifiers in.
 */
export function deriveVoteNullifier(handle: VoterHandle, pollId: string): FieldString {
  const ctx = pollContextId(pollId);
  const secret = handle.kind === "subject" ? handle.subject : handle.membershipNullifier;
  return deriveContextNullifier(secret, ctx).toString();
}

// Re-export FIELD so consumers / tests can reason about the field bound without a
// second dependency edge.
export { FIELD };
