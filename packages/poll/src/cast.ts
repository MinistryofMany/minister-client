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

import {
  deriveContextNullifier,
  deriveContextNullifierFromField,
  toField,
  FIELD,
} from "@ministryofmany/nullifier";
import type { FieldString } from "@ministryofmany/membership";
import type { VoterHandle } from "./types.js";

/**
 * Per-kind domain-separation tags. The two VoterHandle kinds (a membership-proof
 * nullifier vs an authenticated subject) live in DISJOINT namespaces, so a
 * subject "1" and a membership nullifier "1" derive different per-poll values.
 * The subject tag is prepended to the subject string before it is reduced; the
 * membership path mixes its tag into the context (its secret is a field VALUE,
 * not a string, so it cannot be string-prefixed - see deriveVoteNullifier).
 */
const SUBJECT_TAG = "sub:";
const MEMBERSHIP_TAG = "mem:";

/**
 * Reduce a poll id to a BN254 field element the same way @ministryofmany/nullifier
 * reduces an arbitrary subject string: accumulate UTF-8 bytes big-endian mod
 * FIELD. Reusing `toField` keeps the reduction byte-for-byte identical to the
 * rest of the ecosystem rather than inventing a second one.
 */
export function pollContextId(pollId: string): bigint {
  return toField(pollId);
}

/**
 * Derive the per-(poll, member) nullifier from a verified voter handle. The two
 * handle kinds are DOMAIN-SEPARATED into disjoint namespaces, so a subject "1"
 * and a membership nullifier "1" derive DIFFERENT per-poll nullifiers (the map is
 * not collapsed across kinds):
 *
 *  - subject handle:    deriveContextNullifier(SUBJECT_TAG + subject, pollContext)
 *                       = poseidon2(toField("sub:" + subject), pollContext). The
 *                       subject is an arbitrary string, correctly byte-reduced by
 *                       toField; the "sub:" tag puts it in the subject namespace.
 *
 *  - membership handle: deriveContextNullifierFromField(BigInt(n) % FIELD,
 *                       membershipContext). The membership nullifier is ALREADY a
 *                       field element, so it is mixed in as a field VALUE
 *                       (BigInt(n) % FIELD), NOT re-byte-reduced through toField on
 *                       its decimal string (which would re-hash its digits and is
 *                       not the identity on field elements). The membership
 *                       context folds the "mem:" tag into the pollId so this path
 *                       lands in a disjoint namespace from the subject path while
 *                       still being per-poll (cross-poll replay prevention).
 *
 * Both paths bind the pollId, so the same member's value differs per poll. The
 * per-(poll, member) nullifier is collision-resistant by the field size (~2^254),
 * not injective: two field elements colliding under poseidon2 is cryptographically
 * negligible.
 *
 * The result is returned as a decimal FieldString - the form the VoteStore's
 * UNIQUE index and every donor app store keeps nullifiers in.
 */
export function deriveVoteNullifier(handle: VoterHandle, pollId: string): FieldString {
  if (handle.kind === "subject") {
    const ctx = pollContextId(pollId);
    return deriveContextNullifier(SUBJECT_TAG + handle.subject, ctx).toString();
  }
  // Membership: tag the context so this kind is namespace-disjoint from subject,
  // and treat the already-field-element nullifier as a VALUE, not a byte string.
  const ctx = toField(MEMBERSHIP_TAG + pollId);
  const value = BigInt(handle.membershipNullifier) % FIELD;
  return deriveContextNullifierFromField(value, ctx).toString();
}

// Re-export FIELD so consumers / tests can reason about the field bound without a
// second dependency edge.
export { FIELD };
