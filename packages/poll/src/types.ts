// Core domain types for @ministryofmany/poll.
//
// A Poll is { id, questionType, audienceGate, config, lifecycle }. Each question
// type fixes its own `config`, `vote`, `tally`, and `resultView` shapes via the
// QuestionType abstraction (see ./engine.ts and ./question-types/*). This file
// holds only the cross-cutting domain vocabulary: lifecycle, the audience gate,
// the voter handle, and the cast envelope - the pieces the engine and every
// question type share.

import type { PolicyNode } from "@ministryofmany/policy";
import type { FieldString } from "@ministryofmany/membership";

/**
 * A poll's lifecycle stage. The engine enforces the legal transitions:
 *
 *   draft --open--> open --close--> closed --resolve--> resolved
 *
 * - draft:    being configured; no votes accepted.
 * - open:     accepting casts (commit phase for commit-reveal).
 * - closed:   no longer accepting NEW casts; reveals (commit-reveal) still
 *             accepted in this stage so a voter can open their sealed commit.
 * - resolved: terminal; the outcome is frozen. Tally is read-only.
 *
 * A question type with no reveal phase resolves directly from `closed`. The
 * commit-reveal type uses `closed` as its reveal window before `resolved`.
 */
export type PollLifecycle = "draft" | "open" | "closed" | "resolved";

/**
 * The audience gate: WHO may vote, expressed as a @ministryofmany/policy badge
 * requirement AST (a boolean allOf/anyOf/atLeast/badge-leaf tree). The poll
 * engine does NOT evaluate badges itself - the caller verifies disclosed badge
 * VCs and evaluates this gate with @ministryofmany/policy `evaluate(...)` BEFORE
 * minting a verified voter handle. The gate is carried on the poll so a result
 * view can surface the pool definition (the credibility surface, polling.md).
 *
 * `open: true` means a public poll with no badge requirement; the pool is then
 * defined entirely by the membership / identity layer that still mints the voter
 * handle (so the poll is still unstuffable - one handle, one vote).
 */
export type AudienceGate =
  | { open: true }
  | { open: false; policy: PolicyNode };

/**
 * A VERIFIED voter handle. The poll engine takes this as already-trusted input;
 * it does NOT perform authentication or proof verification. The two shapes match
 * the two pools polling.md describes:
 *
 *  - "membership": anonymous / named-set polls. The caller has already verified a
 *    @ministryofmany/membership proof (its VerifyResult.nullifier is the field-string
 *    membership nullifier). The poll's per-(poll, member) nullifier is derived
 *    from this so a member is unlinkable across polls yet at most one cast counts.
 *
 *  - "subject": pseudonymous polls. The caller has authenticated an identity (an
 *    OIDC pairwise `sub`, a session principal, ...) and supplies its stable
 *    string. The per-(poll, member) nullifier is derived from this subject.
 *
 * In BOTH cases the handle reduces to one stable secret-bearing string per real
 * member, which the cast path turns into the per-poll nullifier (see ./cast.ts).
 */
export type VoterHandle =
  | {
      kind: "membership";
      /**
       * The membership nullifier from a verified @ministryofmany/membership proof
       * (VerifyResult.nullifier), a decimal field-element string. Stable for a
       * given (member, membership-context); unlinkable across contexts.
       */
      membershipNullifier: FieldString;
    }
  | {
      kind: "subject";
      /**
       * The authenticated, stable per-relying-party subject (e.g. a Minister
       * pairwise `sub`). Never an email or other cross-RP identifier.
       */
      subject: string;
    };

/**
 * A cast envelope: a verified voter handle plus the question-type-specific
 * payload. `T` is the question type's vote payload (e.g. an option id, a
 * yes/no/abstain choice, a ranking, a commit hash, a reveal).
 *
 * The engine derives the per-(poll, member) nullifier from `handle` + `pollId`
 * and stores it under UNIQUE(pollId, nullifier) so a member casts at most once.
 */
export interface Cast<T> {
  handle: VoterHandle;
  vote: T;
}

/**
 * A stored vote: the per-poll nullifier (the one-vote key, never the handle) and
 * the validated, NORMALIZED vote payload the question type produced. The handle
 * itself is intentionally NOT persisted - only the nullifier - so a stored vote
 * carries no linkage back to the membership context or subject beyond this poll.
 */
export interface StoredVote<T> {
  /** The per-(poll, member) nullifier; the UNIQUE one-vote key within the poll. */
  nullifier: FieldString;
  /** The validated + normalized vote payload (the question type owns its shape). */
  vote: T;
}

/**
 * A poll record. `Config`, `Vote`, and `Tally` are the question type's own
 * shapes; the engine threads them through generically. `questionType` is the
 * registered slug (e.g. "single-choice", "yes-no", "ranked", "schedule",
 * "commit-reveal", "raffle", "verdict") used to look up the QuestionType impl.
 */
export interface Poll<Config = unknown> {
  id: string;
  questionType: string;
  audienceGate: AudienceGate;
  config: Config;
  lifecycle: PollLifecycle;
}
