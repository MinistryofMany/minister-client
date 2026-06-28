// Typed, fail-closed results for the poll engine.
//
// EXPECTED failures (a vote that does not validate, a double-vote, a cast against
// a closed poll, a non-matching reveal) are returned as discriminated results,
// never thrown - so a caller cannot accidentally treat a rejected cast as
// accepted. Throwing is reserved for programmer error (an unknown question type,
// an illegal lifecycle call) where there is no meaningful caller recovery.

/** Why a cast / reveal / lifecycle action was rejected. */
export type PollErrorCode =
  // The poll is not in a stage that accepts this action (e.g. cast on a draft /
  // closed / resolved poll, reveal outside the reveal window).
  | "wrong-lifecycle"
  // The vote payload failed the question type's validateVote.
  | "invalid-vote"
  // A second cast from the same member (UNIQUE(pollId, nullifier) hit). This is
  // the unstuffability guard firing.
  | "already-voted"
  // A reveal did not reproduce the stored commit hash (commit-reveal binding).
  | "reveal-mismatch"
  // A reveal arrived for a member who never committed.
  | "no-commit"
  // A raffle / resolve was asked to draw with no seed material or no entrants.
  | "not-resolvable";

export interface PollError {
  ok: false;
  code: PollErrorCode;
  message: string;
}

export type Result<T> = ({ ok: true } & T) | PollError;

export function err(code: PollErrorCode, message: string): PollError {
  return { ok: false, code, message };
}
