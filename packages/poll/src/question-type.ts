// The QuestionType abstraction: the lever that makes one engine cover every poll
// shape (polling.md "Question type" knob). An implementation fixes four things:
//
//   - Config:  the per-poll settings the type needs (options, num/den, slots...).
//   - Vote:    the per-cast payload, validated + NORMALIZED by validateVote.
//   - Tally:   the intermediate aggregate tally() produces from stored votes.
//   - View:    the result view resultView() renders from a Tally.
//
// The engine owns lifecycle, the unstuffability guard, and the stores; a
// QuestionType owns ONLY the vote semantics. It never touches persistence, auth,
// or nullifiers - keeping each type a small, testable pure unit.

import type { Result } from "./errors.js";
import type { QuestionResultView } from "./result-views.js";
import type { StoredVote } from "./types.js";

/**
 * A question type. Generic over its config, vote payload, and tally shape.
 *
 *  - `slug` is the registry key stored on Poll.questionType.
 *
 *  - `validateVote(config, raw)` parses an UNTRUSTED raw payload into a normalized
 *    Vote, or returns an "invalid-vote" error. It is pure and side-effect-free;
 *    it is the ONLY place a vote shape is trusted. (Commit-reveal validates the
 *    commit at commit time and the reveal separately - see its resolve/reveal.)
 *
 *  - `tally(config, votes)` folds the stored, validated votes into a Tally. Pure.
 *
 *  - `resultView(config, tally)` renders the Tally into the type's result view.
 *    Pure. The engine wraps it with the credibility surface.
 *
 *  - `resolve(config, votes)` computes the FINAL tally for a poll being resolved.
 *    For most types this is just `tally`; commit-reveal overrides it to count
 *    only revealed-and-matching votes, and raffle overrides it to draw a winner
 *    from a public seed. Returns a Result so a non-resolvable state (no seed, no
 *    entrants) fails closed rather than fabricating an outcome.
 */
export interface QuestionType<Config, Vote, Tally> {
  readonly slug: string;

  validateVote(config: Config, raw: unknown): Result<{ vote: Vote }>;

  tally(config: Config, votes: StoredVote<Vote>[]): Tally;

  resultView(config: Config, tally: Tally): QuestionResultView;

  resolve(config: Config, votes: StoredVote<Vote>[]): Result<{ tally: Tally }>;
}
