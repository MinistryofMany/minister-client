// raffle / draw-a-random-winner (the "Hat Pass" shape).
//
// Each verified member ENTERS once (the unstuffability guard already makes that
// one entry per member). resolve() draws exactly one winner from the entrant set.
//
// FAIRNESS + VERIFIABILITY (the security property):
//   The winner is a DETERMINISTIC function of two PUBLIC inputs -
//     (1) the sorted entrant nullifier list, and
//     (2) a public seed -
//   via uniformIndex(seed, entrants.length) (rejection-sampled, bias-free; see
//   ../hash.ts). There is NO unseeded randomness: Math.random is never used (it
//   is unseedable, unverifiable, and banned in this environment). Anyone holding
//   the public seed and the entrant list recomputes the same winner and audits
//   the draw.
//
//   The seed is supplied by the CALLER in config at resolve time. Two sanctioned
//   schemes, each with its trust assumption:
//
//     a) COMMIT-REVEAL SEED. Before entries open, the operator publishes
//        H(seedPreimage). After entries close, they reveal seedPreimage; use it as
//        the seed. Trust assumption: the operator cannot grind the outcome because
//        they committed the seed before knowing the entrant set, and anyone can
//        check H(seedPreimage) matches the pre-published commitment. (A colluding
//        operator + last entrant could still grind by choosing whether to enter;
//        for full grinding-resistance use scheme (b).)
//
//     b) EXTERNAL VERIFIABLE RANDOMNESS (VRF / drand / a future block hash).
//        Supply a public randomness beacon value as the seed. Trust assumption is
//        the beacon's: no single party (operator included) can predict or bias it,
//        and the value is publicly verifiable independent of this poll.
//
//   The package does not pick the scheme - it consumes whatever public seed the
//   caller commits to, and guarantees the draw is a pure function of (seed,
//   entrants) so the chosen scheme's trust assumption is the ONLY one in play.

import { z } from "zod";
import { err, type Result } from "../errors.js";
import { seedCommitHash, uniformIndex } from "../hash.js";
import type { QuestionType } from "../question-type.js";
import type { WinnerView } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface RaffleConfig {
  /**
   * The public draw seed (a revealed commit-reveal preimage or a VRF/beacon
   * value). Optional in config: a poll using the commit-reveal scheme commits a
   * `seedCommit` at create and supplies the revealed seed at resolve time via
   * `engine.resolve(pollId, { seed })`. If neither a config seed nor a
   * resolve-time seed is supplied, resolve fails closed (not-resolvable) rather
   * than drawing from unseeded randomness.
   */
  seed?: string;
  /**
   * The COMMIT-REVEAL seed commitment, published at poll create: H(seedPreimage)
   * (domain-separated SHA-256, see ../hash.ts `seedCommitHash`). When set, the
   * seed supplied at resolve time MUST hash to this value or the draw is rejected
   * (not-resolvable) - this is what stops the operator from grinding the outcome,
   * since they committed before knowing the entrant set. When unset, any supplied
   * seed (config or resolve-time) is used as-is (the VRF/beacon scheme, whose
   * trust assumption is the beacon's).
   */
  seedCommit?: string;
}

/**
 * Optional per-resolve overrides. The revealed commit-reveal preimage or beacon
 * value is supplied HERE (after entries close), not in config - so a poll can
 * commit the seed-hash at create and reveal the preimage only once the entrant
 * set is fixed. Omitted -> the config seed (if any) is used (backward compatible).
 */
export interface RaffleResolveOpts {
  /** The revealed public seed to draw from, overriding config.seed. */
  seed?: string;
}

/** A raffle entry carries no payload - entering IS the vote. */
export type RaffleVote = Record<string, never>;

export interface RaffleTally {
  /** Sorted entrant nullifiers (the public draw domain). */
  entrants: string[];
  /** The drawn winner's nullifier, or null before resolve / with no entrants. */
  winner: string | null;
  /** The seed the winner was drawn from (echoed for auditability). */
  seed: string | null;
}

const voteSchema = z.object({}).strict();

export const raffle: QuestionType<RaffleConfig, RaffleVote, RaffleTally> = {
  slug: "raffle",

  validateVote(_config, raw): Result<{ vote: RaffleVote }> {
    // Accept an empty object (entering). Reject extra fields so a caller cannot
    // smuggle a payload that a future change might trust.
    const parsed = voteSchema.safeParse(raw ?? {});
    if (!parsed.success) return err("invalid-vote", "a raffle entry takes no payload");
    return { ok: true, vote: {} };
  },

  // Pre-draw tally: just the entrant domain, no winner yet (seed not applied).
  tally(_config, votes): RaffleTally {
    return { entrants: sortedEntrants(votes), winner: null, seed: null };
  },

  resultView(_config, tally): WinnerView {
    return {
      kind: "winner",
      winner: tally.winner,
      entrants: tally.entrants.length,
      seed: tally.seed,
    };
  },

  // resolve() is async-by-result here: the QuestionType.resolve signature is sync,
  // but the draw needs SubtleCrypto. We expose the async draw as drawWinner and
  // make resolve fail closed if asked to resolve synchronously without a winner
  // already computed. The engine routes raffle resolves through drawWinner.
  resolve(config, votes): Result<{ tally: RaffleTally }> {
    if (config.seed === undefined) {
      return err("not-resolvable", "raffle resolve requires a public seed in config");
    }
    if (votes.length === 0) {
      return err("not-resolvable", "raffle has no entrants to draw from");
    }
    // resolve is synchronous; the actual draw is async (SHA-256). The engine
    // calls drawWinner for raffles. Returning not-resolvable here guards against
    // a caller invoking the sync resolve directly for a raffle.
    return err("not-resolvable", "use drawWinner(config, votes) for the async, seeded raffle draw");
  },
};

/**
 * A canonical entrant nullifier is a non-empty run of ASCII decimal digits (the
 * decimal field-element string the cast path stores). Anything else - a leading
 * sign, hex, whitespace, an empty string - is a poisoned VoteStore row, and we
 * MUST fail closed on it rather than let BigInt(...) throw an uncaught exception
 * out of the draw (which would crash resolve, unlike every other resolve path
 * that returns a typed Result).
 */
const CANONICAL_NULLIFIER = /^[0-9]+$/;

/**
 * Validate the stored entrant nullifiers and return the canonical sorted draw
 * domain, or a typed `not-resolvable` error naming the malformed entrant. The
 * draw domain MUST be canonical (ascending numeric) so the winner is reproducible
 * regardless of the order votes were stored or returned in.
 */
export function validatedSortedEntrants(
  votes: StoredVote<RaffleVote>[],
): Result<{ entrants: string[] }> {
  const nullifiers = votes.map((v) => v.nullifier);
  for (const n of nullifiers) {
    if (typeof n !== "string" || !CANONICAL_NULLIFIER.test(n)) {
      return err(
        "not-resolvable",
        `malformed entrant nullifier ${JSON.stringify(n)}: not a canonical decimal field element`,
      );
    }
  }
  const entrants = nullifiers.sort((a, b) => {
    const da = BigInt(a);
    const db = BigInt(b);
    return da < db ? -1 : da > db ? 1 : 0;
  });
  return { ok: true, entrants };
}

/** Deterministic entrant ordering: ascending by numeric nullifier value. Skips
 *  any non-canonical (non-decimal) nullifier rather than throwing, so the
 *  pre-draw tally never crashes on a poisoned row; `drawWinner` uses the stricter
 *  `validatedSortedEntrants` to fail closed before drawing. The draw domain MUST
 *  be canonical so the winner is reproducible regardless of stored order. */
export function sortedEntrants(votes: StoredVote<RaffleVote>[]): string[] {
  return votes
    .map((v) => v.nullifier)
    .filter((n) => typeof n === "string" && CANONICAL_NULLIFIER.test(n))
    .sort((a, b) => {
      const da = BigInt(a);
      const db = BigInt(b);
      return da < db ? -1 : da > db ? 1 : 0;
    });
}

/**
 * Draw the winner: a pure, verifiable function of (seed, sorted entrants). Anyone
 * can recompute it. Fails closed (typed `not-resolvable`, never a throw) with no
 * seed, no entrants, a malformed entrant nullifier, or a revealed seed that does
 * not match a committed seed-hash.
 *
 * The seed is resolved as: `opts.seed` (the revealed preimage / beacon supplied
 * AFTER entries close) if present, else `config.seed` (the fixed-at-create seed).
 * If the poll committed a `config.seedCommit` at create, the resolved seed MUST
 * hash to it (the commit-reveal grinding guard) or the draw is rejected.
 */
export async function drawWinner(
  config: RaffleConfig,
  votes: StoredVote<RaffleVote>[],
  opts?: RaffleResolveOpts,
): Promise<Result<{ tally: RaffleTally }>> {
  const seed = opts?.seed ?? config.seed;
  if (seed === undefined) {
    return err(
      "not-resolvable",
      "raffle resolve requires a public seed (config.seed or resolve opts.seed)",
    );
  }
  // Commit-reveal grinding guard: if a seed-hash was committed at create, the
  // revealed seed must reproduce it before we draw.
  if (config.seedCommit !== undefined) {
    const recomputed = await seedCommitHash(seed);
    if (recomputed !== config.seedCommit) {
      return err(
        "not-resolvable",
        "revealed raffle seed does not match the committed seed-hash",
      );
    }
  }
  const validated = validatedSortedEntrants(votes);
  if (!validated.ok) return validated;
  const entrants = validated.entrants;
  if (entrants.length === 0) {
    return err("not-resolvable", "raffle has no entrants to draw from");
  }
  const idx = await uniformIndex(seed, entrants.length);
  return { ok: true, tally: { entrants, winner: entrants[idx]!, seed } };
}
