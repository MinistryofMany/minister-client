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
import { uniformIndex } from "../hash.js";
import type { QuestionType } from "../question-type.js";
import type { WinnerView } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface RaffleConfig {
  /**
   * The public draw seed (a revealed commit-reveal preimage or a VRF/beacon
   * value). REQUIRED to resolve; until it is set, resolve fails closed
   * (not-resolvable) rather than drawing from unseeded randomness.
   */
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

/** Deterministic entrant ordering: ascending by numeric nullifier value. The
 *  draw domain MUST be canonical so the winner is reproducible regardless of the
 *  order votes were stored or returned in. */
export function sortedEntrants(votes: StoredVote<RaffleVote>[]): string[] {
  return votes
    .map((v) => v.nullifier)
    .sort((a, b) => {
      const da = BigInt(a);
      const db = BigInt(b);
      return da < db ? -1 : da > db ? 1 : 0;
    });
}

/**
 * Draw the winner: a pure, verifiable function of (seed, sorted entrants). Anyone
 * can recompute it. Fails closed with no seed or no entrants.
 */
export async function drawWinner(
  config: RaffleConfig,
  votes: StoredVote<RaffleVote>[],
): Promise<Result<{ tally: RaffleTally }>> {
  if (config.seed === undefined) {
    return err("not-resolvable", "raffle resolve requires a public seed in config");
  }
  const entrants = sortedEntrants(votes);
  if (entrants.length === 0) {
    return err("not-resolvable", "raffle has no entrants to draw from");
  }
  const idx = await uniformIndex(config.seed, entrants.length);
  return { ok: true, tally: { entrants, winner: entrants[idx]!, seed: config.seed } };
}
