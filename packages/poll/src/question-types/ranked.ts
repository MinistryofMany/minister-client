// ranked: instant-runoff voting (IRV).
//
// METHOD CHOICE - IRV (not Borda). IRV elects a candidate with a majority of
// active first preferences by repeatedly eliminating the lowest-support
// candidate and transferring those ballots to each ballot's next still-standing
// preference. It is chosen over Borda because it satisfies the majority
// criterion (a candidate ranked first by a majority always wins) and is the
// system most voters mean by "ranked choice", and because it produces an
// auditable round-by-round trace that maps cleanly onto the ranked result view.
//
// TIE-BREAKING (deterministic, documented):
//  - Elimination tie (two+ candidates share the lowest count): eliminate the one
//    that sorts FIRST by the poll's config option order (stable, public, and
//    independent of ballot insertion order). Config order is the published tie
//    rule; nothing here depends on Math.random or wall-clock.
//  - Winner declared when a candidate holds > 50% of the ballots still active
//    (not exhausted). If every remaining ballot is exhausted with no majority,
//    the candidate with the most first preferences in the final round wins,
//    breaking a final tie again by config order. A poll with zero ballots
//    resolves to winner = null.

import { z } from "zod";
import { err, type Result } from "../errors.js";
import type { QuestionType } from "../question-type.js";
import type { RankedRound, RankedStanding, RankedView } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface RankedConfig {
  /** Candidate ids, in display + tie-break order. Non-empty + unique. */
  candidates: string[];
}

/** A ranked ballot: candidate ids in preference order (most preferred first). */
export interface RankedVote {
  ranking: string[];
}

export interface RankedTally {
  rounds: RankedRound[];
  standings: RankedStanding[];
  winner: string | null;
}

const voteSchema = z.object({ ranking: z.array(z.string()) }).strict();

export const ranked: QuestionType<RankedConfig, RankedVote, RankedTally> = {
  slug: "ranked",

  validateVote(config, raw): Result<{ vote: RankedVote }> {
    const parsed = voteSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { ranking: string[] }");
    const ranking = parsed.data.ranking;
    if (ranking.length === 0) return err("invalid-vote", "ranking must list at least one candidate");
    const seen = new Set<string>();
    for (const c of ranking) {
      if (!config.candidates.includes(c)) {
        return err("invalid-vote", `"${c}" is not a candidate`);
      }
      if (seen.has(c)) return err("invalid-vote", `"${c}" is ranked more than once`);
      seen.add(c);
    }
    // A partial ranking is allowed (a ballot may exhaust); we keep it as given.
    return { ok: true, vote: { ranking } };
  },

  tally(config, votes): RankedTally {
    return runIrv(config.candidates, votes.map((v) => v.vote.ranking));
  },

  resultView(_config, tally): RankedView {
    return {
      kind: "ranked",
      standings: tally.standings,
      rounds: tally.rounds,
      winner: tally.winner,
    };
  },

  resolve(config, votes): Result<{ tally: RankedTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};

/**
 * Run IRV over a set of ballots. Pure and deterministic. `candidateOrder` is the
 * config option order used as the tie-break key.
 */
export function runIrv(candidateOrder: string[], ballots: string[][]): RankedTally {
  const orderIndex = new Map(candidateOrder.map((c, i) => [c, i]));
  const tieKey = (c: string) => orderIndex.get(c) ?? Number.MAX_SAFE_INTEGER;

  let active = new Set(candidateOrder);
  const eliminated = new Map<string, number>();
  const rounds: RankedRound[] = [];

  if (ballots.length === 0) {
    return {
      rounds: [],
      standings: candidateOrder.map((c) => ({ candidate: c, eliminatedInRound: null })),
      winner: null,
    };
  }

  let round = 0;
  let winner: string | null = null;

  // Each round: count each ballot's top still-active preference, find a majority
  // of non-exhausted ballots, else eliminate the lowest (config-order tie-break).
  // Bounded by the candidate count.
  while (active.size > 0) {
    round += 1;
    const counts: Record<string, number> = {};
    for (const c of active) counts[c] = 0;

    let activeBallots = 0;
    for (const ballot of ballots) {
      const top = ballot.find((c) => active.has(c));
      if (top !== undefined) {
        counts[top] = (counts[top] ?? 0) + 1;
        activeBallots += 1;
      }
    }

    // Majority of currently-active (non-exhausted) ballots wins outright.
    const leader = pickExtreme(active, counts, "max", tieKey);
    if (leader !== null && counts[leader]! * 2 > activeBallots && activeBallots > 0) {
      rounds.push({ round, counts: { ...counts }, eliminated: null });
      winner = leader;
      break;
    }

    // No majority. If only one candidate remains, they win by plurality.
    if (active.size === 1) {
      rounds.push({ round, counts: { ...counts }, eliminated: null });
      winner = leader;
      break;
    }

    // If every ballot is exhausted, the standing leader (config-order tie-break)
    // wins; we stop here rather than eliminating into an empty field.
    if (activeBallots === 0) {
      rounds.push({ round, counts: { ...counts }, eliminated: null });
      winner = leader;
      break;
    }

    // Eliminate the lowest-support active candidate (config-order tie-break).
    const loser = pickExtreme(active, counts, "min", tieKey);
    if (loser === null) break;
    rounds.push({ round, counts: { ...counts }, eliminated: loser });
    active.delete(loser);
    eliminated.set(loser, round);
  }

  // Standings: winner first (eliminatedInRound null), then survivors that reached
  // the end (null), then eliminated candidates latest-out-first. Order among the
  // same status falls back to config order for determinism.
  const standings: RankedStanding[] = candidateOrder
    .map((candidate) => ({ candidate, eliminatedInRound: eliminated.get(candidate) ?? null }))
    .sort((a, b) => {
      const aWin = a.candidate === winner ? 1 : 0;
      const bWin = b.candidate === winner ? 1 : 0;
      if (aWin !== bWin) return bWin - aWin; // winner first
      const aElim = a.eliminatedInRound;
      const bElim = b.eliminatedInRound;
      if (aElim === null && bElim === null) return tieKey(a.candidate) - tieKey(b.candidate);
      if (aElim === null) return -1; // survivors before eliminated
      if (bElim === null) return 1;
      if (aElim !== bElim) return bElim - aElim; // later elimination ranks higher
      return tieKey(a.candidate) - tieKey(b.candidate);
    });

  return { rounds, standings, winner };
}

/**
 * Pick the active candidate with the max or min count, breaking ties by the
 * lowest tieKey (config order). Returns null if `active` is empty.
 */
function pickExtreme(
  active: Set<string>,
  counts: Record<string, number>,
  mode: "max" | "min",
  tieKey: (c: string) => number,
): string | null {
  let best: string | null = null;
  let bestCount = mode === "max" ? -Infinity : Infinity;
  for (const c of active) {
    const n = counts[c] ?? 0;
    const better = mode === "max" ? n > bestCount : n < bestCount;
    if (best === null || better) {
      best = c;
      bestCount = n;
    } else if (n === bestCount && tieKey(c) < tieKey(best)) {
      best = c;
    }
  }
  return best;
}
