// yes-no: a motion with an OPTIONAL quorum + supermajority threshold. The
// threshold math is byte-for-byte FreedInk's tally.ts:
//
//     threshold = ceil(eligible * numerator / denominator)
//
// with the supermajority numerator/denominator configurable and DEFAULTING to
// 2/3 (FreedInk's blog approval default). "yes" passes when it reaches the
// threshold; "no" fails the motion when IT reaches the threshold; otherwise
// undecided. An optional `quorum` adds a minimum-turnout floor: even a yes
// supermajority does not pass if turnout is below the quorum.

import { z } from "zod";
import { err, type Result } from "../errors.js";
import type { QuestionType } from "../question-type.js";
import type { ThresholdView } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface YesNoConfig {
  /**
   * Eligible population (the denominator of the supermajority bar). This is the
   * FROZEN eligible count - the caller passes the snapshot/membership size at the
   * time the poll opened, exactly as FreedInk freezes eligibleReviewersAtReview
   * to close the quorum-capture attack. The engine does not recompute it.
   */
  eligible: number;
  /** Supermajority numerator. Defaults to 2 if omitted. */
  numerator?: number;
  /** Supermajority denominator. Defaults to 3 if omitted. */
  denominator?: number;
  /** Whether "abstain" is an allowed choice. Default false (yes/no only). */
  allowAbstain?: boolean;
  /**
   * Optional minimum-turnout floor: total counted votes (yes + no + abstain)
   * must be >= ceil(eligible * quorum.num / quorum.den) or the motion cannot
   * pass even with a yes supermajority. Omit for no turnout floor.
   */
  quorum?: { num: number; den: number };
}

export type YesNoChoice = "yes" | "no" | "abstain";

export interface YesNoVote {
  choice: YesNoChoice;
}

export interface YesNoTally {
  yes: number;
  no: number;
  abstain: number;
}

const DEFAULT_NUM = 2;
const DEFAULT_DEN = 3;

const voteSchema = z.object({ choice: z.enum(["yes", "no", "abstain"]) }).strict();

/** The FreedInk threshold formula, isolated for the golden test. */
export function thresholdFor(eligible: number, numerator: number, denominator: number): number {
  return Math.ceil((eligible * numerator) / denominator);
}

export const yesNo: QuestionType<YesNoConfig, YesNoVote, YesNoTally> = {
  slug: "yes-no",

  validateVote(config, raw): Result<{ vote: YesNoVote }> {
    const parsed = voteSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { choice: 'yes'|'no'|'abstain' }");
    if (parsed.data.choice === "abstain" && !config.allowAbstain) {
      return err("invalid-vote", "abstain is not allowed for this motion");
    }
    return { ok: true, vote: { choice: parsed.data.choice } };
  },

  tally(_config, votes): YesNoTally {
    const t: YesNoTally = { yes: 0, no: 0, abstain: 0 };
    for (const v of votes) t[v.vote.choice] += 1;
    return t;
  },

  resultView(config, tally): ThresholdView {
    const numerator = config.numerator ?? DEFAULT_NUM;
    const denominator = config.denominator ?? DEFAULT_DEN;
    const threshold = thresholdFor(config.eligible, numerator, denominator);
    const counted = tally.yes + tally.no + tally.abstain;

    let quorumMet = true;
    if (config.quorum) {
      const quorumFloor = thresholdFor(config.eligible, config.quorum.num, config.quorum.den);
      quorumMet = counted >= quorumFloor;
    }

    let outcome: ThresholdView["outcome"] = "undecided";
    if (threshold > 0 && quorumMet) {
      if (tally.yes >= threshold) outcome = "passed";
      else if (tally.no >= threshold) outcome = "failed";
    }

    return {
      kind: "threshold",
      yes: tally.yes,
      no: tally.no,
      abstain: tally.abstain,
      counted,
      threshold,
      eligible: config.eligible,
      numerator,
      denominator,
      outcome,
      quorumMet,
    };
  },

  resolve(config, votes): Result<{ tally: YesNoTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};
