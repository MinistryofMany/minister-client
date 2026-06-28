// single-choice: pick exactly one of a fixed option set. Result view = the
// percentage bar (polling.md result-views v1).

import { z } from "zod";
import { err, type Result } from "../errors.js";
import type { QuestionType } from "../question-type.js";
import type { BarView, OptionShare } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface SingleChoiceConfig {
  /** The selectable option ids, in display order. Must be non-empty + unique. */
  options: string[];
}

/** A single-choice vote: the chosen option id. */
export interface SingleChoiceVote {
  option: string;
}

/** Tally: votes per option, in config order. */
export interface SingleChoiceTally {
  counts: Record<string, number>;
  total: number;
}

const voteSchema = z.object({ option: z.string() }).strict();

export const singleChoice: QuestionType<SingleChoiceConfig, SingleChoiceVote, SingleChoiceTally> = {
  slug: "single-choice",

  validateVote(config, raw): Result<{ vote: SingleChoiceVote }> {
    const parsed = voteSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { option: string }");
    if (!config.options.includes(parsed.data.option)) {
      return err("invalid-vote", `option "${parsed.data.option}" is not in the poll's option set`);
    }
    return { ok: true, vote: { option: parsed.data.option } };
  },

  tally(config, votes): SingleChoiceTally {
    const counts: Record<string, number> = {};
    for (const option of config.options) counts[option] = 0;
    for (const v of votes) {
      // A stored vote always passed validateVote, so its option is in the set;
      // guard defensively anyway so an out-of-set value can never NaN the bar.
      if (Object.prototype.hasOwnProperty.call(counts, v.vote.option)) {
        counts[v.vote.option] = (counts[v.vote.option] ?? 0) + 1;
      }
    }
    return { counts, total: votes.length };
  },

  resultView(config, tally): BarView {
    const options: OptionShare[] = config.options.map((option) => {
      const v = tally.counts[option] ?? 0;
      return { option, votes: v, fraction: tally.total === 0 ? 0 : v / tally.total };
    });
    return { kind: "bar", options, totalVotes: tally.total };
  },

  resolve(config, votes): Result<{ tally: SingleChoiceTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};
