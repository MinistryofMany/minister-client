// verdict: a binary accept / reject decision (the "Ghost Jury" shape). Unlike
// yes-no it carries no eligible-population threshold - it is a simple majority of
// the cast verdicts. A tie (equal accept and reject) is reported as "tied" so the
// caller decides what a deadlocked jury means rather than the engine guessing.

import { z } from "zod";
import { err, type Result } from "../errors.js";
import type { QuestionType } from "../question-type.js";
import type { VerdictView } from "../result-views.js";
import type { StoredVote } from "../types.js";

// verdict has no per-poll settings today; an empty config keeps the shape uniform
// and leaves room for future options (e.g. a unanimity requirement) without an
// interface break.
export type VerdictConfig = Record<string, never>;

export type VerdictChoice = "accept" | "reject";

export interface VerdictVote {
  choice: VerdictChoice;
}

export interface VerdictTally {
  accept: number;
  reject: number;
}

const voteSchema = z.object({ choice: z.enum(["accept", "reject"]) }).strict();

export const verdict: QuestionType<VerdictConfig, VerdictVote, VerdictTally> = {
  slug: "verdict",

  validateVote(_config, raw): Result<{ vote: VerdictVote }> {
    const parsed = voteSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { choice: 'accept'|'reject' }");
    return { ok: true, vote: { choice: parsed.data.choice } };
  },

  tally(_config, votes): VerdictTally {
    const t: VerdictTally = { accept: 0, reject: 0 };
    for (const v of votes) t[v.vote.choice] += 1;
    return t;
  },

  resultView(_config, tally): VerdictView {
    let outcome: VerdictView["outcome"] = "tied";
    if (tally.accept > tally.reject) outcome = "accepted";
    else if (tally.reject > tally.accept) outcome = "rejected";
    return { kind: "verdict", accept: tally.accept, reject: tally.reject, outcome };
  },

  resolve(config, votes): Result<{ tally: VerdictTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};
