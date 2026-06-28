// commit-reveal: a two-phase sealed vote (the "Sealed Bets" shape).
//
//   Phase 1 (poll OPEN):   the voter CASTS a commit = a binding hash of
//                          (choice, salt). The engine stores only the hash, so no
//                          one - not even the operator - learns the choice yet.
//                          This consumes the member's one vote (one nullifier row).
//
//   Phase 2 (poll CLOSED): the voter REVEALS (choice, salt). The engine recomputes
//                          commitHash(choice, salt) and accepts the reveal ONLY if
//                          it reproduces the stored commit. A reveal that does not
//                          match is rejected (reveal-mismatch), so a voter can
//                          neither change their choice after committing nor reveal a
//                          value other than what they sealed.
//
//   resolve (-> RESOLVED): tallies ONLY revealed-and-matching votes. A commit that
//                          was never (or wrongly) revealed contributes nothing.
//
// The binding hash is SHA-256 over a domain-separated, unit-separator-delimited
// encoding (see ../hash.ts). The salt is the voter's secret blinding value; the
// caller is responsible for using a high-entropy salt (documented below).

import { z } from "zod";
import { err, type Result } from "../errors.js";
import { commitHash } from "../hash.js";
import type { QuestionType } from "../question-type.js";
import type { BarView, OptionShare } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface CommitRevealConfig {
  /** The allowed choices (the menu the sealed choice must belong to). Non-empty. */
  options: string[];
}

/**
 * The stored payload for a commit-reveal vote. At commit time only `commit` is
 * present; a successful reveal fills in `revealed`. The `commit` is immutable once
 * set - the engine's reveal path only ever sets `revealed`, never rewrites
 * `commit` - which is what makes a post-commit choice change impossible.
 */
export interface CommitRevealVote {
  /** The binding hash committed during the open phase. */
  commit: string;
  /** The opened (choice, salt), set iff a matching reveal was accepted. */
  revealed?: { choice: string; salt: string };
}

export interface CommitRevealTally {
  /** Counts over REVEALED-AND-MATCHING votes only. */
  counts: Record<string, number>;
  /** Number of commits cast (sealed votes), revealed or not. */
  committed: number;
  /** Number of valid reveals counted. */
  revealed: number;
}

const commitSchema = z.object({ commit: z.string().min(1) }).strict();

export const commitReveal: QuestionType<CommitRevealConfig, CommitRevealVote, CommitRevealTally> = {
  slug: "commit-reveal",

  /**
   * validateVote handles the COMMIT (the cast phase). It accepts only a commit
   * hash; the choice is sealed and unknown at this point. The reveal is NOT a
   * cast and does not flow through here - it is the engine's `reveal` action,
   * which calls `verifyReveal` below.
   */
  validateVote(_config, raw): Result<{ vote: CommitRevealVote }> {
    const parsed = commitSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { commit: string } (a commitment hash)");
    return { ok: true, vote: { commit: parsed.data.commit } };
  },

  tally(config, votes): CommitRevealTally {
    const counts: Record<string, number> = {};
    for (const option of config.options) counts[option] = 0;
    let committed = 0;
    let revealed = 0;
    for (const v of votes) {
      committed += 1;
      const r = v.vote.revealed;
      if (r && Object.prototype.hasOwnProperty.call(counts, r.choice)) {
        counts[r.choice] = (counts[r.choice] ?? 0) + 1;
        revealed += 1;
      }
    }
    return { counts, committed, revealed };
  },

  resultView(config, tally): BarView {
    const options: OptionShare[] = config.options.map((option) => {
      const v = tally.counts[option] ?? 0;
      return { option, votes: v, fraction: tally.revealed === 0 ? 0 : v / tally.revealed };
    });
    return { kind: "bar", options, totalVotes: tally.revealed };
  },

  // resolve == tally: tally already counts only revealed-and-matching votes.
  resolve(config, votes): Result<{ tally: CommitRevealTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};

/**
 * Build a commit for the CLIENT side: hash (choice, salt). The caller picks the
 * salt; it MUST be high-entropy and unguessable (e.g. 32 random bytes hex), or an
 * adversary who knows the option set could brute-force the commit to learn the
 * sealed choice before reveal. Returned as the `{ commit }` payload to cast.
 */
export async function buildCommit(choice: string, salt: string): Promise<CommitRevealVote> {
  return { commit: await commitHash(choice, salt) };
}

/**
 * Verify a reveal against a stored commit. Returns the opened (choice, salt) iff
 * commitHash(choice, salt) reproduces `storedCommit` AND choice is in the option
 * set; otherwise a reveal-mismatch / invalid-vote error. This is the binding
 * check: a voter cannot reveal a different value than committed, because any other
 * (choice, salt) hashes to a different commit.
 */
export async function verifyReveal(
  config: CommitRevealConfig,
  storedCommit: string,
  raw: unknown,
): Promise<Result<{ choice: string; salt: string }>> {
  const revealSchema = z.object({ choice: z.string(), salt: z.string() }).strict();
  const parsed = revealSchema.safeParse(raw);
  if (!parsed.success) return err("invalid-vote", "expected { choice: string, salt: string }");
  const { choice, salt } = parsed.data;
  if (!config.options.includes(choice)) {
    return err("invalid-vote", `revealed choice "${choice}" is not in the option set`);
  }
  const recomputed = await commitHash(choice, salt);
  if (recomputed !== storedCommit) {
    return err("reveal-mismatch", "reveal does not reproduce the committed hash");
  }
  return { ok: true, choice, salt };
}
