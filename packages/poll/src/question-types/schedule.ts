// schedule (multi-select / pick-time-slots, Doodle-style): each voter selects any
// subset of the offered slots; the result view is a heatmap of per-slot counts
// plus the best (most-selected) slot(s). The same engine serves a generic
// multi-select question (the "slots" are just option ids).

import { z } from "zod";
import { err, type Result } from "../errors.js";
import type { QuestionType } from "../question-type.js";
import type { ScheduleView, SlotCount } from "../result-views.js";
import type { StoredVote } from "../types.js";

export interface ScheduleConfig {
  /** Offered slot ids, in display order. Non-empty + unique. */
  slots: string[];
  /** Minimum selections a ballot must make. Default 0 (a voter may pick none). */
  minSelections?: number;
  /** Maximum selections a ballot may make. Default = all slots. */
  maxSelections?: number;
}

/** A schedule ballot: the chosen slot ids (a subset, deduped + normalized). */
export interface ScheduleVote {
  selected: string[];
}

export interface ScheduleTally {
  counts: Record<string, number>;
}

const voteSchema = z.object({ selected: z.array(z.string()) }).strict();

export const schedule: QuestionType<ScheduleConfig, ScheduleVote, ScheduleTally> = {
  slug: "schedule",

  validateVote(config, raw): Result<{ vote: ScheduleVote }> {
    const parsed = voteSchema.safeParse(raw);
    if (!parsed.success) return err("invalid-vote", "expected { selected: string[] }");
    const unique = [...new Set(parsed.data.selected)];
    for (const s of unique) {
      if (!config.slots.includes(s)) return err("invalid-vote", `"${s}" is not an offered slot`);
    }
    const min = config.minSelections ?? 0;
    const max = config.maxSelections ?? config.slots.length;
    if (unique.length < min) return err("invalid-vote", `select at least ${min} slot(s)`);
    if (unique.length > max) return err("invalid-vote", `select at most ${max} slot(s)`);
    // Normalize to config order so storage is canonical regardless of input order.
    const selected = config.slots.filter((s) => unique.includes(s));
    return { ok: true, vote: { selected } };
  },

  tally(config, votes): ScheduleTally {
    const counts: Record<string, number> = {};
    for (const slot of config.slots) counts[slot] = 0;
    for (const v of votes) {
      for (const s of v.vote.selected) {
        if (Object.prototype.hasOwnProperty.call(counts, s)) {
          counts[s] = (counts[s] ?? 0) + 1;
        }
      }
    }
    return { counts };
  },

  resultView(config, tally): ScheduleView {
    const slots: SlotCount[] = config.slots.map((slot) => ({ slot, count: tally.counts[slot] ?? 0 }));
    const maxCount = slots.reduce((m, s) => Math.max(m, s.count), 0);
    const best = maxCount === 0 ? [] : slots.filter((s) => s.count === maxCount).map((s) => s.slot);
    return { kind: "schedule", slots, best };
  },

  resolve(config, votes): Result<{ tally: ScheduleTally }> {
    return { ok: true, tally: this.tally(config, votes) };
  },
};
