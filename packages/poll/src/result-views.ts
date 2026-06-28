// Result-view shapes (polling.md "Result view" knob). Every view carries the
// credibility surface: the distinct-verified-voter count and the pool definition
// (the audience gate), so a viewer can judge that the number is unstuffable. The
// engine attaches `voters` + `pool` to whatever the question type returns.

import type { AudienceGate } from "./types.js";

/** The credibility surface shared by every result view. */
export interface Credibility {
  /** Distinct verified voters = distinct recorded nullifiers (UNIQUE-guarded). */
  distinctVoters: number;
  /** The pool definition (audience gate), so a viewer sees WHO could vote. */
  pool: AudienceGate;
}

/** One option's share, for a percentage-bar view. */
export interface OptionShare {
  option: string;
  votes: number;
  /** Share of total cast votes, 0..1 (0 when no votes). */
  fraction: number;
}

/** Percentage-bar view (single-choice). */
export interface BarView {
  kind: "bar";
  options: OptionShare[];
  totalVotes: number;
}

/** Quorum / threshold outcome (yes-no + quorum/supermajority). */
export interface ThresholdView {
  kind: "threshold";
  yes: number;
  no: number;
  abstain: number;
  /** Votes that counted toward the threshold denominator. */
  counted: number;
  /** ceil(eligible * num / den) - the FreedInk threshold formula. */
  threshold: number;
  eligible: number;
  numerator: number;
  denominator: number;
  /** "yes" crossed the bar, "no" crossed it, or neither did. */
  outcome: "passed" | "failed" | "undecided";
  /** Whether the quorum (a minimum-turnout floor, if configured) was met. */
  quorumMet: boolean;
}

/** Ranked standings (IRV). One entry per candidate, final order. */
export interface RankedView {
  kind: "ranked";
  /** Candidates in finishing order (winner first). */
  standings: RankedStanding[];
  /** The IRV round-by-round tallies, for an auditable result. */
  rounds: RankedRound[];
  winner: string | null;
}

export interface RankedStanding {
  candidate: string;
  /** Round the candidate was eliminated, or null if they won / reached the end. */
  eliminatedInRound: number | null;
}

export interface RankedRound {
  round: number;
  /** Live first-preference counts among not-yet-eliminated candidates. */
  counts: Record<string, number>;
  /** Candidate eliminated this round, or null on the deciding round. */
  eliminated: string | null;
}

/** Schedule heatmap (multi-select / pick-time-slots). */
export interface ScheduleView {
  kind: "schedule";
  /** Per-slot count of voters who selected it, in the poll's slot order. */
  slots: SlotCount[];
  /** Slot(s) with the most selections (could tie), for a "best time" surface. */
  best: string[];
}

export interface SlotCount {
  slot: string;
  count: number;
}

/** Winner view (raffle / draw). */
export interface WinnerView {
  kind: "winner";
  winner: FieldStringOrNull;
  /** Number of entrants the draw chose among. */
  entrants: number;
  /** The public seed the winner was derived from (so anyone can recompute). */
  seed: string | null;
}

type FieldStringOrNull = string | null;

/** Verdict outcome (accept / reject). */
export interface VerdictView {
  kind: "verdict";
  accept: number;
  reject: number;
  outcome: "accepted" | "rejected" | "tied";
}

/** The union of every question type's view, each tagged by `kind`. */
export type QuestionResultView =
  | BarView
  | ThresholdView
  | RankedView
  | ScheduleView
  | WinnerView
  | VerdictView;

/** A result view as returned by the engine: the question view + credibility. */
export type ResultView = QuestionResultView & { credibility: Credibility };
