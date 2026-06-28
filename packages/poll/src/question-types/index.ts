// The shipped question-type registry. Each is the lever a poll selects via
// Poll.questionType. The default registry covers every type in the spec; a
// consumer can build its own registry (e.g. to add a custom type) and pass it to
// createPollEngine.

import type { QuestionType } from "../question-type.js";
import { singleChoice } from "./single-choice.js";
import { yesNo } from "./yes-no.js";
import { ranked } from "./ranked.js";
import { schedule } from "./schedule.js";
import { commitReveal } from "./commit-reveal.js";
import { raffle } from "./raffle.js";
import { verdict } from "./verdict.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- a heterogeneous
// registry maps slugs to question types of differing Config/Vote/Tally; the engine
// re-narrows per poll. The `any` is confined to the registry value type.
export type AnyQuestionType = QuestionType<any, any, any>;

/** The default registry: slug -> question type. */
export const defaultQuestionTypes: Record<string, AnyQuestionType> = {
  [singleChoice.slug]: singleChoice,
  [yesNo.slug]: yesNo,
  [ranked.slug]: ranked,
  [schedule.slug]: schedule,
  [commitReveal.slug]: commitReveal,
  [raffle.slug]: raffle,
  [verdict.slug]: verdict,
};

export { singleChoice, yesNo, ranked, schedule, commitReveal, raffle, verdict };
export type { SingleChoiceConfig, SingleChoiceVote, SingleChoiceTally } from "./single-choice.js";
export type { YesNoConfig, YesNoVote, YesNoTally, YesNoChoice } from "./yes-no.js";
export { thresholdFor } from "./yes-no.js";
export type { RankedConfig, RankedVote, RankedTally } from "./ranked.js";
export { runIrv } from "./ranked.js";
export type { ScheduleConfig, ScheduleVote, ScheduleTally } from "./schedule.js";
export type { VerdictConfig, VerdictVote, VerdictTally, VerdictChoice } from "./verdict.js";
export type {
  CommitRevealConfig,
  CommitRevealVote,
  CommitRevealTally,
} from "./commit-reveal.js";
export { buildCommit, verifyReveal } from "./commit-reveal.js";
export type { RaffleConfig, RaffleVote, RaffleTally } from "./raffle.js";
export { drawWinner, sortedEntrants } from "./raffle.js";
