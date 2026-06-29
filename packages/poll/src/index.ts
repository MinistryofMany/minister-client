// @ministryofmany/poll - a framework-agnostic polling / decision engine.
//
// One engine, many surfaces (polling.md): a Poll = { id, questionType,
// audienceGate, config, lifecycle } whose behavior is fixed by three levers -
// the QUESTION TYPE (single-choice, yes-no + quorum/supermajority, ranked IRV,
// schedule/multi-select, commit-reveal, raffle, verdict), the AUDIENCE GATE (a
// @ministryofmany/policy badge requirement AST), and the RESULT VIEW. Every cast is
// UNSTUFFABLE: a verified voter handle plus a per-(poll, member) nullifier from
// @ministryofmany/nullifier, one-vote-guarded by an insert-or-reject VoteStore. All
// storage is behind injectable PollStore / VoteStore interfaces - no ORM here.

// Core domain types.
export type {
  Poll,
  PollLifecycle,
  AudienceGate,
  VoterHandle,
  Cast,
  StoredVote,
} from "./types.js";

// Errors / results.
export type { Result, PollError, PollErrorCode } from "./errors.js";
export { err } from "./errors.js";

// Persistence + the unstuffability guard contract.
export type { PollStore, VoteStore, CastOutcome } from "./store.js";

// The unstuffability core (nullifier derivation).
export { deriveVoteNullifier, pollContextId, FIELD } from "./cast.js";

// The question-type abstraction + the credibility surface + result views.
export type { QuestionType } from "./question-type.js";
export type {
  Credibility,
  ResultView,
  QuestionResultView,
  BarView,
  OptionShare,
  ThresholdView,
  RankedView,
  RankedStanding,
  RankedRound,
  ScheduleView,
  SlotCount,
  WinnerView,
  VerdictView,
} from "./result-views.js";

// Hash primitives (commit-reveal binding + raffle draw).
export { sha256Hex, commitHash, seedCommitHash, uniformIndex } from "./hash.js";

// The shipped question types + their config/vote/tally types + helpers.
export * from "./question-types/index.js";

// The orchestrator.
export type { PollEngine, PollEngineConfig, CreatePollInput } from "./engine.js";
export { createPollEngine } from "./engine.js";
