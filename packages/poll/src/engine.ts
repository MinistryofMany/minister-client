// createPollEngine - the orchestrator.
//
// It owns the three cross-cutting concerns and leaves vote semantics to the
// question types:
//
//   1. LIFECYCLE. open/close/resolve transitions, enforced (no cast on a draft or
//      resolved poll; reveal only in the closed window).
//   2. UNSTUFFABILITY. cast() derives the per-(poll, member) nullifier from the
//      verified voter handle and stores the vote through VoteStore.castOnce
//      (insert-or-reject UNIQUE(pollId, nullifier)) - the one-vote + no-cross-poll
//      -replay guard.
//   3. TALLY / VIEW / RESOLVE. delegated to the poll's QuestionType, with the
//      credibility surface (distinct verified voters + the pool) attached.
//
// No ORM, no auth, no proof verification live here: the caller supplies a verified
// VoterHandle and injects PollStore + VoteStore.

import { deriveVoteNullifier } from "./cast.js";
import { err, type PollError, type Result } from "./errors.js";
import {
  defaultQuestionTypes,
  drawWinner,
  verifyReveal,
  type AnyQuestionType,
} from "./question-types/index.js";
import type { CommitRevealConfig, CommitRevealVote } from "./question-types/commit-reveal.js";
import type { RaffleConfig, RaffleVote } from "./question-types/raffle.js";
import type { Credibility, ResultView } from "./result-views.js";
import type { PollStore, VoteStore } from "./store.js";
import type { AudienceGate, Poll, PollLifecycle, StoredVote, VoterHandle } from "./types.js";

export interface PollEngineConfig {
  pollStore: PollStore;
  voteStore: VoteStore;
  /** Slug -> question type. Defaults to the shipped registry. */
  questionTypes?: Record<string, AnyQuestionType>;
}

/** Input to create a poll. The engine assigns no id - the caller owns id minting. */
export interface CreatePollInput {
  id: string;
  questionType: string;
  audienceGate: AudienceGate;
  config: unknown;
  /** Initial lifecycle, default "draft". */
  lifecycle?: PollLifecycle;
}

export interface PollEngine {
  create(input: CreatePollInput): Promise<Result<{ poll: Poll }>>;

  /** Transition a poll to a new lifecycle stage (validated). */
  transition(pollId: string, to: PollLifecycle): Promise<Result<{ poll: Poll }>>;

  /**
   * Cast a vote. For commit-reveal this is the COMMIT (the raw payload is a
   * { commit } hash). Derives the per-poll nullifier, validates the payload, and
   * records it insert-or-reject. Returns the nullifier on success.
   */
  cast(pollId: string, handle: VoterHandle, vote: unknown): Promise<Result<{ nullifier: string }>>;

  /**
   * Reveal a commit-reveal vote (the open phase). Matches the reveal to the
   * member's stored commit and attaches it. Only valid while the poll is closed.
   */
  reveal(pollId: string, handle: VoterHandle, reveal: unknown): Promise<Result<{ nullifier: string }>>;

  /** Current tally + result view (with the credibility surface). */
  results(pollId: string): Promise<Result<{ view: ResultView }>>;

  /**
   * Resolve a poll: compute the final tally, transition to "resolved", and return
   * the final view. For raffle this runs the seeded, verifiable draw.
   */
  resolve(pollId: string): Promise<Result<{ view: ResultView }>>;
}

const LEGAL_TRANSITIONS: Record<PollLifecycle, PollLifecycle[]> = {
  draft: ["open"],
  open: ["closed"],
  closed: ["resolved"],
  resolved: [],
};

export function createPollEngine(cfg: PollEngineConfig): PollEngine {
  const registry = cfg.questionTypes ?? defaultQuestionTypes;

  function lookup(poll: Poll): AnyQuestionType {
    const qt = registry[poll.questionType];
    if (!qt) throw new Error(`@minister/poll: unknown question type "${poll.questionType}"`);
    return qt;
  }

  async function loadPoll(pollId: string): Promise<Poll | PollError> {
    const poll = await cfg.pollStore.get(pollId);
    if (!poll) return err("not-resolvable", `poll "${pollId}" not found`);
    return poll;
  }

  function credibility(poll: Poll, distinctVoters: number): Credibility {
    return { distinctVoters, pool: poll.audienceGate };
  }

  return {
    async create(input): Promise<Result<{ poll: Poll }>> {
      if (!registry[input.questionType]) {
        return err("invalid-vote", `unknown question type "${input.questionType}"`);
      }
      const poll: Poll = {
        id: input.id,
        questionType: input.questionType,
        audienceGate: input.audienceGate,
        config: input.config,
        lifecycle: input.lifecycle ?? "draft",
      };
      await cfg.pollStore.create(poll);
      return { ok: true, poll };
    },

    async transition(pollId, to): Promise<Result<{ poll: Poll }>> {
      const poll = await loadPoll(pollId);
      if ("ok" in poll) return poll;
      if (!LEGAL_TRANSITIONS[poll.lifecycle].includes(to)) {
        return err(
          "wrong-lifecycle",
          `cannot transition poll from "${poll.lifecycle}" to "${to}"`,
        );
      }
      await cfg.pollStore.setLifecycle(pollId, to);
      return { ok: true, poll: { ...poll, lifecycle: to } };
    },

    async cast(pollId, handle, vote): Promise<Result<{ nullifier: string }>> {
      const poll = await loadPoll(pollId);
      if ("ok" in poll) return poll;
      // Casting (incl. a commit-reveal commit) is only legal while OPEN.
      if (poll.lifecycle !== "open") {
        return err("wrong-lifecycle", `poll is "${poll.lifecycle}"; casting requires "open"`);
      }
      const qt = lookup(poll);
      const validated = qt.validateVote(poll.config, vote);
      if (!validated.ok) return validated;

      const nullifier = deriveVoteNullifier(handle, pollId);
      const outcome = await cfg.voteStore.castOnce(pollId, { nullifier, vote: validated.vote });
      if (outcome.status === "replay") {
        return err("already-voted", "this member has already voted in this poll");
      }
      return { ok: true, nullifier };
    },

    async reveal(pollId, handle, revealPayload): Promise<Result<{ nullifier: string }>> {
      const poll = await loadPoll(pollId);
      if ("ok" in poll) return poll;
      if (poll.questionType !== "commit-reveal") {
        return err("invalid-vote", "reveal is only valid for a commit-reveal poll");
      }
      // Reveals happen in the CLOSED window (after casting, before resolve).
      if (poll.lifecycle !== "closed") {
        return err("wrong-lifecycle", `poll is "${poll.lifecycle}"; reveal requires "closed"`);
      }

      const nullifier = deriveVoteNullifier(handle, pollId);
      // Find the member's committed row. The reveal must NOT create a new row -
      // the member already consumed their one vote at commit time.
      const all = (await cfg.voteStore.list(pollId)) as StoredVote<CommitRevealVote>[];
      const committed = all.find((v) => v.nullifier === nullifier);
      if (!committed) return err("no-commit", "no commit found for this member");

      const config = poll.config as CommitRevealConfig;
      const checked = await verifyReveal(config, committed.vote.commit, revealPayload);
      if (!checked.ok) return checked;

      // Attach the reveal to the EXISTING row (commit stays immutable).
      const next: CommitRevealVote = {
        commit: committed.vote.commit,
        revealed: { choice: checked.choice, salt: checked.salt },
      };
      const updated = await cfg.voteStore.update(pollId, nullifier, next);
      if (!updated) return err("no-commit", "commit row vanished before reveal could attach");
      return { ok: true, nullifier };
    },

    async results(pollId): Promise<Result<{ view: ResultView }>> {
      const poll = await loadPoll(pollId);
      if ("ok" in poll) return poll;
      const qt = lookup(poll);
      const votes = await cfg.voteStore.list(pollId);
      const distinct = await cfg.voteStore.count(pollId);
      const tally = qt.tally(poll.config, votes);
      const view = qt.resultView(poll.config, tally);
      return { ok: true, view: { ...view, credibility: credibility(poll, distinct) } };
    },

    async resolve(pollId): Promise<Result<{ view: ResultView }>> {
      const poll = await loadPoll(pollId);
      if ("ok" in poll) return poll;
      if (poll.lifecycle !== "closed") {
        return err("wrong-lifecycle", `poll is "${poll.lifecycle}"; resolve requires "closed"`);
      }
      const qt = lookup(poll);
      const votes = await cfg.voteStore.list(pollId);
      const distinct = await cfg.voteStore.count(pollId);

      // Raffle resolves through the async, seeded, verifiable draw (the sync
      // QuestionType.resolve fails closed for raffle by design).
      let resolved;
      if (poll.questionType === "raffle") {
        resolved = await drawWinner(
          poll.config as RaffleConfig,
          votes as StoredVote<RaffleVote>[],
        );
      } else {
        resolved = qt.resolve(poll.config, votes);
      }
      if (!resolved.ok) return resolved;

      const view = qt.resultView(poll.config, resolved.tally);
      await cfg.pollStore.setLifecycle(pollId, "resolved");
      return { ok: true, view: { ...view, credibility: credibility(poll, distinct) } };
    },
  };
}
