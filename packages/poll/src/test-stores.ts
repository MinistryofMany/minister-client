// In-memory PollStore / VoteStore for tests. The VoteStore is the reference
// implementation of the unstuffability guard: a Map keyed on `${pollId}|${nullifier}`
// is the in-memory analogue of a UNIQUE(pollId, nullifier) index, and castOnce is
// insert-or-reject against it. Atomicity is trivial in a single-threaded test, but
// the contract a real (SQL) store must meet is the same: a second insert of the
// same key returns "replay" and writes nothing.

import type { FieldString } from "@minister/membership";
import type { PollStore, VoteStore, CastOutcome } from "./store.js";
import type { Poll, StoredVote } from "./types.js";

export class MemoryPollStore implements PollStore {
  private polls = new Map<string, Poll>();

  async get(pollId: string): Promise<Poll | null> {
    return this.polls.get(pollId) ?? null;
  }
  async create(poll: Poll): Promise<void> {
    if (this.polls.has(poll.id)) throw new Error(`poll ${poll.id} already exists`);
    this.polls.set(poll.id, { ...poll });
  }
  async setLifecycle(pollId: string, lifecycle: Poll["lifecycle"]): Promise<void> {
    const p = this.polls.get(pollId);
    if (!p) throw new Error(`poll ${pollId} not found`);
    this.polls.set(pollId, { ...p, lifecycle });
  }
}

export class MemoryVoteStore<T = unknown> implements VoteStore<T> {
  // key = `${pollId}|${nullifier}` -> the stored vote. This is the UNIQUE index.
  private byKey = new Map<string, StoredVote<T>>();
  private byPoll = new Map<string, Set<string>>();

  private key(pollId: string, nullifier: string): string {
    return `${pollId}|${nullifier}`;
  }

  async castOnce(pollId: string, vote: StoredVote<T>): Promise<CastOutcome> {
    const k = this.key(pollId, vote.nullifier);
    if (this.byKey.has(k)) return { status: "replay" };
    this.byKey.set(k, { ...vote });
    let set = this.byPoll.get(pollId);
    if (!set) {
      set = new Set<string>();
      this.byPoll.set(pollId, set);
    }
    set.add(vote.nullifier);
    return { status: "fresh" };
  }

  async list(pollId: string): Promise<StoredVote<T>[]> {
    const set = this.byPoll.get(pollId);
    if (!set) return [];
    const out: StoredVote<T>[] = [];
    for (const nullifier of set) {
      const v = this.byKey.get(this.key(pollId, nullifier));
      if (v) out.push(v);
    }
    return out;
  }

  async count(pollId: string): Promise<number> {
    return this.byPoll.get(pollId)?.size ?? 0;
  }

  async update(pollId: string, nullifier: FieldString, vote: T): Promise<boolean> {
    const k = this.key(pollId, nullifier);
    const existing = this.byKey.get(k);
    if (!existing) return false;
    this.byKey.set(k, { nullifier, vote });
    return true;
  }
}
