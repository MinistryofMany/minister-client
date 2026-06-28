import { describe, it, expect } from "vitest";
import { createPollEngine } from "./engine.js";
import { deriveVoteNullifier } from "./cast.js";
import { MemoryPollStore, MemoryVoteStore } from "./test-stores.js";
import type { VoterHandle } from "./types.js";

function engine() {
  return createPollEngine({
    pollStore: new MemoryPollStore(),
    voteStore: new MemoryVoteStore(),
  });
}

const sub = (s: string): VoterHandle => ({ kind: "subject", subject: s });
const mem = (n: string): VoterHandle => ({ kind: "membership", membershipNullifier: n });

describe("per-(poll, member) nullifier derivation", () => {
  it("is deterministic for the same handle + poll", () => {
    const h = sub("alice");
    expect(deriveVoteNullifier(h, "poll-1")).toBe(deriveVoteNullifier(h, "poll-1"));
  });

  it("differs across polls for the same member (cross-poll unlinkability)", () => {
    const h = sub("alice");
    expect(deriveVoteNullifier(h, "poll-1")).not.toBe(deriveVoteNullifier(h, "poll-2"));
  });

  it("differs across members in the same poll", () => {
    expect(deriveVoteNullifier(sub("alice"), "poll-1")).not.toBe(
      deriveVoteNullifier(sub("bob"), "poll-1"),
    );
  });

  it("works for a membership handle and is poll-scoped too", () => {
    const h = mem("12345678901234567890");
    expect(deriveVoteNullifier(h, "poll-1")).toBe(deriveVoteNullifier(h, "poll-1"));
    expect(deriveVoteNullifier(h, "poll-1")).not.toBe(deriveVoteNullifier(h, "poll-2"));
  });

  it("returns a decimal field-element string", () => {
    const v = deriveVoteNullifier(sub("alice"), "poll-1");
    expect(v).toMatch(/^[0-9]+$/);
    expect(BigInt(v)).toBeGreaterThan(0n);
  });
});

describe("unstuffability: one vote per member", () => {
  it("rejects a second cast from the same member", async () => {
    const e = engine();
    await e.create({
      id: "p",
      questionType: "single-choice",
      audienceGate: { open: true },
      config: { options: ["a", "b"] },
    });
    await e.transition("p", "open");

    const first = await e.cast("p", sub("alice"), { option: "a" });
    expect(first.ok).toBe(true);

    // Same member, even a different choice, must be rejected.
    const second = await e.cast("p", sub("alice"), { option: "b" });
    expect(second).toMatchObject({ ok: false, code: "already-voted" });

    // The first vote stands; the tally shows exactly one voter.
    const res = await e.results("p");
    expect(res.ok).toBe(true);
    if (res.ok && res.view.kind === "bar") {
      expect(res.view.totalVotes).toBe(1);
      expect(res.view.credibility.distinctVoters).toBe(1);
      expect(res.view.options.find((o) => o.option === "a")?.votes).toBe(1);
      expect(res.view.options.find((o) => o.option === "b")?.votes).toBe(0);
    }
  });

  it("counts distinct members independently", async () => {
    const e = engine();
    await e.create({
      id: "p",
      questionType: "single-choice",
      audienceGate: { open: true },
      config: { options: ["a", "b"] },
    });
    await e.transition("p", "open");
    expect((await e.cast("p", sub("alice"), { option: "a" })).ok).toBe(true);
    expect((await e.cast("p", sub("bob"), { option: "a" })).ok).toBe(true);
    const res = await e.results("p");
    if (res.ok && res.view.kind === "bar") {
      expect(res.view.credibility.distinctVoters).toBe(2);
      expect(res.view.totalVotes).toBe(2);
    }
  });
});

describe("unstuffability: no cross-poll replay", () => {
  it("a nullifier lifted from poll A cannot be replayed as poll B's honest vote", async () => {
    const pollStore = new MemoryPollStore();
    const voteStore = new MemoryVoteStore();
    const e = createPollEngine({ pollStore, voteStore });

    for (const id of ["A", "B"]) {
      await e.create({
        id,
        questionType: "single-choice",
        audienceGate: { open: true },
        config: { options: ["a", "b"] },
      });
      await e.transition(id, "open");
    }

    const alice = sub("alice");
    const castA = await e.cast("A", alice, { option: "a" });
    expect(castA.ok).toBe(true);
    const nullifierA = castA.ok ? castA.nullifier : "";

    // 1) An attacker who lifts poll A's raw nullifier and tries to write it under
    //    poll B succeeds as a FRESH row in B's namespace - but it is NOT Alice's
    //    poll-B nullifier, so it cannot displace or impersonate her real vote.
    const aliceNullifierB = deriveVoteNullifier(alice, "B");
    expect(nullifierA).not.toBe(aliceNullifierB);

    // 2) Alice's honest vote in B uses her poll-B nullifier and is accepted.
    const castB = await e.cast("B", alice, { option: "b" });
    expect(castB.ok).toBe(true);
    expect(castB.ok && castB.nullifier).toBe(aliceNullifierB);

    // 3) A direct attempt to reuse poll A's nullifier value AS poll A again is a
    //    replay (the one-vote guard), proving the UNIQUE(pollId, nullifier) key.
    const replayA = await voteStore.castOnce("A", {
      nullifier: nullifierA,
      vote: { option: "b" },
    });
    expect(replayA).toEqual({ status: "replay" });
  });

  it("the VoteStore UNIQUE key is scoped per poll (same nullifier, different poll = fresh)", async () => {
    const voteStore = new MemoryVoteStore();
    const fresh1 = await voteStore.castOnce("A", { nullifier: "999", vote: { x: 1 } });
    const fresh2 = await voteStore.castOnce("B", { nullifier: "999", vote: { x: 1 } });
    const replay = await voteStore.castOnce("A", { nullifier: "999", vote: { x: 2 } });
    expect(fresh1).toEqual({ status: "fresh" });
    expect(fresh2).toEqual({ status: "fresh" });
    expect(replay).toEqual({ status: "replay" });
  });
});
