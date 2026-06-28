import { describe, it, expect } from "vitest";
import { createPollEngine, type PollEngine } from "./engine.js";
import { MemoryPollStore, MemoryVoteStore } from "./test-stores.js";
import { buildCommit } from "./question-types/commit-reveal.js";
import { seedCommitHash } from "./hash.js";
import type { VoterHandle } from "./types.js";

const sub = (s: string): VoterHandle => ({ kind: "subject", subject: s });

function engine(): PollEngine {
  return createPollEngine({
    pollStore: new MemoryPollStore(),
    voteStore: new MemoryVoteStore(),
  });
}

describe("lifecycle enforcement", () => {
  it("rejects an illegal transition and casting outside open", async () => {
    const e = engine();
    await e.create({
      id: "p",
      questionType: "single-choice",
      audienceGate: { open: true },
      config: { options: ["a", "b"] },
    });
    // draft -> resolved is illegal.
    expect(await e.transition("p", "resolved")).toMatchObject({ ok: false, code: "wrong-lifecycle" });
    // cast on a draft poll is rejected.
    expect(await e.cast("p", sub("a"), { option: "a" })).toMatchObject({
      ok: false,
      code: "wrong-lifecycle",
    });
    // Legal path: draft -> open -> closed -> resolved.
    expect((await e.transition("p", "open")).ok).toBe(true);
    expect((await e.cast("p", sub("a"), { option: "a" })).ok).toBe(true);
    expect((await e.transition("p", "closed")).ok).toBe(true);
    // cast after close is rejected.
    expect(await e.cast("p", sub("b"), { option: "b" })).toMatchObject({
      ok: false,
      code: "wrong-lifecycle",
    });
    expect((await e.resolve("p")).ok).toBe(true);
  });

  it("rejects an unknown question type at create", async () => {
    const e = engine();
    expect(
      await e.create({ id: "p", questionType: "nope", audienceGate: { open: true }, config: {} }),
    ).toMatchObject({ ok: false, code: "invalid-vote" });
  });

  it("surfaces the audience gate (pool) + distinct voter count in the view", async () => {
    const e = engine();
    const gate = { open: false as const, policy: { badge: { type: "email-domain", where: { domain: "acme.test" } } } };
    await e.create({ id: "p", questionType: "single-choice", audienceGate: gate, config: { options: ["a"] } });
    await e.transition("p", "open");
    await e.cast("p", sub("alice"), { option: "a" });
    const res = await e.results("p");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.view.credibility.distinctVoters).toBe(1);
      expect(res.view.credibility.pool).toEqual(gate);
    }
  });
});

describe("commit-reveal end-to-end through the engine", () => {
  async function setup() {
    const e = engine();
    await e.create({
      id: "cr",
      questionType: "commit-reveal",
      audienceGate: { open: true },
      config: { options: ["yes", "no"] },
    });
    await e.transition("cr", "open");
    return e;
  }

  it("commits during open, reveals during closed, resolves to the revealed tally", async () => {
    const e = await setup();
    const alice = sub("alice");
    const bob = sub("bob");

    const aCommit = await buildCommit("yes", "alice-salt");
    const bCommit = await buildCommit("no", "bob-salt");
    expect((await e.cast("cr", alice, aCommit)).ok).toBe(true);
    expect((await e.cast("cr", bob, bCommit)).ok).toBe(true);

    // Reveal is not allowed while still open.
    expect(await e.reveal("cr", alice, { choice: "yes", salt: "alice-salt" })).toMatchObject({
      ok: false,
      code: "wrong-lifecycle",
    });

    await e.transition("cr", "closed");

    expect((await e.reveal("cr", alice, { choice: "yes", salt: "alice-salt" })).ok).toBe(true);
    expect((await e.reveal("cr", bob, { choice: "no", salt: "bob-salt" })).ok).toBe(true);

    const resolved = await e.resolve("cr");
    expect(resolved.ok).toBe(true);
    if (resolved.ok && resolved.view.kind === "bar") {
      expect(resolved.view.totalVotes).toBe(2);
      expect(resolved.view.options.find((o) => o.option === "yes")?.votes).toBe(1);
      expect(resolved.view.options.find((o) => o.option === "no")?.votes).toBe(1);
    }
  });

  it("a voter cannot change their choice after committing (reveal must match commit)", async () => {
    const e = await setup();
    const alice = sub("alice");
    const aCommit = await buildCommit("yes", "alice-salt");
    expect((await e.cast("cr", alice, aCommit)).ok).toBe(true);
    await e.transition("cr", "closed");

    // Try to reveal a different choice than committed -> rejected.
    expect(await e.reveal("cr", alice, { choice: "no", salt: "alice-salt" })).toMatchObject({
      ok: false,
      code: "reveal-mismatch",
    });
    // Try to reveal with a different salt -> rejected.
    expect(await e.reveal("cr", alice, { choice: "yes", salt: "other" })).toMatchObject({
      ok: false,
      code: "reveal-mismatch",
    });
    // Honest reveal still works and an un-revealed/wrong reveal contributed nothing.
    expect((await e.reveal("cr", alice, { choice: "yes", salt: "alice-salt" })).ok).toBe(true);
  });

  it("a voter cannot commit twice (one sealed vote per member)", async () => {
    const e = await setup();
    const alice = sub("alice");
    expect((await e.cast("cr", alice, await buildCommit("yes", "s1"))).ok).toBe(true);
    // Second commit (even a different sealed choice) is the one-vote guard.
    expect(await e.cast("cr", alice, await buildCommit("no", "s2"))).toMatchObject({
      ok: false,
      code: "already-voted",
    });
  });

  it("a reveal from a member who never committed is rejected", async () => {
    const e = await setup();
    await e.transition("cr", "closed");
    expect(await e.reveal("cr", sub("ghost"), { choice: "yes", salt: "x" })).toMatchObject({
      ok: false,
      code: "no-commit",
    });
  });

  it("resolve ignores un-revealed commits", async () => {
    const e = await setup();
    const alice = sub("alice");
    const bob = sub("bob");
    await e.cast("cr", alice, await buildCommit("yes", "as"));
    await e.cast("cr", bob, await buildCommit("yes", "bs"));
    await e.transition("cr", "closed");
    // Only alice reveals.
    await e.reveal("cr", alice, { choice: "yes", salt: "as" });
    const resolved = await e.resolve("cr");
    if (resolved.ok && resolved.view.kind === "bar") {
      expect(resolved.view.totalVotes).toBe(1); // bob's sealed commit does not count
      // But the credibility surface still shows 2 distinct verified voters cast.
      expect(resolved.view.credibility.distinctVoters).toBe(2);
    }
  });
});

describe("raffle resolve through the engine", () => {
  it("draws a verifiable winner from the configured public seed", async () => {
    const e = engine();
    await e.create({
      id: "r",
      questionType: "raffle",
      audienceGate: { open: true },
      config: { seed: "drand-round-12345" },
    });
    await e.transition("r", "open");
    for (const name of ["alice", "bob", "carol", "dave"]) {
      expect((await e.cast("r", sub(name), {})).ok).toBe(true);
    }
    await e.transition("r", "closed");
    const resolved = await e.resolve("r");
    expect(resolved.ok).toBe(true);
    if (resolved.ok && resolved.view.kind === "winner") {
      expect(resolved.view.entrants).toBe(4);
      expect(resolved.view.seed).toBe("drand-round-12345");
      expect(resolved.view.winner).not.toBeNull();
    }
  });

  it("a raffle with no seed fails closed at resolve", async () => {
    const e = engine();
    await e.create({ id: "r2", questionType: "raffle", audienceGate: { open: true }, config: {} });
    await e.transition("r2", "open");
    await e.cast("r2", sub("alice"), {});
    await e.transition("r2", "closed");
    expect(await e.resolve("r2")).toMatchObject({ ok: false, code: "not-resolvable" });
  });

  it("commits a seed-hash at create and reveals the preimage at resolve", async () => {
    const e = engine();
    const preimage = "drand:round:2026-06-28";
    const seedCommit = await seedCommitHash(preimage);
    await e.create({
      id: "r3",
      questionType: "raffle",
      audienceGate: { open: true },
      config: { seedCommit },
    });
    await e.transition("r3", "open");
    for (const name of ["alice", "bob", "carol", "dave"]) {
      expect((await e.cast("r3", sub(name), {})).ok).toBe(true);
    }
    await e.transition("r3", "closed");

    // Without the revealed seed, resolve fails closed (the seed lives nowhere yet).
    expect(await e.resolve("r3")).toMatchObject({ ok: false, code: "not-resolvable" });

    // The revealed preimage drives a verifiable draw.
    const resolved = await e.resolve("r3", { seed: preimage });
    expect(resolved.ok).toBe(true);
    if (resolved.ok && resolved.view.kind === "winner") {
      expect(resolved.view.seed).toBe(preimage);
      expect(resolved.view.entrants).toBe(4);
      expect(resolved.view.winner).not.toBeNull();
    }
  });

  it("rejects a wrong revealed preimage against the committed seed-hash", async () => {
    const e = engine();
    const seedCommit = await seedCommitHash("the-real-one");
    await e.create({
      id: "r4",
      questionType: "raffle",
      audienceGate: { open: true },
      config: { seedCommit },
    });
    await e.transition("r4", "open");
    await e.cast("r4", sub("alice"), {});
    await e.transition("r4", "closed");
    expect(await e.resolve("r4", { seed: "a-grinding-attempt" })).toMatchObject({
      ok: false,
      code: "not-resolvable",
    });
  });
});
