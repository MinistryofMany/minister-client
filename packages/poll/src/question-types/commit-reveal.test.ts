import { describe, it, expect } from "vitest";
import {
  commitReveal,
  buildCommit,
  verifyReveal,
  type CommitRevealVote,
} from "./commit-reveal.js";
import { commitHash } from "../hash.js";
import type { StoredVote } from "../types.js";

const config = { options: ["yes", "no"] };

describe("commit hash binding", () => {
  it("is deterministic and order/field-separated", async () => {
    const h1 = await commitHash("yes", "salt-1");
    const h2 = await commitHash("yes", "salt-1");
    expect(h1).toBe(h2);
    // Different salt -> different commit.
    expect(await commitHash("yes", "salt-2")).not.toBe(h1);
    // Different choice -> different commit.
    expect(await commitHash("no", "salt-1")).not.toBe(h1);
    // Field separation: ("ab","c") must not equal ("a","bc").
    expect(await commitHash("ab", "c")).not.toBe(await commitHash("a", "bc"));
  });
});

describe("verifyReveal binding (cannot reveal a different value than committed)", () => {
  it("accepts the exact (choice, salt) that produced the commit", async () => {
    const { commit } = await buildCommit("yes", "s3cret");
    const r = await verifyReveal(config, commit, { choice: "yes", salt: "s3cret" });
    expect(r).toMatchObject({ ok: true, choice: "yes", salt: "s3cret" });
  });
  it("rejects a different choice (same salt)", async () => {
    const { commit } = await buildCommit("yes", "s3cret");
    const r = await verifyReveal(config, commit, { choice: "no", salt: "s3cret" });
    expect(r).toMatchObject({ ok: false, code: "reveal-mismatch" });
  });
  it("rejects a different salt (same choice)", async () => {
    const { commit } = await buildCommit("yes", "s3cret");
    const r = await verifyReveal(config, commit, { choice: "yes", salt: "wrong" });
    expect(r).toMatchObject({ ok: false, code: "reveal-mismatch" });
  });
  it("rejects a revealed choice outside the option set", async () => {
    const { commit } = await buildCommit("maybe", "s");
    const r = await verifyReveal(config, commit, { choice: "maybe", salt: "s" });
    expect(r).toMatchObject({ ok: false, code: "invalid-vote" });
  });
});

describe("commit-reveal validateVote (commit phase)", () => {
  it("accepts a { commit } payload and stores only the hash", () => {
    const r = commitReveal.validateVote(config, { commit: "abc123" });
    expect(r).toMatchObject({ ok: true, vote: { commit: "abc123" } });
    if (r.ok) expect(r.vote.revealed).toBeUndefined();
  });
  it("rejects a payload that leaks the choice at commit time", () => {
    expect(commitReveal.validateVote(config, { choice: "yes", salt: "s" })).toMatchObject({
      ok: false,
    });
  });
});

describe("commit-reveal tally counts only revealed-and-matching votes", () => {
  function row(commit: string, revealed?: { choice: string; salt: string }): StoredVote<CommitRevealVote> {
    return { nullifier: commit, vote: { commit, revealed } };
  }
  it("ignores un-revealed commits", () => {
    const t = commitReveal.tally(config, [
      row("c1", { choice: "yes", salt: "a" }),
      row("c2"), // never revealed
      row("c3", { choice: "no", salt: "b" }),
    ]);
    expect(t.committed).toBe(3);
    expect(t.revealed).toBe(2);
    expect(t.counts).toEqual({ yes: 1, no: 1 });
  });
  it("resultView fractions are over revealed votes only", () => {
    const t = commitReveal.tally(config, [
      row("c1", { choice: "yes", salt: "a" }),
      row("c2", { choice: "yes", salt: "b" }),
      row("c3"), // unrevealed
    ]);
    const view = commitReveal.resultView(config, t);
    expect(view.totalVotes).toBe(2);
    expect(view.options.find((o) => o.option === "yes")?.fraction).toBe(1);
  });
});
