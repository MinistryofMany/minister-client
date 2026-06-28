import { describe, it, expect } from "vitest";
import { verdict, type VerdictChoice, type VerdictVote } from "./verdict.js";
import type { StoredVote } from "../types.js";

const config = {};

function votes(choices: VerdictChoice[]): StoredVote<VerdictVote>[] {
  return choices.map((choice, i) => ({ nullifier: String(i + 1), vote: { choice } }));
}

describe("verdict validateVote", () => {
  it("accepts accept / reject", () => {
    expect(verdict.validateVote(config, { choice: "accept" })).toMatchObject({ ok: true });
    expect(verdict.validateVote(config, { choice: "reject" })).toMatchObject({ ok: true });
  });
  it("rejects anything else", () => {
    expect(verdict.validateVote(config, { choice: "maybe" })).toMatchObject({ ok: false });
    expect(verdict.validateVote(config, {})).toMatchObject({ ok: false });
  });
});

describe("verdict tally + outcome", () => {
  it("accepted on a majority accept", () => {
    const v = verdict.resultView(config, verdict.tally(config, votes(["accept", "accept", "reject"])));
    expect(v).toMatchObject({ kind: "verdict", accept: 2, reject: 1, outcome: "accepted" });
  });
  it("rejected on a majority reject", () => {
    const v = verdict.resultView(config, verdict.tally(config, votes(["reject", "reject", "accept"])));
    expect(v.outcome).toBe("rejected");
  });
  it("tied on equal counts", () => {
    const v = verdict.resultView(config, verdict.tally(config, votes(["accept", "reject"])));
    expect(v.outcome).toBe("tied");
  });
  it("tied (0-0) on no votes", () => {
    const v = verdict.resultView(config, verdict.tally(config, []));
    expect(v.outcome).toBe("tied");
  });
});

describe("verdict resolve", () => {
  it("resolve matches tally", () => {
    const r = verdict.resolve(config, votes(["accept"]));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally).toEqual({ accept: 1, reject: 0 });
  });
});
