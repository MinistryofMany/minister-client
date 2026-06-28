import { describe, it, expect } from "vitest";
import { singleChoice } from "./single-choice.js";
import type { StoredVote } from "../types.js";
import type { SingleChoiceVote } from "./single-choice.js";

const config = { options: ["red", "green", "blue"] };

function votes(opts: string[]): StoredVote<SingleChoiceVote>[] {
  return opts.map((option, i) => ({ nullifier: String(i + 1), vote: { option } }));
}

describe("single-choice validateVote", () => {
  it("accepts an in-set option", () => {
    expect(singleChoice.validateVote(config, { option: "red" })).toEqual({
      ok: true,
      vote: { option: "red" },
    });
  });
  it("rejects an out-of-set option", () => {
    expect(singleChoice.validateVote(config, { option: "purple" })).toMatchObject({
      ok: false,
      code: "invalid-vote",
    });
  });
  it("rejects a malformed payload", () => {
    expect(singleChoice.validateVote(config, { choice: "red" })).toMatchObject({ ok: false });
    expect(singleChoice.validateVote(config, "red")).toMatchObject({ ok: false });
    expect(singleChoice.validateVote(config, { option: "red", extra: 1 })).toMatchObject({
      ok: false,
    });
  });
});

describe("single-choice tally + resultView", () => {
  it("counts per option and computes fractions", () => {
    const t = singleChoice.tally(config, votes(["red", "red", "green"]));
    expect(t).toEqual({ counts: { red: 2, green: 1, blue: 0 }, total: 3 });
    const view = singleChoice.resultView(config, t);
    expect(view.kind).toBe("bar");
    expect(view.totalVotes).toBe(3);
    expect(view.options.find((o) => o.option === "red")).toEqual({
      option: "red",
      votes: 2,
      fraction: 2 / 3,
    });
    expect(view.options.find((o) => o.option === "blue")).toEqual({
      option: "blue",
      votes: 0,
      fraction: 0,
    });
  });
  it("handles an empty poll without NaN", () => {
    const view = singleChoice.resultView(config, singleChoice.tally(config, []));
    expect(view.options.every((o) => o.fraction === 0 && o.votes === 0)).toBe(true);
  });
});

describe("single-choice resolve", () => {
  it("resolve equals tally", () => {
    const r = singleChoice.resolve(config, votes(["green", "blue"]));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally).toEqual(singleChoice.tally(config, votes(["green", "blue"])));
  });
});
