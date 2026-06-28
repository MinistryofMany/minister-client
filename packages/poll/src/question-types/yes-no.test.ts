import { describe, it, expect } from "vitest";
import { yesNo, thresholdFor, type YesNoChoice, type YesNoVote } from "./yes-no.js";
import type { StoredVote } from "../types.js";

function votes(choices: YesNoChoice[]): StoredVote<YesNoVote>[] {
  return choices.map((choice, i) => ({ nullifier: String(i + 1), vote: { choice } }));
}

describe("threshold math == FreedInk ceil(eligible * num / den)", () => {
  // Golden vectors computed directly from the FreedInk formula
  // threshold = Math.ceil((eligible * num) / den).
  const cases: Array<[number, number, number, number]> = [
    // [eligible, num, den, expected]
    [10, 2, 3, 7], // ceil(20/3) = ceil(6.67) = 7
    [9, 2, 3, 6], // ceil(18/3) = 6
    [1, 2, 3, 1], // ceil(2/3) = 1
    [0, 2, 3, 0], // ceil(0) = 0
    [100, 1, 2, 50], // simple majority
    [3, 1, 1, 3], // unanimity
    [7, 3, 4, 6], // ceil(21/4) = ceil(5.25) = 6
    [11, 2, 3, 8], // ceil(22/3) = ceil(7.33) = 8
  ];
  it.each(cases)("eligible=%i num=%i den=%i -> %i", (eligible, num, den, expected) => {
    expect(thresholdFor(eligible, num, den)).toBe(expected);
    // And it matches a fresh evaluation of the literal FreedInk expression.
    expect(thresholdFor(eligible, num, den)).toBe(Math.ceil((eligible * num) / den));
  });
});

describe("yes-no validateVote", () => {
  it("accepts yes / no", () => {
    expect(yesNo.validateVote({ eligible: 3 }, { choice: "yes" })).toMatchObject({ ok: true });
    expect(yesNo.validateVote({ eligible: 3 }, { choice: "no" })).toMatchObject({ ok: true });
  });
  it("rejects abstain unless allowed", () => {
    expect(yesNo.validateVote({ eligible: 3 }, { choice: "abstain" })).toMatchObject({
      ok: false,
      code: "invalid-vote",
    });
    expect(
      yesNo.validateVote({ eligible: 3, allowAbstain: true }, { choice: "abstain" }),
    ).toMatchObject({ ok: true });
  });
  it("rejects garbage", () => {
    expect(yesNo.validateVote({ eligible: 3 }, { choice: "maybe" })).toMatchObject({ ok: false });
  });
});

describe("yes-no supermajority outcome (default 2/3)", () => {
  it("passes when yes reaches the 2/3 bar", () => {
    // eligible 9 -> threshold ceil(18/3) = 6.
    const v = yesNo.resultView({ eligible: 9 }, yesNo.tally({ eligible: 9 }, votes(Array(6).fill("yes"))));
    expect(v.threshold).toBe(6);
    expect(v.numerator).toBe(2);
    expect(v.denominator).toBe(3);
    expect(v.outcome).toBe("passed");
  });
  it("stays undecided below the bar", () => {
    const v = yesNo.resultView({ eligible: 9 }, yesNo.tally({ eligible: 9 }, votes(Array(5).fill("yes"))));
    expect(v.outcome).toBe("undecided");
  });
  it("fails when no reaches the bar", () => {
    const v = yesNo.resultView({ eligible: 9 }, yesNo.tally({ eligible: 9 }, votes(Array(6).fill("no"))));
    expect(v.outcome).toBe("failed");
  });
  it("respects a configurable numerator/denominator", () => {
    // simple majority 1/2 of eligible 10 -> threshold ceil(10/2) = 5.
    const cfg = { eligible: 10, numerator: 1, denominator: 2 };
    const v = yesNo.resultView(cfg, yesNo.tally(cfg, votes(Array(5).fill("yes"))));
    expect(v.threshold).toBe(5);
    expect(v.outcome).toBe("passed");
  });
});

describe("yes-no optional quorum (turnout floor)", () => {
  it("blocks a pass when turnout is below the quorum floor", () => {
    // eligible 12, super 1/2 -> threshold 6. quorum 3/4 -> floor ceil(36/4)=9.
    // 6 yes + 0 no = 6 counted < 9 floor: quorum not met, so not passed.
    const cfg = { eligible: 12, numerator: 1, denominator: 2, quorum: { num: 3, den: 4 } };
    const v = yesNo.resultView(cfg, yesNo.tally(cfg, votes(Array(6).fill("yes"))));
    expect(v.threshold).toBe(6);
    expect(v.quorumMet).toBe(false);
    expect(v.outcome).toBe("undecided");
  });
  it("passes once both the supermajority and quorum are met", () => {
    const cfg = { eligible: 12, numerator: 1, denominator: 2, quorum: { num: 3, den: 4 } };
    // 9 yes -> 9 counted >= 9 floor AND yes(9) >= threshold(6) -> passed.
    const v = yesNo.resultView(cfg, yesNo.tally(cfg, votes(Array(9).fill("yes"))));
    expect(v.quorumMet).toBe(true);
    expect(v.outcome).toBe("passed");
  });
});

describe("yes-no resolve", () => {
  it("resolve tally matches running tally", () => {
    const cfg = { eligible: 5 };
    const r = yesNo.resolve(cfg, votes(["yes", "no", "yes"]));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally).toEqual({ yes: 2, no: 1, abstain: 0 });
  });
});
