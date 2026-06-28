import { describe, it, expect } from "vitest";
import { ranked, runIrv, type RankedVote } from "./ranked.js";
import type { StoredVote } from "../types.js";

const config = { candidates: ["A", "B", "C"] };

function votes(ballots: string[][]): StoredVote<RankedVote>[] {
  return ballots.map((ranking, i) => ({ nullifier: String(i + 1), vote: { ranking } }));
}

describe("ranked validateVote", () => {
  it("accepts a full or partial ranking of valid candidates", () => {
    expect(ranked.validateVote(config, { ranking: ["A", "B", "C"] })).toMatchObject({ ok: true });
    expect(ranked.validateVote(config, { ranking: ["B"] })).toMatchObject({ ok: true });
  });
  it("rejects an unknown candidate", () => {
    expect(ranked.validateVote(config, { ranking: ["A", "Z"] })).toMatchObject({
      ok: false,
      code: "invalid-vote",
    });
  });
  it("rejects a duplicate ranking", () => {
    expect(ranked.validateVote(config, { ranking: ["A", "A"] })).toMatchObject({ ok: false });
  });
  it("rejects an empty ranking", () => {
    expect(ranked.validateVote(config, { ranking: [] })).toMatchObject({ ok: false });
  });
});

describe("IRV first-round majority", () => {
  it("declares a candidate with > 50% of first prefs immediately", () => {
    const t = runIrv(config.candidates, [["A"], ["A"], ["A"], ["B"], ["C"]]);
    // A has 3/5 = 60% in round 1 -> wins, no elimination.
    expect(t.winner).toBe("A");
    expect(t.rounds).toHaveLength(1);
    expect(t.rounds[0]!.eliminated).toBeNull();
  });
});

describe("IRV elimination + transfer", () => {
  it("eliminates the lowest and transfers to the next preference", () => {
    // Round 1: A=2, B=2, C=1 (no majority of 5). Eliminate C (lowest).
    // C's single ballot ["C","A"] transfers to A. Round 2: A=3, B=2 -> A wins.
    const t = runIrv(config.candidates, [
      ["A", "B"],
      ["A", "B"],
      ["B", "A"],
      ["B", "A"],
      ["C", "A"],
    ]);
    expect(t.rounds[0]!.eliminated).toBe("C");
    expect(t.winner).toBe("A");
    // Standings: winner first, then survivor B, then eliminated C.
    expect(t.standings[0]!.candidate).toBe("A");
    expect(t.standings.find((s) => s.candidate === "C")?.eliminatedInRound).toBe(1);
  });
});

describe("IRV tie-break by config order", () => {
  it("eliminates the config-earlier candidate on a low-count tie", () => {
    // Round 1: A=1, B=1, C=3. No majority? C has 3/5=60% -> C actually wins.
    // Use a setup with a genuine low tie and no first-round majority:
    // A=2, B=2, C=2 across 6 ballots; eliminate A (config-earliest) on the tie.
    const t = runIrv(["A", "B", "C"], [
      ["A", "B"],
      ["A", "B"],
      ["B", "C"],
      ["B", "C"],
      ["C", "A"],
      ["C", "A"],
    ]);
    // First elimination is the config-earliest among the tied lowest (all tie at 2),
    // which is A. A's ballots transfer to B. Round 2: B=4, C=2 -> B wins.
    expect(t.rounds[0]!.eliminated).toBe("A");
    expect(t.winner).toBe("B");
  });
});

describe("IRV edge cases", () => {
  it("returns winner null for zero ballots", () => {
    const t = runIrv(config.candidates, []);
    expect(t.winner).toBeNull();
    expect(t.rounds).toEqual([]);
  });
  it("single candidate wins", () => {
    const t = runIrv(["A"], [["A"], ["A"]]);
    expect(t.winner).toBe("A");
  });
});

describe("ranked resultView + resolve", () => {
  it("renders standings + rounds and resolve matches tally", () => {
    const v = votes([["A"], ["A"], ["B"]]);
    const view = ranked.resultView(config, ranked.tally(config, v));
    expect(view.kind).toBe("ranked");
    expect(view.winner).toBe("A");
    expect(view.rounds.length).toBeGreaterThanOrEqual(1);
    const r = ranked.resolve(config, v);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally.winner).toBe("A");
  });
});
