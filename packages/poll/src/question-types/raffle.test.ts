import { describe, it, expect } from "vitest";
import { raffle, drawWinner, sortedEntrants, type RaffleVote } from "./raffle.js";
import { uniformIndex } from "../hash.js";
import type { StoredVote } from "../types.js";

function entrants(nullifiers: string[]): StoredVote<RaffleVote>[] {
  return nullifiers.map((nullifier) => ({ nullifier, vote: {} }));
}

describe("raffle validateVote", () => {
  it("accepts an empty entry", () => {
    expect(raffle.validateVote({}, {})).toMatchObject({ ok: true });
    expect(raffle.validateVote({}, undefined)).toMatchObject({ ok: true });
  });
  it("rejects a payload (no smuggled fields)", () => {
    expect(raffle.validateVote({}, { rig: true })).toMatchObject({ ok: false });
  });
});

describe("raffle entrant ordering is canonical (numeric ascending)", () => {
  it("sorts regardless of input order", () => {
    const a = sortedEntrants(entrants(["100", "20", "3"]));
    const b = sortedEntrants(entrants(["3", "100", "20"]));
    expect(a).toEqual(["3", "20", "100"]);
    expect(a).toEqual(b);
  });
});

describe("raffle draw is deterministic from the public seed", () => {
  it("same seed + entrants => same winner (anyone can recompute)", async () => {
    const e = entrants(["3", "20", "100", "7"]);
    const r1 = await drawWinner({ seed: "beacon-2026-06-28" }, e);
    const r2 = await drawWinner({ seed: "beacon-2026-06-28" }, e);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    if (r1.ok && r2.ok) {
      expect(r1.tally.winner).toBe(r2.tally.winner);
      expect(r1.tally.seed).toBe("beacon-2026-06-28");
      // The winner is one of the entrants.
      expect(r1.tally.entrants).toContain(r1.tally.winner);
    }
  });
  it("the winner equals the entrant at uniformIndex(seed, n) over the sorted set", async () => {
    const e = entrants(["3", "20", "100", "7"]);
    const sorted = sortedEntrants(e); // ["3","7","20","100"]
    const idx = await uniformIndex("beacon-2026-06-28", sorted.length);
    const r = await drawWinner({ seed: "beacon-2026-06-28" }, e);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.tally.winner).toBe(sorted[idx]);
  });
  it("a different seed can change the winner", async () => {
    const e = entrants(["3", "20", "100", "7", "9", "11", "13", "17"]);
    const winners = new Set<string | null>();
    for (const seed of ["s-a", "s-b", "s-c", "s-d", "s-e", "s-f"]) {
      const r = await drawWinner({ seed }, e);
      if (r.ok) winners.add(r.tally.winner);
    }
    // Across several seeds we expect more than one distinct winner (the draw is
    // not pinned to a single entrant).
    expect(winners.size).toBeGreaterThan(1);
  });
});

describe("raffle fails closed", () => {
  it("no seed => not-resolvable", async () => {
    const r = await drawWinner({}, entrants(["1", "2"]));
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });
  it("no entrants => not-resolvable", async () => {
    const r = await drawWinner({ seed: "x" }, entrants([]));
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });
  it("the synchronous resolve refuses (routes through drawWinner)", () => {
    const r = raffle.resolve({ seed: "x" }, entrants(["1"]));
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });
});

describe("uniformIndex is bias-free + bounded", () => {
  it("stays within range and is deterministic", async () => {
    for (let n = 1; n <= 20; n++) {
      const i = await uniformIndex("seed", n);
      expect(i).toBeGreaterThanOrEqual(0);
      expect(i).toBeLessThan(n);
      expect(await uniformIndex("seed", n)).toBe(i);
    }
  });
  it("rejects a non-positive n", async () => {
    await expect(uniformIndex("s", 0)).rejects.toThrow();
    await expect(uniformIndex("s", -1)).rejects.toThrow();
  });
});
