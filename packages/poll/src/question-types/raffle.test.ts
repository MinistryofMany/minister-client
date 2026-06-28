import { describe, it, expect } from "vitest";
import {
  raffle,
  drawWinner,
  sortedEntrants,
  validatedSortedEntrants,
  type RaffleVote,
} from "./raffle.js";
import { seedCommitHash, uniformIndex } from "../hash.js";
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

describe("raffle fails CLOSED on a poisoned entrant (does not throw out of resolve)", () => {
  const bad: Array<[string, unknown]> = [
    ["a non-numeric nullifier", "0xdeadbeef"],
    ["a signed nullifier", "-1"],
    ["a whitespace nullifier", " 12 "],
    ["an empty nullifier", ""],
    ["a decimal-with-letters nullifier", "12a3"],
  ];
  for (const [label, value] of bad) {
    it(`${label} => typed not-resolvable err, not a throw`, async () => {
      const votes = [
        { nullifier: "5", vote: {} },
        { nullifier: value as string, vote: {} },
      ] as StoredVote<RaffleVote>[];
      // Must RESOLVE to a typed error rather than reject/throw.
      const r = await drawWinner({ seed: "x" }, votes);
      expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
    });
  }

  it("validatedSortedEntrants returns a typed err naming the malformed entrant", () => {
    const r = validatedSortedEntrants([
      { nullifier: "5", vote: {} },
      { nullifier: "bogus", vote: {} },
    ] as StoredVote<RaffleVote>[]);
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });

  it("all-canonical entrants still validate + sort", () => {
    const r = validatedSortedEntrants([
      { nullifier: "100", vote: {} },
      { nullifier: "3", vote: {} },
    ] as StoredVote<RaffleVote>[]);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.entrants).toEqual(["3", "100"]);
  });
});

describe("raffle resolve-time seed (commit at create, reveal after entries close)", () => {
  const entered = entrants(["3", "20", "100", "7"]);

  it("draws using the resolve-time seed override when no config seed is set", async () => {
    const r = await drawWinner({}, entered, { seed: "revealed-preimage" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.tally.seed).toBe("revealed-preimage");
      expect(r.tally.entrants).toContain(r.tally.winner);
    }
  });

  it("a committed seed-hash is satisfied by the matching revealed preimage", async () => {
    const preimage = "drand:beacon:round-99";
    const seedCommit = await seedCommitHash(preimage);
    const r = await drawWinner({ seedCommit }, entered, { seed: preimage });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.tally.seed).toBe(preimage);
      // Equivalent to a plain draw from the revealed seed (commit only gates).
      const plain = await drawWinner({ seed: preimage }, entered);
      expect(plain.ok).toBe(true);
      if (plain.ok) expect(r.tally.winner).toBe(plain.tally.winner);
    }
  });

  it("a WRONG revealed preimage is rejected (cannot grind the outcome)", async () => {
    const seedCommit = await seedCommitHash("the-real-preimage");
    const r = await drawWinner({ seedCommit }, entered, { seed: "a-different-preimage" });
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });

  it("a committed seed-hash with NO revealed seed fails closed", async () => {
    const seedCommit = await seedCommitHash("p");
    const r = await drawWinner({ seedCommit }, entered);
    expect(r).toMatchObject({ ok: false, code: "not-resolvable" });
  });

  it("resolve-time opts.seed overrides config.seed", async () => {
    const viaConfig = await drawWinner({ seed: "from-opts" }, entered);
    const viaOpts = await drawWinner({ seed: "ignored-config-seed" }, entered, {
      seed: "from-opts",
    });
    expect(viaConfig.ok && viaOpts.ok).toBe(true);
    if (viaConfig.ok && viaOpts.ok) {
      expect(viaOpts.tally.seed).toBe("from-opts");
      expect(viaOpts.tally.winner).toBe(viaConfig.tally.winner);
    }
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
