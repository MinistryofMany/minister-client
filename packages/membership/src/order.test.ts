import { describe, it, expect } from "vitest";
import { Group } from "@semaphore-protocol/group";
import { Identity } from "@semaphore-protocol/identity";
import { orderLeaves } from "./order.js";
import type { EligibleLeaf } from "./provider.js";

// ORDERKEYS determinism (control 4). FreedInk's snapshot root is a pure function
// of a SPECIFIC sort (userCreatedAtMs, userId, deviceCreatedAtMs, idc) and the
// client is forbidden to re-sort. If this comparator drifts, every stored
// FreedInk snapshot becomes unverifiable. These tests are the tripwire.

function leaf(commitment: string, orderKeys?: ReadonlyArray<string | number>): EligibleLeaf {
  return { leaf: commitment, commitment, orderKeys };
}

describe("orderLeaves comparator (byte-specified)", () => {
  it("numeric keys compare by value (ms timestamps), not lexicographically", () => {
    // 9 > 10 lexicographically but 9 < 10 numerically; numeric ordering must win.
    const a = leaf("aaa", [9]);
    const b = leaf("bbb", [10]);
    const out = orderLeaves([b, a]);
    expect(out.map((l) => l.commitment)).toEqual(["aaa", "bbb"]);
  });

  it("string keys compare by localeCompare", () => {
    const a = leaf("x", ["alice"]);
    const b = leaf("y", ["bob"]);
    expect(orderLeaves([b, a]).map((l) => l.commitment)).toEqual(["x", "y"]);
  });

  it("applies the full FreedInk key chain (userCreatedAt, userId, deviceCreatedAt, idc)", () => {
    // Two members; member u1 created before u2. Within u1, two devices; the second
    // device shares a created-at so the idc tiebreak decides.
    const rows: EligibleLeaf[] = [
      leaf("300", [200, "u2", 5, "300"]),
      leaf("102", [100, "u1", 9, "102"]), // same device-ts as next -> idc tiebreak
      leaf("101", [100, "u1", 9, "101"]),
      leaf("100", [100, "u1", 1, "100"]),
    ];
    const out = orderLeaves(rows).map((l) => l.commitment);
    // u1 (createdAt 100) before u2 (200); within u1 device-ts 1 before 9; the two
    // device-ts-9 leaves tiebreak on idc string ("101" < "102").
    expect(out).toEqual(["100", "101", "102", "300"]);
  });

  it("is a stable no-op when no leaf carries orderKeys (Discreetly: preserve return order)", () => {
    const rows = [leaf("c"), leaf("a"), leaf("b")];
    expect(orderLeaves(rows).map((l) => l.commitment)).toEqual(["c", "a", "b"]);
  });

  it("does not mutate its input", () => {
    const rows = [leaf("b", [2]), leaf("a", [1])];
    const before = rows.slice();
    orderLeaves(rows);
    expect(rows).toEqual(before);
  });

  it("throws on a mixed key type at the same position (drift guard)", () => {
    expect(() => orderLeaves([leaf("a", [1]), leaf("b", ["x"])])).toThrow(/type mismatch/i);
  });
});

// Port of FreedInk's snapshots.unit.test.ts "group root reproducibility": the
// load-bearing invariant that rebuilding the group from the SAME ordered idc set
// yields the SAME root the original proof was issued against. We additionally
// assert that ordering via orderLeaves reproduces the exact root FreedInk's
// snapshots.ts would compute (its sort then `new Group()` over the ordered idcs).
describe("FreedInk root determinism (ported tripwire)", () => {
  function rootOf(idcs: string[]): string {
    const g = new Group();
    for (const c of idcs) g.addMember(BigInt(c));
    return g.root.toString();
  }

  it("produces the same root for the same sorted IDC set", () => {
    const ids = [new Identity(), new Identity(), new Identity()];
    const idcs = ids.map((i) => i.commitment.toString()).sort();
    expect(rootOf(idcs)).toEqual(rootOf(idcs));
  });

  it("is sensitive to insertion order if not sorted", () => {
    const ids = [new Identity(), new Identity(), new Identity()];
    const a = ids.map((i) => i.commitment.toString());
    const b = a.slice().reverse();
    // Distinct orders -> distinct roots (so order is load-bearing).
    expect(new Set(a).size).toBe(3);
    expect(rootOf(a)).not.toEqual(rootOf(b));
  });

  it("orderLeaves reproduces FreedInk's snapshots.ts root for a realistic key chain", () => {
    // Build three identities and assign FreedInk-style order keys; ordering via
    // orderLeaves must match a hand-applied FreedInk sort, and the resulting root
    // must equal `new Group()` over the same ordered idcs.
    const i1 = new Identity();
    const i2 = new Identity();
    const i3 = new Identity();
    const c1 = i1.commitment.toString();
    const c2 = i2.commitment.toString();
    const c3 = i3.commitment.toString();

    // userCreatedAt: u-a (1000) holds i1 (dev 10) + i3 (dev 20); u-b (2000) holds i2.
    const rows: EligibleLeaf[] = [
      { leaf: c2, commitment: c2, orderKeys: [2000, "u-b", 5, c2] },
      { leaf: c3, commitment: c3, orderKeys: [1000, "u-a", 20, c3] },
      { leaf: c1, commitment: c1, orderKeys: [1000, "u-a", 10, c1] },
    ];

    // Hand-apply FreedInk's exact sort (snapshots.ts).
    const hand = rows.slice().sort((a, b) => {
      const ak = a.orderKeys!;
      const bk = b.orderKeys!;
      const t = (ak[0] as number) - (bk[0] as number);
      if (t !== 0) return t;
      if (ak[1] !== bk[1]) return (ak[1] as string).localeCompare(bk[1] as string);
      const d = (ak[2] as number) - (bk[2] as number);
      if (d !== 0) return d;
      return (ak[3] as string).localeCompare(bk[3] as string);
    });

    const ordered = orderLeaves(rows);
    expect(ordered.map((l) => l.commitment)).toEqual(hand.map((l) => l.commitment));

    // The package-ordered root equals the FreedInk-ordered root.
    expect(rootOf(ordered.map((l) => l.commitment))).toEqual(
      rootOf(hand.map((l) => l.commitment)),
    );
  });
});
