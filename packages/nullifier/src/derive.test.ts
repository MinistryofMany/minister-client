import { describe, it, expect } from "vitest";
import { poseidon2 } from "poseidon-lite";
import {
  FIELD,
  toField,
  deriveContextNullifier,
  deriveContextNullifierFromField,
} from "./derive.js";

/**
 * Canonical reference implementation, copied verbatim from Discreetly
 * `services/api/src/gate/join-nullifier.ts`. `deriveContextNullifier` must
 * produce byte-identical output to this for every input, so an existing
 * Discreetly anchor and a new Deforum anchor never silently diverge.
 */
function joinNullifierReference(sub: string, rlnIdentifier: bigint): bigint {
  return poseidon2([toField(sub), rlnIdentifier % FIELD]);
}

describe("FIELD", () => {
  it("is the BN254 scalar field order (frozen constant)", () => {
    expect(FIELD).toBe(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    );
  });
});

describe("toField golden vectors", () => {
  // Fixed inputs -> fixed expected bigints, computed against poseidon-lite 0.2.0
  // (the pinned version). A change here means the reduction drifted.
  it("matches the recorded big-endian base-256 reduction", () => {
    expect(toField("hello")).toBe(448378203247n);
    expect(toField("")).toBe(0n);
    expect(toField("café-✓")).toBe(1833246175497935821971n);
  });

  it("is field-bounded", () => {
    expect(toField("any-long-string-".repeat(20))).toBeLessThan(FIELD);
  });
});

describe("deriveContextNullifier golden vectors", () => {
  // Frozen expected outputs computed with the pinned poseidon-lite 0.2.0 against
  // the exact Discreetly derivation. If poseidon-lite or the math ever drifts,
  // these fail loudly instead of silently shifting every nullifier.
  it("matches the recorded hashes for fixed inputs", () => {
    expect(deriveContextNullifier("sub-abc", 700n)).toBe(
      19689601124232383687478931466696358110832892559241128841187386029020705617851n,
    );
    expect(deriveContextNullifier("pairwise-user-123", 42n)).toBe(
      7936859699018423231474624662945145271663768100853138089131173980322240423885n,
    );
    expect(deriveContextNullifier("", 0n)).toBe(
      14744269619966411208579211824598458697587494354926760081771325075741142829156n,
    );
  });
});

describe("deriveContextNullifier behavior", () => {
  it("is deterministic per (sub, contextId) and field-bounded", () => {
    const a = deriveContextNullifier("sub-abc", 700n);
    expect(deriveContextNullifier("sub-abc", 700n)).toBe(a);
    expect(a).toBeLessThan(FIELD);
  });

  it("differs across subs and across contexts (per-context unlinkable)", () => {
    expect(deriveContextNullifier("sub-a", 700n)).not.toBe(deriveContextNullifier("sub-b", 700n));
    expect(deriveContextNullifier("sub-a", 700n)).not.toBe(deriveContextNullifier("sub-a", 701n));
  });

  it("reduces contextId modulo FIELD (a wrapped contextId hits the same anchor)", () => {
    expect(deriveContextNullifier("sub-abc", FIELD + 700n)).toBe(
      deriveContextNullifier("sub-abc", 700n),
    );
  });
});

describe("deriveContextNullifierFromField (field VALUE input, not a string)", () => {
  it("is poseidon2(value % FIELD, contextId % FIELD)", () => {
    expect(deriveContextNullifierFromField(7n, 700n)).toBe(poseidon2([7n, 700n]));
  });

  it("reduces the value modulo FIELD as a NUMBER (wrap hits the same anchor)", () => {
    expect(deriveContextNullifierFromField(FIELD + 7n, 700n)).toBe(
      deriveContextNullifierFromField(7n, 700n),
    );
  });

  it("treats a field element as a value, NOT its decimal byte-reduction", () => {
    // The whole point of FIX 3: a field element fed as a value must NOT equal the
    // same decimal run through toField (which re-hashes its digits).
    expect(deriveContextNullifierFromField(7n, 700n)).not.toBe(
      deriveContextNullifier("7", 700n),
    );
  });

  it("is field-bounded and deterministic", () => {
    const a = deriveContextNullifierFromField(123456789n, 42n);
    expect(deriveContextNullifierFromField(123456789n, 42n)).toBe(a);
    expect(a).toBeLessThan(FIELD);
  });
});

describe("cross-impl equality with Discreetly joinNullifier", () => {
  it("equals the Discreetly derivation for the same (sub, contextId)", () => {
    const cases: Array<[string, bigint]> = [
      ["sub-abc", 700n],
      ["pairwise-user-123", 42n],
      ["", 0n],
      ["a longer pairwise subject value", 123456789n],
      ["sub-with-unicode-café-✓", FIELD + 9n],
    ];
    for (const [sub, ctx] of cases) {
      expect(deriveContextNullifier(sub, ctx)).toBe(joinNullifierReference(sub, ctx));
    }
  });
});
