import { describe, it, expect } from "vitest";
import { calculateSignalHash } from "./signal-hash.js";

// Golden vectors cross-checked against Discreetly v2 packages/crypto/src/signal-hash.test.ts.
describe("calculateSignalHash (parity)", () => {
  it("matches the keccak256>>8 outputs", () => {
    expect(calculateSignalHash("hello")).toBe(
      50431049290266644231251360234089458127683824157542166152159614998166072810n,
    );
    expect(calculateSignalHash(JSON.stringify({ body: "gm", type: "TEXT" }))).toBe(
      101884730950471513996544060039004803867143945453357388976088785884555538236n,
    );
    expect(calculateSignalHash("")).toBe(
      349520125851268261087593898257781118122351904114639672919570969471416632740n,
    );
  });
});
