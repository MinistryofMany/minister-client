import { describe, it, expect } from "vitest";
import { str2BigInt, genId, randomBigInt, getRateCommitmentHash, getMessageHash } from "./field.js";

// Golden vectors cross-checked against the Discreetly v2 source
// (packages/crypto/src/field.test.ts) on the installed poseidon-lite 0.2.0.
describe("field utils (parity with Discreetly golden vectors)", () => {
  it("str2BigInt", () => {
    expect(str2BigInt("")).toBe(0n);
    expect(str2BigInt("Alpha Testers")).toBe(5183390837097462041516934787699n);
    expect(str2BigInt("gm 🌅")).toBe(29111910844566661n);
  });

  it("genId", () => {
    expect(genId(0, "Alpha Testers")).toBe(
      18165449002766348569087181317809972811560541873833072082773716372988104637535n,
    );
    expect(genId(42, "general")).toBe(
      15305175996942493984876657405065573381055348967581108949886047442046564599825n,
    );
    expect(genId(1, 700)).toBe(
      6585934516913424527874756177614402393272149364854687834971917373045751390946n,
    );
  });

  it("getRateCommitmentHash", () => {
    expect(getRateCommitmentHash(123n, 1)).toBe(
      1825367215715080944898610730329185918884251567885580835209236772238472514878n,
    );
    expect(
      getRateCommitmentHash(
        19014214495641488759237505126948346942972912379615652741039992445865937985n,
        50,
      ),
    ).toBe(8605271634723343760659286622282624455771371598881535798394442865683358678826n);
  });

  it("getMessageHash", () => {
    expect(getMessageHash("hello")).toBe(
      14021998335275890241385849815772078196725001835760665002305519183140501905n,
    );
  });

  it("randomBigInt stays in range and varies", () => {
    const a = randomBigInt(253);
    const b = randomBigInt(253);
    expect(a).toBeLessThan(1n << 253n);
    expect(a).not.toBe(b);
  });
});
