import { describe, it, expect } from "vitest";
import { shamirRecovery, getIdentityCommitmentFromSecret } from "./shamir.js";
import { deriveSecret } from "./identity.js";

// Golden vectors cross-checked against Discreetly v2 packages/crypto/src/shamir.test.ts.
describe("shamirRecovery (parity)", () => {
  it("recovers the secret (y-intercept) from two points in Fq", () => {
    expect(shamirRecovery(3n, 7n, 5n, 11n)).toBe(
      10944121435919637611123202872628637544274182200208017171849102093287904247809n,
    );
    expect(
      shamirRecovery(
        111111111111111111111n,
        222222222222222222222n,
        333333333333333333333n,
        555555555555555555555n,
      ),
    ).toBe(111111111111111111111n);
  });

  it("getIdentityCommitmentFromSecret", () => {
    expect(getIdentityCommitmentFromSecret(12345n)).toBe(
      4267533774488295900887461483015112262021273608761099826938271132511348470966n,
    );
  });

  it("recovers the exact identity secret from two colliding RLN share points", () => {
    // An RLN identity secret used as the Shamir line's y-intercept.
    const trapdoor = 0x123456789abcdefn;
    const nullifier = 0xfedcba987654321n;
    const secret = deriveSecret(trapdoor, nullifier);

    // Two distinct x-coordinates (signal hashes) in the same epoch. The line is
    // y = secret + a1*x (RLN message-limit 1 -> degree-1 polynomial). We model
    // the share points the circuit would emit for an arbitrary slope a1.
    const a1 = 7777777777777777n;
    const SNARK_FIELD_SIZE = BigInt(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    const mod = (v: bigint) => ((v % SNARK_FIELD_SIZE) + SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE;
    const x1 = 11n;
    const x2 = 22n;
    const y1 = mod(secret + a1 * x1);
    const y2 = mod(secret + a1 * x2);

    // Two colliding points -> the secret is fully recovered.
    expect(shamirRecovery(x1, x2, y1, y2)).toBe(mod(secret));
    // And the recovered secret maps back to the same commitment.
    expect(getIdentityCommitmentFromSecret(shamirRecovery(x1, x2, y1, y2))).toBe(
      getIdentityCommitmentFromSecret(secret),
    );
  });
});
