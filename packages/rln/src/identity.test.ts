import { describe, it, expect } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import {
  deriveSecret,
  deriveCommitment,
  deserializeV3Identity,
  serializeV3Identity,
} from "./identity.js";
import { getIdentityCommitmentFromSecret } from "./shamir.js";

// Cross-impl: prove the bigint identity layer reproduces Semaphore v3 byte-for-byte
// so existing Discreetly localStorage identities keep working (the migration path).
describe("v3 identity layer (bigint surface) vs @semaphore-protocol/identity@3.15.0", () => {
  it("deriveSecret matches v3 secret = poseidon2([nullifier, trapdoor])", () => {
    // A fixed, known [trapdoor, nullifier] pair via the v3 hex serialization.
    const blob = JSON.stringify(["0x123456789abcdef", "0xfedcba987654321"]);
    const v3 = new Identity(blob);
    const trapdoor = 0x123456789abcdefn;
    const nullifier = 0xfedcba987654321n;

    expect(deriveSecret(trapdoor, nullifier)).toBe(v3.secret);
    expect(deriveCommitment(deriveSecret(trapdoor, nullifier))).toBe(v3.commitment);
  });

  it("an existing v3 blob round-trips to the SAME poseidon1 commitment", () => {
    // Generate a fresh v3 identity exactly as Discreetly's identity.ts does and
    // serialize it the canonical way (Identity.toString() = [trapdoor, nullifier]).
    const v3 = new Identity();
    const blob = v3.toString();

    const migrated = deserializeV3Identity(blob);

    // The migration MUST preserve the secret and the commitment exactly.
    expect(migrated.secret).toBe(v3.secret);
    expect(migrated.commitment).toBe(v3.commitment);
    expect(migrated.trapdoor).toBe(v3.trapdoor);
    expect(migrated.nullifier).toBe(v3.nullifier);

    // And the commitment is poseidon1(secret) - the invariant Shamir recovery relies on.
    expect(getIdentityCommitmentFromSecret(migrated.secret)).toBe(migrated.commitment);
  });

  it("round-trips across 50 random v3 identities", () => {
    for (let i = 0; i < 50; i++) {
      const v3 = new Identity();
      const migrated = deserializeV3Identity(v3.toString());
      expect(migrated.secret).toBe(v3.secret);
      expect(migrated.commitment).toBe(v3.commitment);
    }
  });

  it("accepts the already-parsed tuple and decimal-string elements", () => {
    const v3 = new Identity(JSON.stringify(["0xabc", "0xdef"]));
    // Tuple form.
    expect(deserializeV3Identity(["0xabc", "0xdef"]).commitment).toBe(v3.commitment);
    // Decimal-string elements (BigNumber.from / BigInt both accept these).
    expect(deserializeV3Identity([String(0xabc), String(0xdef)]).commitment).toBe(v3.commitment);
  });

  it("serializeV3Identity reproduces the canonical v3 toString() bytes", () => {
    const v3 = new Identity();
    expect(serializeV3Identity(v3.trapdoor, v3.nullifier)).toBe(v3.toString());
  });

  it("rejects malformed blobs", () => {
    expect(() => deserializeV3Identity("not json")).toThrow();
    expect(() => deserializeV3Identity(JSON.stringify([1, 2, 3]))).toThrow();
    expect(() => deserializeV3Identity(JSON.stringify(["0x1"]))).toThrow();
  });
});
