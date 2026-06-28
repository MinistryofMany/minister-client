import { describe, expect, it } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import {
  DEVICE_SEED_BYTES,
  DERIVED_KEY_BYTES,
  deriveIdentities,
  deriveIdentity,
  derivePrivateKeyBytes,
  generateDeviceSeed,
} from "./derive.js";

// A fixed, deterministic device seed for golden-style tests.
const SEED_A = new Uint8Array(DEVICE_SEED_BYTES).map((_, i) => (i * 7 + 1) & 0xff);
const SEED_B = new Uint8Array(DEVICE_SEED_BYTES).map((_, i) => (i * 13 + 5) & 0xff);

describe("device-seed -> per-context identity derivation", () => {
  it("same (seed, context) -> same commitment (deterministic)", async () => {
    const a = await deriveIdentity(SEED_A, "subforum:alpha");
    const b = await deriveIdentity(SEED_A, "subforum:alpha");
    expect(a.commitment).toBe(b.commitment);
    // and the underlying private key bytes are identical
    const ka = await derivePrivateKeyBytes(SEED_A, "subforum:alpha");
    const kb = await derivePrivateKeyBytes(SEED_A, "subforum:alpha");
    expect([...ka]).toEqual([...kb]);
    expect(ka.byteLength).toBe(DERIVED_KEY_BYTES);
  });

  it("different context -> different commitment (per-context separation)", async () => {
    const alpha = await deriveIdentity(SEED_A, "subforum:alpha");
    const beta = await deriveIdentity(SEED_A, "subforum:beta");
    expect(alpha.commitment).not.toBe(beta.commitment);
  });

  it("different seed, same context -> different commitment", async () => {
    const a = await deriveIdentity(SEED_A, "subforum:alpha");
    const b = await deriveIdentity(SEED_B, "subforum:alpha");
    expect(a.commitment).not.toBe(b.commitment);
  });

  it("cross-context unlinkability: many contexts from one seed are all distinct", async () => {
    const contexts = Array.from({ length: 16 }, (_, i) => `room:${i}`);
    const ids = await deriveIdentities(SEED_A, contexts);
    const commitments = ids.map((i) => i.commitment);
    // every commitment is unique -> no two contexts share a leaf, so an observer
    // holding the at-rest leaves cannot link two contexts to the same seed.
    expect(new Set(commitments).size).toBe(commitments.length);
    // order preserved
    expect(ids.map((i) => i.context)).toEqual(contexts);
  });

  it("derived commitment equals a v4 Identity built from the same derived key (no extra math)", async () => {
    const key = await derivePrivateKeyBytes(SEED_A, "subforum:alpha");
    const direct = new Identity(key);
    const derived = await deriveIdentity(SEED_A, "subforum:alpha");
    // Confirms we do not touch the commitment math: commitment is exactly
    // poseidon2([publicKey.x, publicKey.y]) of new Identity(derivedKey).
    expect(derived.commitment).toBe(direct.commitment.toString());
    expect(derived.commitment).toBe(
      Identity.generateCommitment(direct.publicKey).toString(),
    );
  });

  it("commitment is a decimal string (FieldString), not a bigint", async () => {
    const a = await deriveIdentity(SEED_A, "subforum:alpha");
    expect(typeof a.commitment).toBe("string");
    expect(a.commitment).toMatch(/^[0-9]+$/);
  });

  it("rejects a wrong-length device seed", async () => {
    await expect(deriveIdentity(new Uint8Array(16), "x")).rejects.toThrow(/32 bytes/);
    await expect(derivePrivateKeyBytes(new Uint8Array(64), "x")).rejects.toThrow(/32 bytes/);
  });

  it("generateDeviceSeed produces 32 random bytes (distinct across calls)", () => {
    const s1 = generateDeviceSeed();
    const s2 = generateDeviceSeed();
    expect(s1.byteLength).toBe(DEVICE_SEED_BYTES);
    expect(s2.byteLength).toBe(DEVICE_SEED_BYTES);
    expect([...s1]).not.toEqual([...s2]);
  });
});
