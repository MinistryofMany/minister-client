import { describe, expect, it } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import {
  CONTEXT_KEY_BYTES,
  PER_APP_SECRET_BYTES,
  deriveContextKeyBytes,
  deriveIdentities,
  deriveIdentity,
} from "./derive.js";
import type { AnonContext } from "./types.js";

// A fixed, deterministic per-app secret for golden-style tests.
const SECRET_A = new Uint8Array(PER_APP_SECRET_BYTES).map((_, i) => (i * 7 + 1) & 0xff);
const SECRET_B = new Uint8Array(PER_APP_SECRET_BYTES).map((_, i) => (i * 13 + 5) & 0xff);

const ALPHA: AnonContext = { kind: "subforum", id: "alpha" };
const BETA: AnonContext = { kind: "subforum", id: "beta" };

describe("per-app-secret -> per-context identity derivation", () => {
  it("same (secret, context) -> same commitment (deterministic)", async () => {
    const a = await deriveIdentity(SECRET_A, ALPHA);
    const b = await deriveIdentity(SECRET_A, ALPHA);
    expect(a.commitment).toBe(b.commitment);
    const ka = await deriveContextKeyBytes(SECRET_A, ALPHA);
    const kb = await deriveContextKeyBytes(SECRET_A, ALPHA);
    expect([...ka]).toEqual([...kb]);
    expect(ka.byteLength).toBe(CONTEXT_KEY_BYTES);
  });

  it("different context -> different commitment (per-context separation)", async () => {
    const alpha = await deriveIdentity(SECRET_A, ALPHA);
    const beta = await deriveIdentity(SECRET_A, BETA);
    expect(alpha.commitment).not.toBe(beta.commitment);
  });

  it("different secret, same context -> different commitment", async () => {
    const a = await deriveIdentity(SECRET_A, ALPHA);
    const b = await deriveIdentity(SECRET_B, ALPHA);
    expect(a.commitment).not.toBe(b.commitment);
  });

  it("the sub qualifier separates two leaves of the same room (trapdoor vs nullifier)", async () => {
    const trapdoor = await deriveContextKeyBytes(SECRET_A, { kind: "room", id: "r1", sub: "trapdoor" });
    const nullifier = await deriveContextKeyBytes(SECRET_A, { kind: "room", id: "r1", sub: "nullifier" });
    const plain = await deriveContextKeyBytes(SECRET_A, { kind: "room", id: "r1" });
    expect(toHex(trapdoor)).not.toBe(toHex(nullifier));
    expect(toHex(trapdoor)).not.toBe(toHex(plain));
  });

  it("a slash in any context segment is rejected (collision is structurally impossible)", async () => {
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "room", id: "a/b" })).rejects.toThrow(/must not contain/);
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "ro/om", id: "a" })).rejects.toThrow(/must not contain/);
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "room", id: "a", sub: "x/y" })).rejects.toThrow(/must not contain/);
    // The collision the structure prevents: {room, a, trapdoor} vs {room, a/trapdoor}
    // can no longer produce the same context id, because the latter is rejected.
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "room", id: "a/trapdoor" })).rejects.toThrow();
  });

  it("empty context segments are rejected", async () => {
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "", id: "a" })).rejects.toThrow(/non-empty/);
    await expect(deriveContextKeyBytes(SECRET_A, { kind: "room", id: "" })).rejects.toThrow(/non-empty/);
  });

  it("cross-context unlinkability: many contexts from one secret are all distinct", async () => {
    const contexts: AnonContext[] = Array.from({ length: 16 }, (_, i) => ({ kind: "room", id: String(i) }));
    const ids = await deriveIdentities(SECRET_A, contexts);
    const commitments = ids.map((i) => i.commitment);
    expect(new Set(commitments).size).toBe(commitments.length);
    expect(ids.map((i) => i.context)).toEqual(contexts);
  });

  it("derived commitment equals a v4 Identity built from the same derived key (no extra math)", async () => {
    const key = await deriveContextKeyBytes(SECRET_A, ALPHA);
    const direct = new Identity(key);
    const derived = await deriveIdentity(SECRET_A, ALPHA);
    expect(derived.commitment).toBe(direct.commitment.toString());
    expect(derived.commitment).toBe(Identity.generateCommitment(direct.publicKey).toString());
  });

  it("commitment is a decimal string (FieldString), not a bigint", async () => {
    const a = await deriveIdentity(SECRET_A, ALPHA);
    expect(typeof a.commitment).toBe("string");
    expect(a.commitment).toMatch(/^[0-9]+$/);
  });

  it("rejects a wrong-length per-app secret", async () => {
    await expect(deriveIdentity(new Uint8Array(16), ALPHA)).rejects.toThrow(/32 bytes/);
    await expect(deriveContextKeyBytes(new Uint8Array(64), ALPHA)).rejects.toThrow(/32 bytes/);
  });
});

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
