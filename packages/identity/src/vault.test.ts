import { describe, expect, it } from "vitest";
import {
  PBKDF2_ITERATIONS,
  WrongPasswordError,
  decryptSeed,
  encryptSeed,
  vaultFromJson,
  vaultToJson,
} from "./vault.js";
import { DEVICE_SEED_BYTES, deriveIdentity, generateDeviceSeed } from "./derive.js";

const PASSWORD = "correct horse battery staple";

describe("device-seed vault (PBKDF2-SHA256 + AES-GCM)", () => {
  it("encrypt -> decrypt round-trips the exact seed bytes", async () => {
    const seed = generateDeviceSeed();
    const vault = await encryptSeed(seed, PASSWORD);
    const out = await decryptSeed(vault, PASSWORD);
    expect([...out]).toEqual([...seed]);
  });

  it("envelope records the KDF parameters and uses the configured iteration count", async () => {
    const vault = await encryptSeed(generateDeviceSeed(), PASSWORD);
    expect(vault.v).toBe(1);
    expect(vault.kdf).toBe("PBKDF2");
    expect(vault.hash).toBe("SHA-256");
    expect(vault.iterations).toBe(PBKDF2_ITERATIONS);
    // salt, iv, ciphertext are base64 strings.
    expect(vault.salt).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(vault.iv).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(vault.ciphertext).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("a wrong password throws WrongPasswordError (AES-GCM auth-tag failure)", async () => {
    const vault = await encryptSeed(generateDeviceSeed(), PASSWORD);
    await expect(decryptSeed(vault, "wrong password")).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it("tampered ciphertext throws WrongPasswordError", async () => {
    const seed = generateDeviceSeed();
    const vault = await encryptSeed(seed, PASSWORD);
    // Flip a byte in the base64 ciphertext payload.
    const bytes = atob(vault.ciphertext).split("");
    bytes[0] = String.fromCharCode(bytes[0]!.charCodeAt(0) ^ 0xff);
    const tampered = { ...vault, ciphertext: btoa(bytes.join("")) };
    await expect(decryptSeed(tampered, PASSWORD)).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it("two encryptions of the same seed differ (random salt + iv) but both decrypt", async () => {
    const seed = generateDeviceSeed();
    const v1 = await encryptSeed(seed, PASSWORD);
    const v2 = await encryptSeed(seed, PASSWORD);
    expect(v1.ciphertext).not.toBe(v2.ciphertext);
    expect(v1.salt).not.toBe(v2.salt);
    expect(v1.iv).not.toBe(v2.iv);
    expect([...(await decryptSeed(v1, PASSWORD))]).toEqual([...seed]);
    expect([...(await decryptSeed(v2, PASSWORD))]).toEqual([...seed]);
  });

  it("a restored seed re-derives the same per-context commitments", async () => {
    const seed = generateDeviceSeed();
    const before = await deriveIdentity(seed, "room:42");
    const vault = await encryptSeed(seed, PASSWORD);
    const restored = await decryptSeed(vault, PASSWORD);
    const after = await deriveIdentity(restored, "room:42");
    expect(after.commitment).toBe(before.commitment);
  });

  it("JSON serialize / parse round-trips an envelope", async () => {
    const vault = await encryptSeed(generateDeviceSeed(), PASSWORD);
    const json = vaultToJson(vault);
    const parsed = vaultFromJson(json);
    expect(parsed).toEqual(vault);
  });

  it("rejects empty password, wrong seed size, and malformed JSON", async () => {
    await expect(encryptSeed(generateDeviceSeed(), "")).rejects.toThrow(/Password/);
    await expect(encryptSeed(new Uint8Array(8), PASSWORD)).rejects.toThrow(
      new RegExp(String(DEVICE_SEED_BYTES)),
    );
    expect(() => vaultFromJson("not json")).toThrow(/valid JSON/);
    expect(() => vaultFromJson(JSON.stringify({ v: 2 }))).toThrow(/shape|fields/);
  });
});
