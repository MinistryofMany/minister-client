import { describe, expect, it } from "vitest";
import { isValidMnemonic, mnemonicToSeed, seedToMnemonic } from "./mnemonic.js";
import { DEVICE_SEED_BYTES, deriveIdentities, generateDeviceSeed } from "./derive.js";

describe("BIP-39 device-seed backup", () => {
  it("seed -> mnemonic -> seed round-trips the exact bytes", () => {
    const seed = generateDeviceSeed();
    const mnemonic = seedToMnemonic(seed);
    expect(mnemonic.split(/\s+/)).toHaveLength(24); // 256-bit entropy -> 24 words
    expect([...mnemonicToSeed(mnemonic)]).toEqual([...seed]);
  });

  it("a restored seed re-derives the same identities across many contexts", async () => {
    const seed = generateDeviceSeed();
    const contexts = ["subforum:a", "subforum:b", "room:99"];
    const before = await deriveIdentities(seed, contexts);

    const mnemonic = seedToMnemonic(seed);
    const restored = mnemonicToSeed(mnemonic);
    const after = await deriveIdentities(restored, contexts);

    expect(after.map((i) => i.commitment)).toEqual(before.map((i) => i.commitment));
  });

  it("normalizes whitespace and case when restoring", () => {
    const seed = generateDeviceSeed();
    const mnemonic = seedToMnemonic(seed);
    const messy = `   ${mnemonic.toUpperCase().split(/\s+/).join("    ")}  `;
    expect([...mnemonicToSeed(messy)]).toEqual([...seed]);
    expect(isValidMnemonic(messy)).toBe(true);
  });

  it("rejects a mnemonic with a bad checksum", () => {
    const seed = generateDeviceSeed();
    const words = seedToMnemonic(seed).split(" ");
    // Swap the last word for a different valid wordlist word -> checksum breaks.
    words[words.length - 1] = words[words.length - 1] === "zoo" ? "zone" : "zoo";
    const broken = words.join(" ");
    expect(isValidMnemonic(broken)).toBe(false);
    expect(() => mnemonicToSeed(broken)).toThrow(/checksum|BIP-39/i);
  });

  it("rejects a wrong-length seed", () => {
    expect(() => seedToMnemonic(new Uint8Array(16))).toThrow(
      new RegExp(String(DEVICE_SEED_BYTES)),
    );
  });
});
