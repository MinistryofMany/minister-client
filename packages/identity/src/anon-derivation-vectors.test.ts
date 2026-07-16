import { describe, expect, it } from "vitest";
import { deriveContextKeyBytes } from "./derive.js";
import type { AnonContext } from "./types.js";
import vectors from "./anon-derivation-vectors.json";

// Proves the SDK's derivation reproduces the FROZEN golden vectors. If this
// fails, the derivation drifted - fix the derivation (salt/info/L), never the
// committed JSON. L1 (root -> per_app_secret) happens only on ministry.id and is
// not part of the SDK surface, so it is recomputed here with raw WebCrypto HKDF;
// L2 (per_app_secret -> context key) goes through the exported
// deriveContextKeyBytes so a real drift in the shipped code is caught.

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hkdf(ikm: Uint8Array, salt: string, info: string, length: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(salt) as BufferSource,
      info: new TextEncoder().encode(info) as BufferSource,
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

const ROOT = fromHex(vectors.rootHex);

describe("frozen anon-derivation golden vectors", () => {
  it("root hex decodes to the expected utf8 marker", () => {
    expect(new TextDecoder().decode(ROOT)).toBe(vectors.rootUtf8);
    expect(ROOT.byteLength).toBe(16);
  });

  it("L1 per_app_secret vectors reproduce (root -> HKDF ministry/v1/rp/app/epoch)", async () => {
    for (const v of vectors.l1) {
      const info = `${vectors.l1InfoPrefix}${v.app}/${v.epoch}`;
      const got = await hkdf(ROOT, vectors.salt, info, vectors.length);
      expect(toHex(got), `${v.app} epoch ${v.epoch}`).toBe(v.hex);
    }
  });

  it("L2 context_secret vectors reproduce through deriveContextKeyBytes", async () => {
    const from = vectors.l1.find((e) => e.app === vectors.l2From.app && e.epoch === vectors.l2From.epoch);
    if (from === undefined) throw new Error("l2From does not reference an l1 vector");
    const branch = fromHex(from.hex);
    for (const v of vectors.l2) {
      const context = v.context as AnonContext;
      const got = await deriveContextKeyBytes(branch, context);
      expect(toHex(got), v.contextId).toBe(v.hex);
      // The structured context must serialize to the frozen flat context id.
      const flat = context.sub === undefined ? `${context.kind}/${context.id}` : `${context.kind}/${context.id}/${context.sub}`;
      expect(flat).toBe(v.contextId);
    }
  });

  it("epoch changes the L1 branch (deforum/1 != deforum/2)", () => {
    const e1 = vectors.l1.find((e) => e.app === "deforum" && e.epoch === 1)?.hex;
    const e2 = vectors.l1.find((e) => e.app === "deforum" && e.epoch === 2)?.hex;
    expect(e1).toBeDefined();
    expect(e2).toBeDefined();
    expect(e1).not.toBe(e2);
  });
});
