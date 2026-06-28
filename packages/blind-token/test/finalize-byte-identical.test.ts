// CHROMIUM DRIFT TRIPWIRE + BYTE-IDENTICAL FINALIZE.
//
// This is the load-bearing test for the @cloudflare/blindrsa-ts@0.4.6 pin and the
// encapsulated Chromium-safe finalize. It fails LOUDLY if either:
//   (1) the deep internal import paths (lib/src/sjcl, lib/src/util) no longer
//       resolve - a consumer pinning a new commit that bumped the library would
//       get a signal here before shipping; or
//   (2) finalizeToken's signature bytes ever drift from the library's own
//       suite.finalize output - the byte-identical guarantee that keeps the wire
//       scheme (and the Signet interop) intact.
//
// Lifted from FreedInk's src/lib/client/vote-token.browser.unit.test.ts, retargeted
// at the package's encapsulated finalize (__testing.finalizeInBrowser).

import { describe, it, expect } from "vitest";
import { RSAPBSSA, PartiallyBlindRSA } from "@cloudflare/blindrsa-ts";
import { generatePrimeSync } from "node:crypto";
import { __testing } from "../src/client/index.js";

const SUITE = RSAPBSSA.SHA384.PSS.Randomized();

function fastSafePrime(length: number): bigint {
  return generatePrimeSync(length, { safe: true, bigint: true });
}

describe("Chromium-drift tripwire: deep internal imports resolve", () => {
  it("can dynamically import the pinned library's internal sjcl + util modules", async () => {
    // If a future @cloudflare/blindrsa-ts moves/renames these paths or adds an
    // `exports` map that hides them, BOTH imports throw and this test fails -
    // exactly the signal a consumer needs before pinning a new commit.
    const sjclMod = await import("@cloudflare/blindrsa-ts/lib/src/sjcl/index.js");
    const utilMod = await import("@cloudflare/blindrsa-ts/lib/src/util.js");
    expect(sjclMod.default).toBeDefined();
    expect(sjclMod.default.bn).toBeDefined();
    // The exact util primitives finalizeInBrowser depends on must all exist.
    for (const name of [
      "os2ip",
      "i2osp",
      "int_to_bytes",
      "joinAll",
      "rsavp1",
    ] as const) {
      expect(typeof (utilMod as Record<string, unknown>)[name]).toBe("function");
    }
  });
});

describe("byte-identical finalize (Chromium-safe == library finalize)", () => {
  it("finalizeInBrowser matches the library finalize byte-for-byte and verifies", async () => {
    // 1024-bit key keeps the test fast; the derived exponent is still 512 bits
    // (> WebCrypto's ~32-bit bound), so it exercises the same code path the
    // production 2048-bit key hits. Protocol logic is size-independent.
    const { privateKey, publicKey } = await PartiallyBlindRSA.generateKey(
      { modulusLength: 1024, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-384" },
      fastSafePrime,
    );
    const info = new TextEncoder().encode("freedink-vote:version-xyz");

    // CLIENT: blind a random nonce.
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const prepared = SUITE.prepare(nonce);
    const { blindedMsg, inv } = await SUITE.blind(publicKey, prepared, info);
    expect(blindedMsg.length).toBeGreaterThan(0);

    // SERVER: blind-sign.
    const blindSig = await SUITE.blindSign(privateKey, blindedMsg, info);

    // CLIENT: the package's Chromium-safe finalize.
    const mine = await __testing.finalizeInBrowser(publicKey, prepared, info, blindSig, inv);
    // The library's finalize, for the byte-for-byte comparison (works under Node).
    const lib = await SUITE.finalize(publicKey, prepared, info, blindSig, inv);

    expect(mine.length).toBe(lib.length);
    expect(Array.from(mine)).toEqual(Array.from(lib));

    // SERVER: verify the package's signature with the UNMODIFIED library (wire compat).
    expect(await SUITE.verify(publicKey, mine, prepared, info)).toBe(true);
    // Cross-action replay is impossible: a different info fails.
    expect(
      await SUITE.verify(publicKey, mine, prepared, new TextEncoder().encode("other")),
    ).toBe(false);
  });

  it("finalizeInBrowser rejects a tampered blind signature (self-check intact)", async () => {
    const { privateKey, publicKey } = await PartiallyBlindRSA.generateKey(
      { modulusLength: 1024, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-384" },
      fastSafePrime,
    );
    const info = new TextEncoder().encode("freedink-vote:tamper");
    const prepared = SUITE.prepare(crypto.getRandomValues(new Uint8Array(32)));
    const { blindedMsg, inv } = await SUITE.blind(publicKey, prepared, info);
    const blindSig = await SUITE.blindSign(privateKey, blindedMsg, info);

    const tampered = blindSig.slice();
    tampered[3]! ^= 0x80;
    await expect(
      __testing.finalizeInBrowser(publicKey, prepared, info, tampered, inv),
    ).rejects.toThrow(/invalid signature/);
  });
});
