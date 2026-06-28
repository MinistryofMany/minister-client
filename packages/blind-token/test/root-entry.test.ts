// Root entry (isomorphic) surface: SUITE_NAME, buildInfo byte-exactness, and the
// base64url codecs round-trip. These are the shared wire helpers both the client
// and server depend on, so an error here breaks the whole scheme.

import { describe, it, expect } from "vitest";
import { SUITE_NAME, buildInfo, bytesToB64url, b64urlToBytes } from "../src/index.js";
import { BlindTokenPendingError } from "../src/client/index.js";

describe("root entry wire helpers", () => {
  it("SUITE_NAME is the fixed scheme constant", () => {
    expect(SUITE_NAME).toBe("RSAPBSSA.SHA384.PSS.Randomized");
  });

  it("buildInfo produces exactly <infoPrefix>:<actionKey> UTF-8", () => {
    const out = buildInfo({ infoPrefix: "freedink-vote", actionKey: "abc-123" });
    expect(Array.from(out)).toEqual(
      Array.from(new TextEncoder().encode("freedink-vote:abc-123")),
    );
    // Byte-identical to FreedInk's versionInfo().
    const freedink = new TextEncoder().encode(`freedink-vote:${"abc-123"}`);
    expect(Array.from(out)).toEqual(Array.from(freedink));
  });

  it("buildInfo handles a Deforum-style prefix + composite actionKey", () => {
    const actionKey = "subforum:targetNull:r3";
    const out = buildInfo({ infoPrefix: "deforum-ban", actionKey });
    expect(new TextDecoder().decode(out)).toBe(`deforum-ban:${actionKey}`);
  });

  it("base64url codecs round-trip arbitrary bytes (unpadded, url-safe)", () => {
    for (const len of [0, 1, 2, 3, 31, 32, 256]) {
      const b = new Uint8Array(len);
      for (let i = 0; i < len; i++) b[i] = (i * 37 + 11) & 0xff;
      const enc = bytesToB64url(b);
      // url-safe + unpadded.
      expect(enc).not.toMatch(/[+/=]/);
      expect(Array.from(b64urlToBytes(enc))).toEqual(Array.from(b));
    }
  });

  it("base64url encoding matches Node's base64url for a known vector", () => {
    const b = new Uint8Array([255, 254, 253, 0, 1, 2, 250]);
    expect(bytesToB64url(b)).toBe(Buffer.from(b).toString("base64url"));
  });
});

describe("BlindTokenPendingError", () => {
  it("is an Error carrying the pending flag", () => {
    const e = new BlindTokenPendingError();
    expect(e).toBeInstanceOf(Error);
    expect(e.pending).toBe(true);
    expect(e.name).toBe("BlindTokenPendingError");
  });
});
