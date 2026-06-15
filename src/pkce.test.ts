import { describe, expect, it } from "vitest";

import { generatePkce, randomUrlToken } from "./pkce";

function b64urlSha256(input: string): Promise<string> {
  return crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(input))
    .then((digest) => {
      const bytes = new Uint8Array(digest);
      let str = "";
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/u, "");
    });
}

describe("generatePkce", () => {
  it("produces a base64url challenge equal to S256(verifier)", async () => {
    const { verifier, challenge } = await generatePkce();
    expect(challenge).toBe(await b64urlSha256(verifier));
  });

  it("uses url-safe base64 with no padding", async () => {
    const { verifier, challenge } = await generatePkce();
    for (const value of [verifier, challenge]) {
      expect(value).toMatch(/^[A-Za-z0-9_-]+$/u);
    }
  });

  it("returns a fresh pair each call", async () => {
    const a = await generatePkce();
    const b = await generatePkce();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).not.toBe(b.challenge);
  });
});

describe("randomUrlToken", () => {
  it("is url-safe and unique", () => {
    const a = randomUrlToken();
    const b = randomUrlToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(a).not.toBe(b);
  });

  it("scales length with the byte count", () => {
    // 32 bytes base64url -> 43 chars (no padding).
    expect(randomUrlToken(32)).toHaveLength(43);
  });
});
