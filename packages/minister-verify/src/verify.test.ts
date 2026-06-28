import { describe, it, expect } from "vitest";
import { createLocalJWKSet } from "jose";
import { makeVerifier, type RejectedBadgesReport } from "./verify.js";
import { jwks, signIdToken, MOCK_ISSUER, MOCK_CLIENT_ID } from "./test/mock-issuer.js";

const verify = makeVerifier({
  issuer: MOCK_ISSUER,
  audience: MOCK_CLIENT_ID,
  // Injecting the mock JWKS keeps verification offline. The SDK applies this
  // same key to the id_token wrapper AND the badge VCs, and derives the
  // expected VC issuer DID (did:web:mock.minister) from MOCK_ISSUER's host.
  jwks: createLocalJWKSet(await jwks()),
});

describe("makeVerifier (mock issuer)", () => {
  it("verifies a token and extracts verified badges", async () => {
    const idToken = await signIdToken({
      sub: "pairwise-abc",
      badges: [{ type: "email-domain", attributes: { domain: "acme.com" } }],
    });
    const result = await verify(idToken);
    expect(result.sub).toBe("pairwise-abc");
    expect(result.badges).toEqual([
      expect.objectContaining({ type: "email-domain", attributes: { domain: "acme.com" } }),
    ]);
    // issuedAt is recovered from the verified VC's raw payload `iat`.
    expect(typeof result.badges[0]!.issuedAt).toBe("number");
    expect(result.badges[0]!.issuedAt).toBeGreaterThan(0);
  });

  it("rejects a wrong audience", async () => {
    const idToken = await signIdToken({ sub: "s", aud: "someone-else" });
    await expect(verify(idToken)).rejects.toThrow();
  });

  it("rejects a wrong issuer", async () => {
    const idToken = await signIdToken({ sub: "s", issuer: "https://evil" });
    await expect(verify(idToken)).rejects.toThrow();
  });

  it("refuses to construct without an audience (fail-closed aud check)", () => {
    // The SDK only enforces `aud` when its clientId is truthy; an empty audience
    // would silently accept a token minted for any RP. makeVerifier must refuse.
    expect(() => makeVerifier({ issuer: MOCK_ISSUER, audience: "" })).toThrow(/audience/i);
  });

  it("drops a badge whose VC issuer does not match the OIDC issuer host", async () => {
    // The wrapper is valid, but the badge VC is stamped with a different
    // `iss`. The SDK expects did:web:mock.minister (derived from MOCK_ISSUER),
    // so the mismatched badge lands in `rejected` and is absent from results.
    // Login still succeeds.
    const idToken = await signIdToken({
      sub: "s",
      badges: [
        { type: "email-domain", attributes: { domain: "a.com" }, vcIssuer: "did:web:other" },
      ],
    });
    const result = await verify(idToken);
    expect(result.sub).toBe("s");
    expect(result.badges).toEqual([]);
  });

  it("returns an empty badge set when none are disclosed", async () => {
    const idToken = await signIdToken({ sub: "s" });
    expect((await verify(idToken)).badges).toEqual([]);
  });

  it("drops an expired VC but still verifies the identity", async () => {
    // The SDK never throws on a bad badge: the expired VC lands in `rejected`,
    // so login succeeds with no usable badges (fails closed for gating).
    const idToken = await signIdToken({
      sub: "s",
      badges: [{ type: "email-domain", attributes: { domain: "a.com" }, expired: true }],
    });
    const result = await verify(idToken);
    expect(result.sub).toBe("s");
    expect(result.badges).toEqual([]);
  });

  it("reports rejected badges via onRejectedBadges with a SAFE summary only", async () => {
    const reports: RejectedBadgesReport[] = [];
    const verifyWithHook = makeVerifier({
      issuer: MOCK_ISSUER,
      audience: MOCK_CLIENT_ID,
      jwks: createLocalJWKSet(await jwks()),
      onRejectedBadges: (r) => reports.push(r),
    });
    const idToken = await signIdToken({
      sub: "pairwise-xyz",
      badges: [
        { type: "email-domain", attributes: { domain: "a.com" }, vcIssuer: "did:web:other" },
      ],
    });
    const result = await verifyWithHook(idToken);
    expect(result.badges).toEqual([]);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.sub).toBe("pairwise-xyz");
    expect(reports[0]!.rejectedCount).toBe(1);
    expect(reports[0]!.rejectedReasons).toHaveLength(1);
    // The report carries no raw VC JWT - only a summary string.
    expect(JSON.stringify(reports[0])).not.toContain("eyJ");
  });

  it("does not invoke onRejectedBadges when all badges verify", async () => {
    let called = false;
    const verifyWithHook = makeVerifier({
      issuer: MOCK_ISSUER,
      audience: MOCK_CLIENT_ID,
      jwks: createLocalJWKSet(await jwks()),
      onRejectedBadges: () => {
        called = true;
      },
    });
    const idToken = await signIdToken({
      sub: "s",
      badges: [{ type: "email-domain", attributes: { domain: "acme.com" } }],
    });
    await verifyWithHook(idToken);
    expect(called).toBe(false);
  });
});
