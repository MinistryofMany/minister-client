import { describe, it, expect } from "vitest";
import { createLocalJWKSet } from "jose";
import { evaluate, type PolicyNode } from "@ministryofmany/policy";
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

  it("passes through the verified sybil_bucket, preserving 0 and omitting out-of-range/absent", async () => {
    expect((await verify(await signIdToken({ sub: "s", sybil_bucket: 3 }))).sybil_bucket).toBe(3);
    // 0 is a real bucket and must not be dropped.
    expect((await verify(await signIdToken({ sub: "s", sybil_bucket: 0 }))).sybil_bucket).toBe(0);
    // The SDK range-validates (0-4); an out-of-range value is dropped upstream.
    expect(
      (await verify(await signIdToken({ sub: "s", sybil_bucket: 9 }))).sybil_bucket,
    ).toBeUndefined();
    // Absent when the scope was not granted / not disclosed.
    expect((await verify(await signIdToken({ sub: "s" }))).sybil_bucket).toBeUndefined();
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

  // -------------------------------------------------------------------------
  // RP-side freshness (`maxAgeDays`) via the coarse `issuanceMonth` claim.
  //
  // MIN-1 made every disclosed VC's `iat` the DISCLOSURE instant, so deriving
  // `issuedAt` from it let every badge through any maxAgeDays gate ("seconds
  // old"). The verifier must instead derive `issuedAt` from the coarse
  // issuance bucket Minister now discloses (`credentialSubject.issuanceMonth`,
  // "YYYY-MM" UTC), mapped to the bucket START — so the computed age is always
  // ≥ the true age and a stale badge can never pass (fail-closed direction).
  // -------------------------------------------------------------------------

  it("REJECTS a badge older than a maxAgeDays window (was vacuously accepted pre-fix)", async () => {
    // True issuance ~120 days ago; its month bucket starts 120-151 days ago.
    // The mock stamps iat = disclosure NOW (real Minister shape), so an
    // iat-derived issuedAt would sail through this gate — the adversary's
    // stale-badge replay.
    const idToken = await signIdToken({
      sub: "s",
      badges: [{ type: "email-domain", attributes: { domain: "acme.com" }, ageDays: 120 }],
    });
    const { badges } = await verify(idToken);
    expect(badges).toHaveLength(1); // verification passes; the POLICY gate must reject
    const policy: PolicyNode = { badge: { type: "email-domain", maxAgeDays: 45 } };
    expect(evaluate(policy, badges, Math.floor(Date.now() / 1000))).toBe(false);
  });

  it("ACCEPTS a badge within the maxAgeDays window", async () => {
    // Issued this month: bucket start is at most ~31 days ago, well inside 45.
    const idToken = await signIdToken({
      sub: "s",
      badges: [{ type: "email-domain", attributes: { domain: "acme.com" }, ageDays: 0 }],
    });
    const { badges } = await verify(idToken);
    const policy: PolicyNode = { badge: { type: "email-domain", maxAgeDays: 45 } };
    expect(evaluate(policy, badges, Math.floor(Date.now() / 1000))).toBe(true);
  });

  it("derives issuedAt as the issuance-month START, never the disclosure-time iat", async () => {
    // Fixed true issuance instant mid-month: the derived issuedAt must be the
    // first UTC second of that month — sub-month precision is intentionally
    // lost, and the disclosure-time iat (≈ now) must play no part.
    const trueIssuance = Date.UTC(2026, 2, 17, 13, 37, 42) / 1000; // 2026-03-17
    const idToken = await signIdToken({
      sub: "s",
      badges: [
        { type: "email-domain", attributes: { domain: "acme.com" }, issuedAtSec: trueIssuance },
      ],
    });
    const { badges } = await verify(idToken);
    expect(badges[0]!.issuedAt).toBe(Date.UTC(2026, 2, 1) / 1000);
    expect(badges[0]!.issuedAt).not.toBe(trueIssuance);
    // Nowhere near "seconds old" — the pre-fix vacuous value.
    expect(Math.floor(Date.now() / 1000) - badges[0]!.issuedAt).toBeGreaterThan(45 * 86_400);
  });

  it("two RPs receiving the same badge see the SAME coarse bucket (and it is only a bucket)", async () => {
    // The claim is deliberately cross-RP-stable — it is a shared-by-many
    // cohort value, not a pairwise field. Same true issuance instant, two
    // different RPs (audience + pairwise sub differ): identical issuedAt.
    const trueIssuance = Date.UTC(2026, 2, 9, 4, 5, 6) / 1000;
    const verifyB = makeVerifier({
      issuer: MOCK_ISSUER,
      audience: "another-rp",
      jwks: createLocalJWKSet(await jwks()),
    });
    const tokenA = await signIdToken({
      sub: "pairwise-at-A",
      badges: [{ type: "email-domain", attributes: { domain: "x.com" }, issuedAtSec: trueIssuance }],
    });
    const tokenB = await signIdToken({
      sub: "pairwise-at-B",
      aud: "another-rp",
      badges: [{ type: "email-domain", attributes: { domain: "x.com" }, issuedAtSec: trueIssuance }],
    });
    const a = await verify(tokenA);
    const b = await verifyB(tokenB);
    // Pairwise identity differs across the RPs...
    expect(a.sub).not.toBe(b.sub);
    // ...the coarse freshness field does not (same bucket start)...
    expect(a.badges[0]!.issuedAt).toBe(b.badges[0]!.issuedAt);
    // ...and it is the BUCKET, not the instant (coarse by construction).
    expect(a.badges[0]!.issuedAt).toBe(Date.UTC(2026, 2, 1) / 1000);
  });

  it("badges issued at different instants in the same month are indistinguishable on the freshness field", async () => {
    // Correlation bound within a bucket: the field has zero resolving power
    // between two badges (different users, different days/hours) issued in
    // the same UTC month.
    const early = Date.UTC(2026, 4, 1, 0, 0, 1) / 1000;
    const late = Date.UTC(2026, 4, 31, 23, 59, 58) / 1000;
    const t1 = await signIdToken({
      sub: "user-one-sub",
      badges: [{ type: "email-domain", attributes: { domain: "a.com" }, issuedAtSec: early }],
    });
    const t2 = await signIdToken({
      sub: "user-two-sub",
      badges: [{ type: "email-domain", attributes: { domain: "a.com" }, issuedAtSec: late }],
    });
    const r1 = await verify(t1);
    const r2 = await verify(t2);
    expect(r1.badges[0]!.issuedAt).toBe(r2.badges[0]!.issuedAt);
  });

  it("fails CLOSED on maxAgeDays for a legacy badge with no issuanceMonth claim", async () => {
    const idToken = await signIdToken({
      sub: "s",
      badges: [
        {
          type: "email-domain",
          attributes: { domain: "acme.com" },
          omitIssuanceMonth: true,
        },
      ],
    });
    const { badges } = await verify(idToken);
    expect(badges).toHaveLength(1); // still a valid badge...
    const now = Math.floor(Date.now() / 1000);
    // ...but with NO freshness evidence it satisfies no maxAgeDays leaf,
    const gated: PolicyNode = { badge: { type: "email-domain", maxAgeDays: 3650 } };
    expect(evaluate(gated, badges, now)).toBe(false);
    // while an age-less leaf is unaffected.
    const ungated: PolicyNode = { badge: { type: "email-domain" } };
    expect(evaluate(ungated, badges, now)).toBe(true);
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
