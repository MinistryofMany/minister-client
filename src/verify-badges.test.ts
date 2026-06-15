// src/verify-badges.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterBadges } from "./verify-badges";
import { MinisterTokenError } from "./errors";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";
const CLIENT = "client-1";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  const signVc = (claims: Record<string, unknown>, ct: string) =>
    new SignJWT({ vc: { type: ["VerifiableCredential", ct], credentialSubject: { id: SUB, ...claims } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB).sign(privateKey);
  const signId = (over: Record<string, unknown> = {}) =>
    new SignJWT(over)
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(ISSUER).setSubject("pairwise").setAudience(CLIENT).setExpirationTime("5m").sign(privateKey);
  return { publicJwk, signVc, signId };
}

describe("verifyMinisterBadges", () => {
  it("splits valid and invalid badges from an already-verified payload", async () => {
    const { publicJwk, signVc } = await setup();
    const good = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const bad = await signVc({ domain: "not-a-domain" }, "MinisterEmailDomainCredential");
    const payload = { sub: SUB, minister_badges: [good, bad] };
    const result = await verifyMinisterBadges(payload, { issuer: ISSUER, key: publicJwk });
    expect(result.badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.raw).toBe(bad);
  });

  it("returns empty lists when there are no badges", async () => {
    const { publicJwk } = await setup();
    const result = await verifyMinisterBadges({ sub: SUB }, { issuer: ISSUER, key: publicJwk });
    expect(result).toEqual({ badges: [], rejected: [] });
  });

  it("verifies the id_token wrapper first when given a raw token string", async () => {
    const { publicJwk, signVc, signId } = await setup();
    const good = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const idToken = await signId({ minister_badges: [good] });
    const result = await verifyMinisterBadges(idToken, { issuer: ISSUER, clientId: CLIENT, key: publicJwk });
    expect(result.badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(result.rejected).toHaveLength(0);
  });

  it("hard-fails (throws) when the raw id_token wrapper is invalid", async () => {
    const { publicJwk, signId } = await setup();
    const idToken = await signId({ minister_badges: [] });
    // Wrong clientId -> audience mismatch -> the wrapper verification throws.
    await expect(
      verifyMinisterBadges(idToken, { issuer: ISSUER, clientId: "wrong", key: publicJwk }),
    ).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("rejects a non-array minister_badges claim", async () => {
    const { publicJwk } = await setup();
    const result = await verifyMinisterBadges(
      { sub: SUB, minister_badges: "not-an-array" },
      { issuer: ISSUER, key: publicJwk },
    );
    expect(result.badges).toEqual([]);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.raw).toBe("not-an-array");
  });

  it("rejects a non-string badge entry", async () => {
    const { publicJwk } = await setup();
    const result = await verifyMinisterBadges(
      { sub: SUB, minister_badges: [123] },
      { issuer: ISSUER, key: publicJwk },
    );
    expect(result.badges).toEqual([]);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.raw).toBe("123");
  });
});
