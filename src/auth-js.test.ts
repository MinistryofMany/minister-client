// src/auth-js.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { ministerProvider, ministerBadgesFromProfile } from "./auth-js";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";

describe("auth-js adapter", () => {
  it("ministerProvider returns an oidc provider config with the requested scopes", () => {
    const p = ministerProvider({ clientId: "c", clientSecret: "s", issuer: ISSUER, scopes: ["openid", "badge:age-over-18"] });
    expect(p.id).toBe("minister");
    expect(p.type).toBe("oidc");
    expect(p.issuer).toBe(ISSUER);
    expect(p.authorization).toMatchObject({ params: { scope: "openid badge:age-over-18" } });
    expect(p.checks).toEqual(expect.arrayContaining(["pkce", "state", "nonce"]));
  });
  it("defaults scopes to openid profile when none are given", () => {
    const p = ministerProvider({ clientId: "c", issuer: ISSUER });
    expect(p.authorization).toMatchObject({ params: { scope: "openid profile" } });
  });
  it("ministerBadgesFromProfile verifies badges from a profile payload", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const publicJwk = await exportJWK(publicKey);
    const vc = await new SignJWT({ vc: { type: ["VerifiableCredential", "MinisterEmailDomainCredential"], credentialSubject: { id: SUB, domain: "a.com" } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB).sign(privateKey);
    const profile = { sub: SUB, minister_badges: [vc] };
    const { badges } = await ministerBadgesFromProfile(profile, { issuer: ISSUER, key: publicJwk });
    expect(badges.map((b) => b.type)).toEqual(["email-domain"]);
  });
});
