// src/verifier.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { createMinisterVerifier } from "./verifier";
import { MinisterTokenError } from "./errors";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const CLIENT = "client-1";
const SUB = "did:web:ministry.test:users:u1";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  const signVc = (claims: Record<string, unknown>, ct: string) =>
    new SignJWT({ vc: { type: ["VerifiableCredential", ct], credentialSubject: { id: SUB, ...claims } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB)
      .setIssuedAt().setExpirationTime("1y").sign(privateKey);
  const signId = (over: Record<string, unknown> = {}) =>
    new SignJWT(over).setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(ISSUER).setSubject("pairwise").setAudience(CLIENT).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  return { publicJwk, signVc, signId };
}

describe("createMinisterVerifier", () => {
  it("verifies an id_token and its badges with one configured instance", async () => {
    const { publicJwk, signVc, signId } = await setup();
    const badge = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const idToken = await signId({ name: "Ada", minister_badges: [badge] });
    const verifier = createMinisterVerifier({ issuer: ISSUER, clientId: CLIENT, jwks: publicJwk });

    const claims = await verifier.verifyIdToken(idToken);
    expect(claims.sub).toBe("pairwise");

    const { badges, rejected } = await verifier.verifyBadges(idToken);
    expect(badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(rejected).toHaveLength(0);
  });

  it("forwards the configured clientId so a wrong audience is rejected", async () => {
    const { publicJwk, signId } = await setup();
    const idToken = await signId({ name: "Ada" }); // aud: CLIENT
    const verifier = createMinisterVerifier({ issuer: ISSUER, clientId: "other", jwks: publicJwk });
    await expect(verifier.verifyIdToken(idToken)).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("verifies a standalone badge via verifyBadge", async () => {
    const { publicJwk, signVc } = await setup();
    const badge = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const verifier = createMinisterVerifier({ issuer: ISSUER, clientId: CLIENT, jwks: publicJwk });
    const result = await verifier.verifyBadge(badge);
    expect(result.type).toBe("email-domain");
    expect(result.subject).toBe(SUB);
  });
});
