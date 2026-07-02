// src/verify-id-token.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterIdToken } from "./verify-id-token";
import { MinisterTokenError } from "./errors";

const ISSUER = "https://ministry.test";
const CLIENT = "client-1";

interface IdOpts {
  over?: Record<string, unknown>;
  aud?: string;
  issuer?: string;
  sub?: string | null; // null => omit subject
  exp?: number | string | null; // defaults to "5m"; null omits exp
}

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  async function signId(opts: IdOpts = {}) {
    let signer = new SignJWT({ name: "Ada", picture: "p", ...(opts.over ?? {}) })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(opts.issuer ?? ISSUER)
      .setAudience(opts.aud ?? CLIENT)
      .setIssuedAt();
    if (opts.sub !== null) signer = signer.setSubject(opts.sub ?? "pairwise-sub");
    if (opts.exp !== null) signer = signer.setExpirationTime(opts.exp ?? "5m");
    return signer.sign(privateKey);
  }
  return { publicJwk, signId };
}

describe("verifyMinisterIdToken", () => {
  it("returns claims for a valid token", async () => {
    const { publicJwk, signId } = await setup();
    const claims = await verifyMinisterIdToken(await signId(), { issuer: ISSUER, clientId: CLIENT, key: publicJwk });
    expect(claims.sub).toBe("pairwise-sub");
    expect(claims.name).toBe("Ada");
    expect(claims.picture).toBe("p");
    expect(claims.raw).toBeTypeOf("string");
  });
  it("rejects a wrong audience when clientId is set", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ aud: "other" }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("fails closed: an empty clientId throws instead of skipping the audience check", async () => {
    // Finding #5: a verifier built without an expected audience must NOT
    // silently accept a token minted for another RP. Even a valid token for
    // CLIENT is refused when no audience is provided.
    const { publicJwk, signId } = await setup();
    await expect(
      verifyMinisterIdToken(await signId(), { issuer: ISSUER, clientId: "", key: publicJwk }),
    ).rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("fails closed: a token for another RP is rejected rather than accepted audience-free", async () => {
    // The cross-RP impersonation the old fail-open path allowed: RP-A's token
    // replayed to RP-B. With clientId now mandatory, it is rejected.
    const { publicJwk, signId } = await setup();
    const tokenForOtherRp = await signId({ aud: "rp-a" });
    await expect(
      verifyMinisterIdToken(tokenForOtherRp, { issuer: ISSUER, clientId: "rp-b", key: publicJwk }),
    ).rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a wrong nonce", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ over: { nonce: "a" } }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk, nonce: "b" }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("accepts a matching nonce", async () => {
    const { publicJwk, signId } = await setup();
    const claims = await verifyMinisterIdToken(await signId({ over: { nonce: "abc" } }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk, nonce: "abc" });
    expect(claims.sub).toBe("pairwise-sub");
  });
  it("rejects a wrong issuer", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ issuer: "https://evil.test" }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a bad signature", async () => {
    const { signId } = await setup();
    const other = await setup();
    await expect(verifyMinisterIdToken(await signId(), { issuer: ISSUER, clientId: CLIENT, key: other.publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects an expired token", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ exp: Math.floor(Date.now() / 1000) - 3600 }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a token missing sub", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ sub: null }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a token with no exp", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ exp: null }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a non-EdDSA (HS256) token", async () => {
    const { publicJwk } = await setup();
    const hs = await new SignJWT({ name: "Ada" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setIssuer(ISSUER).setSubject("pairwise-sub").setAudience(CLIENT).setIssuedAt().setExpirationTime("5m")
      .sign(new TextEncoder().encode("a-shared-secret-of-sufficient-length-000"));
    await expect(verifyMinisterIdToken(hs, { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
});
