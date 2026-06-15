import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MinisterTokenError, OidcError } from "./errors";
import { OidcCore, _resetOidcCaches } from "./oidc";
import {
  localJwks,
  makeKeys,
  signIdToken,
  signVc,
  type TestKeys,
} from "./test-helpers";

const ISSUER = "https://ministry.id";
const ISSUER_DID = "did:web:ministry.id";
const CLIENT_ID = "rp-client-123";
const REDIRECT_URI = "https://app.example/callback";

const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oidc/authorize`,
  token_endpoint: `${ISSUER}/oidc/token`,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
};

function makeCore() {
  return new OidcCore({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: "shh",
    redirectUri: REDIRECT_URI,
  });
}

// Mock only the network: discovery + token endpoint. Verification uses
// injected keys, so no JWKS fetch occurs.
function mockFetch(opts: { tokenResponse?: unknown; tokenStatus?: number }) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify(DISCOVERY), { status: 200 });
    }
    if (url.endsWith("/oidc/token")) {
      return new Response(JSON.stringify(opts.tokenResponse ?? {}), {
        status: opts.tokenStatus ?? 200,
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
}

describe("OidcCore.getAuthorizationUrl", () => {
  beforeEach(() => {
    _resetOidcCaches();
    vi.stubGlobal("fetch", mockFetch({}));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("builds an auth URL with the requested scopes, state, nonce and S256", async () => {
    const url = new URL(
      await makeCore().getAuthorizationUrl({
        scopes: ["openid", "profile", "badge:age-over-21"],
        state: "the-state",
        nonce: "the-nonce",
        codeChallenge: "the-challenge",
      }),
    );

    expect(url.origin + url.pathname).toBe(`${ISSUER}/oidc/authorize`);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("scope")).toBe(
      "openid profile badge:age-over-21",
    );
    expect(url.searchParams.get("state")).toBe("the-state");
    expect(url.searchParams.get("nonce")).toBe("the-nonce");
    expect(url.searchParams.get("code_challenge")).toBe("the-challenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("rejects an empty scope list", async () => {
    await expect(
      makeCore().getAuthorizationUrl({
        scopes: [],
        state: "s",
        nonce: "n",
        codeChallenge: "c",
      }),
    ).rejects.toBeInstanceOf(OidcError);
  });
});

describe("OidcCore.exchangeCode", () => {
  let keys: TestKeys;
  const NONCE = "expected-nonce";

  beforeEach(async () => {
    keys = await makeKeys();
    _resetOidcCaches();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function run(
    idToken: string,
    expectedNonce = NONCE,
  ) {
    vi.stubGlobal(
      "fetch",
      mockFetch({ tokenResponse: { id_token: idToken } }),
    );
    return makeCore().exchangeCode({
      code: "auth-code",
      codeVerifier: "verifier",
      expectedNonce,
      idTokenKey: localJwks(keys.publicKey),
      badgeKey: keys.publicKey,
    });
  }

  it("returns verified claims and badges", async () => {
    const badgeJwt = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: "did:web:ministry.id:users:alice",
      type: ["VerifiableCredential", "MinisterAgeOver21Credential"],
      claims: { threshold: 21 },
    });
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: ISSUER,
      audience: CLIENT_ID,
      nonce: NONCE,
      name: "Alice",
      picture: "https://img/alice.png",
      ministerBadges: [badgeJwt],
    });

    const result = await run(idToken);
    expect(result.claims).toEqual({
      sub: "pairwise-subject-123",
      name: "Alice",
      picture: "https://img/alice.png",
      raw: idToken,
    });
    expect(result.badges).toHaveLength(1);
    expect(result.badges[0]!.claims).toEqual({ threshold: 21 });
    expect(result.badges[0]!.type).toBe("age-over-21");
    expect(result.rejected).toEqual([]);
  });

  it("returns an empty badge list when minister_badges is absent", async () => {
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: ISSUER,
      audience: CLIENT_ID,
      nonce: NONCE,
    });
    const result = await run(idToken);
    expect(result.badges).toEqual([]);
  });

  it("rejects a bad nonce", async () => {
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: ISSUER,
      audience: CLIENT_ID,
      nonce: "attacker-nonce",
    });
    await expect(run(idToken)).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("rejects a wrong audience", async () => {
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: ISSUER,
      audience: "some-other-client",
      nonce: NONCE,
    });
    await expect(run(idToken)).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("rejects a wrong issuer", async () => {
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: "https://evil.example",
      audience: CLIENT_ID,
      nonce: NONCE,
    });
    await expect(run(idToken)).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("rejects an id_token signed by the wrong key", async () => {
    const attacker = await makeKeys();
    const idToken = await signIdToken({
      privateKey: attacker.privateKey,
      issuer: ISSUER,
      audience: CLIENT_ID,
      nonce: NONCE,
    });
    await expect(run(idToken)).rejects.toBeInstanceOf(MinisterTokenError);
  });

  it("rejects a token response missing id_token", async () => {
    vi.stubGlobal("fetch", mockFetch({ tokenResponse: {} }));
    await expect(
      makeCore().exchangeCode({
        code: "c",
        codeVerifier: "v",
        expectedNonce: NONCE,
        idTokenKey: localJwks(keys.publicKey),
        badgeKey: keys.publicKey,
      }),
    ).rejects.toThrow(/missing id_token/u);
  });

  it("rejects a failed token exchange", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch({ tokenStatus: 400, tokenResponse: { error: "invalid_grant" } }),
    );
    await expect(
      makeCore().exchangeCode({
        code: "c",
        codeVerifier: "v",
        expectedNonce: NONCE,
        idTokenKey: localJwks(keys.publicKey),
        badgeKey: keys.publicKey,
      }),
    ).rejects.toThrow(/token exchange failed/u);
  });

  it("rejects a badge with a holder-binding mismatch", async () => {
    const badBadge = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: "did:web:ministry.id:users:alice",
      subOverride: "did:web:ministry.id:users:mallory",
    });
    const idToken = await signIdToken({
      privateKey: keys.privateKey,
      issuer: ISSUER,
      audience: CLIENT_ID,
      nonce: NONCE,
      ministerBadges: [badBadge],
    });
    const result = await run(idToken);
    expect(result.badges).toEqual([]);
    expect(result.rejected).toHaveLength(1);
  });
});
