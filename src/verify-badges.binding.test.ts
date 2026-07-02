// Holder-to-login binding (MIN-1 / audit finding #5): the wrapper must bind
// each disclosed badge to the id_token sub, so a validly-signed badge minted
// for a DIFFERENT user (a borrowed credential) is rejected.
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, importJWK, SignJWT, type JWK } from "jose";
import { verifyMinisterBadges } from "./verify-badges";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const CLIENT = "client-1";
const BOUND_SUB = "pairwise-alice"; // the id_token sub for THIS login
const BORROWED_SUB = "pairwise-mallory"; // another user's pairwise sub

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);

  // A Minister-shaped, correctly self-consistent badge (iss ok, key ok,
  // credentialSubject.id === jwt sub). `pairwiseSub` chooses which login it
  // binds to via its subject `did:web:<host>:u:<pairwiseSub>`.
  const signBadge = (pairwiseSub: string, claims: Record<string, unknown> = { domain: "a.com" }) => {
    const subjectDid = `${DID}:u:${pairwiseSub}`;
    return new SignJWT({
      vc: {
        type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
        credentialSubject: { id: subjectDid, ...claims },
      },
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" })
      .setIssuer(DID)
      .setSubject(subjectDid)
      .setIssuedAt()
      .setExpirationTime("1y")
      .sign(privateKey);
  };

  const signId = (sub: string, badges: string[]) =>
    new SignJWT({ minister_badges: badges })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(ISSUER)
      .setSubject(sub)
      .setAudience(CLIENT)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

  return { publicJwk, privateKey, signBadge, signId };
}

describe("verifyMinisterBadges — holder-to-login binding", () => {
  // Property 7 — accept the correctly-bound badge.
  it("accepts a badge whose pairwise subject binds to the id_token sub", async () => {
    const { publicJwk, signBadge, signId } = await setup();
    const badge = await signBadge(BOUND_SUB);
    const idToken = await signId(BOUND_SUB, [badge]);
    const { badges, rejected } = await verifyMinisterBadges(idToken, {
      issuer: ISSUER,
      clientId: CLIENT,
      key: publicJwk,
    });
    expect(rejected).toHaveLength(0);
    expect(badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(badges[0]!.subject).toBe(`${DID}:u:${BOUND_SUB}`);
  });

  // Property 6 — reject the borrowed badge (validly signed, but bound to
  // another user's sub) presented alongside this login.
  it("rejects a validly-signed badge minted for a DIFFERENT user's sub", async () => {
    const { publicJwk, signBadge, signId } = await setup();
    const borrowed = await signBadge(BORROWED_SUB);
    const idToken = await signId(BOUND_SUB, [borrowed]); // login is alice, badge is mallory's
    const { badges, rejected } = await verifyMinisterBadges(idToken, {
      issuer: ISSUER,
      clientId: CLIENT,
      key: publicJwk,
    });
    expect(badges).toEqual([]);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.raw).toBe(borrowed);
    expect(rejected[0]!.error.message).toMatch(/bound|borrow|mismatch/i);
  });

  // The binding is per-badge, not wholesale: a bound badge alongside a borrowed
  // one keeps the bound one and drops only the borrowed one.
  it("keeps the bound badge and drops only the borrowed one", async () => {
    const { publicJwk, signBadge, signId } = await setup();
    const mine = await signBadge(BOUND_SUB, { domain: "mine.com" });
    const borrowed = await signBadge(BORROWED_SUB, { domain: "theirs.com" });
    const idToken = await signId(BOUND_SUB, [mine, borrowed]);
    const { badges, rejected } = await verifyMinisterBadges(idToken, {
      issuer: ISSUER,
      clientId: CLIENT,
      key: publicJwk,
    });
    expect(badges).toHaveLength(1);
    expect(badges[0]!.claims).toEqual({ domain: "mine.com" });
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.raw).toBe(borrowed);
  });

  // Binding also applies on the already-verified PAYLOAD path (Auth.js /
  // ministerBadgesFromProfile), which is defense-in-depth against a
  // disclosure-minimizer bug attaching the wrong user's badge.
  it("binds on the already-verified payload path too", async () => {
    const { publicJwk, signBadge } = await setup();
    const borrowed = await signBadge(BORROWED_SUB);
    const payload = { sub: BOUND_SUB, minister_badges: [borrowed] };
    const { badges, rejected } = await verifyMinisterBadges(payload, { issuer: ISSUER, key: publicJwk });
    expect(badges).toEqual([]);
    expect(rejected).toHaveLength(1);
  });

  // Fail closed: an id_token payload with no usable sub cannot bind, so every
  // badge is rejected rather than trusted unbound.
  it("rejects all badges when the payload has no usable sub (fail closed)", async () => {
    const { publicJwk, signBadge } = await setup();
    const badge = await signBadge(BOUND_SUB);
    const payload = { minister_badges: [badge] }; // no `sub`
    const { badges, rejected } = await verifyMinisterBadges(payload, { issuer: ISSUER, key: publicJwk });
    expect(badges).toEqual([]);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.error.message).toMatch(/bind|sub/i);
  });

  // The `key` option accepts a bare JWK (the widened KeyInput): an RP or test
  // hands over Minister's public key without importing it first.
  it("accepts a bare JWK as the verification key", async () => {
    const { publicJwk, signBadge, signId } = await setup();
    const badge = await signBadge(BOUND_SUB);
    const idToken = await signId(BOUND_SUB, [badge]);
    // publicJwk is a plain JWK object — the SDK imports it internally.
    const jwk: JWK = publicJwk;
    const { badges, rejected } = await verifyMinisterBadges(idToken, {
      issuer: ISSUER,
      clientId: CLIENT,
      key: jwk,
    });
    expect(rejected).toHaveLength(0);
    expect(badges).toHaveLength(1);
  });

  // ...and a pre-imported KeyLike still works (the passthrough branch).
  it("accepts a pre-imported KeyLike as the verification key", async () => {
    const { publicJwk, signBadge, signId } = await setup();
    const keyLike = await importJWK(publicJwk, "EdDSA");
    const badge = await signBadge(BOUND_SUB);
    const idToken = await signId(BOUND_SUB, [badge]);
    const { badges, rejected } = await verifyMinisterBadges(idToken, {
      issuer: ISSUER,
      clientId: CLIENT,
      key: keyLike,
    });
    expect(rejected).toHaveLength(0);
    expect(badges).toHaveLength(1);
  });
});
