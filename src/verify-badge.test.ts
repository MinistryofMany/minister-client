import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, type KeyLike } from "jose";
import { verifyMinisterBadge, _resetBadgeKeyCache } from "./verify-badge";
import { VcVerificationError } from "./errors";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";

// A well-formed `mnv1:` tag with a REALISTIC 43-char base64url tail (Minister
// derives base64url of a 32-byte HMAC/VOPRF output — always 43 chars). The SDK
// now length-bounds the tail, so test fixtures must use realistic lengths.
const tag = (seed: string): string => `mnv1:${seed.padEnd(43, "0").slice(0, 43)}`;

interface SignOpts {
  claims?: Record<string, unknown>;
  credentialType?: string;
  // credentialSubject.id (the holder DID).
  subject?: string;
  // The JWT `sub`; defaults to `subject`. Set independently to exercise
  // the holder-binding mismatch rejection.
  jwtSub?: string;
  // The VC issuer DID; defaults to DID. Override to test issuer rejection.
  issuerDid?: string;
  // Absolute exp (epoch seconds); defaults to 1y out; null omits exp entirely.
  exp?: number | null;
}

// Self-contained offline signer: generates an Ed25519 key, signs a
// Minister-shaped VC JWT, and exposes the matching public JWK so
// verification never touches the network.
async function makeKeyAndSigner() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  async function signVc(opts: SignOpts = {}) {
    const subject = opts.subject ?? SUB;
    const credentialType = opts.credentialType ?? "MinisterEmailDomainCredential";
    const claims = opts.claims ?? { domain: "a.com" };
    let signer = new SignJWT({
      vc: {
        type: ["VerifiableCredential", credentialType],
        credentialSubject: { id: subject, ...claims },
      },
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" })
      .setIssuer(opts.issuerDid ?? DID)
      .setSubject(opts.jwtSub ?? subject)
      .setIssuedAt();
    if (opts.exp !== null) {
      signer = signer.setExpirationTime(opts.exp ?? Math.floor(Date.now() / 1000) + 31536000);
    }
    return signer.sign(privateKey);
  }
  return { publicJwk, signVc };
}

describe("verifyMinisterBadge", () => {
  it("returns a slug-typed, schema-validated badge", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "a.com" } });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.type).toBe("email-domain");
    expect(badge.claims).toEqual({ domain: "a.com" });
    expect(badge.subject).toBe(SUB);
    expect(badge.raw).toBe(jwt);
  });

  it("rejects an unknown credential type", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { x: 1 }, credentialType: "MinisterMysteryCredential" });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects claims that fail the schema", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "not-a-domain" } });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a badge signed by a different key (bad signature)", async () => {
    const { signVc } = await makeKeyAndSigner();
    const other = await makeKeyAndSigner();
    const jwt = await signVc({});
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: other.publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a badge from a different issuer DID", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ issuerDid: "did:web:evil.test" });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a holder-binding mismatch (credentialSubject.id != sub)", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({
      subject: SUB,
      jwtSub: "did:web:ministry.test:users:someone-else",
    });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects an expired badge", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ exp: Math.floor(Date.now() / 1000) - 3600 });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a badge with no exp", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ exp: null });
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  // ---------------------------------------------------------------------------
  // Reserved coarse-issuance metadata: `credentialSubject.issuanceMonth`
  // ("YYYY-MM", UTC month of the badge's true issuance). It is issuer
  // metadata, NOT a per-type claim: surfaced as its own field, stripped
  // before per-type schema validation, and strictly format-checked.
  // ---------------------------------------------------------------------------

  it("surfaces issuanceMonth as metadata and STRIPS it from the claims", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "a.com", issuanceMonth: "2026-03" } });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.issuanceMonth).toBe("2026-03");
    // Not a claim: per-type claims stay exactly the badge facts.
    expect(badge.claims).toEqual({ domain: "a.com" });
  });

  it("keeps a STRICT per-type schema (tlsn-attestation) passing despite the reserved key", async () => {
    // TlsnAttestationClaims is .strict(): if issuanceMonth leaked into the
    // schema parse, every disclosed tlsn badge would be rejected. The strip
    // must happen before validation, like `id`.
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({
      credentialType: "MinisterTlsnAttestationCredential",
      claims: { domain: "id.me", claim: "age>=21", issuanceMonth: "2026-03" },
    });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.type).toBe("tlsn-attestation");
    expect(badge.claims).toEqual({ domain: "id.me", claim: "age>=21" });
    expect(badge.issuanceMonth).toBe("2026-03");
  });

  it("tolerates an absent issuanceMonth (legacy Minister): verifies, field undefined", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "a.com" } });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.issuanceMonth).toBeUndefined();
  });

  it("rejects a present-but-malformed issuanceMonth (nothing finer or weirder than YYYY-MM)", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    // Day precision, bad month, non-string, junk — all must fail closed:
    // a malformed bucket means issuer drift or tampering upstream of the
    // signature; never guess.
    for (const bad of ["2026-03-15", "2026-13", "2026-00", "March 2026", 202603, "", null]) {
      const jwt = await signVc({ claims: { domain: "a.com", issuanceMonth: bad } });
      await expect(
        verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
      ).rejects.toBeInstanceOf(VcVerificationError);
    }
  });

  // ---------------------------------------------------------------------------
  // Reserved per-RP Sybil nullifier: `credentialSubject.nullifier` (`mnv1:...`).
  // Issuer metadata, NOT a per-type claim: surfaced as its own field, stripped
  // BEFORE the (possibly strict) per-type schema parse, and format-checked.
  // ---------------------------------------------------------------------------

  it("surfaces the nullifier as metadata and STRIPS it from the claims", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "a.com", nullifier: tag("AbC-123_def") } });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.nullifier).toBe(tag("AbC-123_def"));
    expect(badge.claims).toEqual({ domain: "a.com" });
  });

  it("keeps a STRICT nullifier-bearing schema (account-age) passing AND exposes the value", async () => {
    // AccountAgeClaims is .strict(): if `nullifier` leaked into the schema
    // parse, every disclosed account-age badge would be rejected. The strip
    // must happen before validation, like `id`/`issuanceMonth`.
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({
      credentialType: "MinisterAccountAgeCredential",
      claims: {
        provider: "github",
        olderThanMonths: 24,
        nullifier: tag("ACCOUNT_age_tag"),
        issuanceMonth: "2026-03",
      },
    });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.type).toBe("account-age");
    expect(badge.claims).toEqual({ provider: "github", olderThanMonths: 24 });
    expect(badge.nullifier).toBe(tag("ACCOUNT_age_tag"));
    expect(badge.issuanceMonth).toBe("2026-03");
  });

  it("keeps a STRICT nullifier-bearing schema (social-following) passing AND exposes the value", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({
      credentialType: "MinisterSocialFollowingCredential",
      claims: { provider: "github", followersAtLeast: 100, nullifier: tag("SOCIAL_tag_9") },
    });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.type).toBe("social-following");
    expect(badge.claims).toEqual({ provider: "github", followersAtLeast: 100 });
    expect(badge.nullifier).toBe(tag("SOCIAL_tag_9"));
  });

  it("tolerates an absent nullifier (ref-less badge / pre-M5): verifies, field undefined", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ claims: { domain: "a.com" } });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.nullifier).toBeUndefined();
  });

  it("rejects a present-but-malformed nullifier (fails closed on issuer drift / smuggle)", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    // Missing prefix, wrong prefix, illegal chars, non-string, empty, too-short
    // (under the length bound), and UNBOUNDED-length (a compromised issuer
    // stamping an arbitrarily long tag RPs would persist) — all must fail closed
    // rather than gate on a garbage tag.
    for (const bad of [
      "deadbeef",
      "mnv2:abc",
      "mnv1:",
      "mnv1:has space",
      "mnv1:plus+slash/",
      "mnv1:tooShort", // valid charset but under the 20-char floor
      `mnv1:${"A".repeat(65)}`, // over the 64-char cap (was unbounded before)
      123,
      "",
    ]) {
      const jwt = await signVc({ claims: { domain: "a.com", nullifier: bad } });
      await expect(
        verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk }),
      ).rejects.toBeInstanceOf(VcVerificationError);
    }
  });
});

// ---------------------------------------------------------------------------
// KMS split (H1): badge keys are pinned to the DID document `assertionMethod`,
// NOT the raw JWKS. Minister's JWKS serves BOTH the badge key (#key-2) and the
// in-process token key (#key-3); a badge carrying `kid ...#key-3` would verify
// against the token key if we trusted the JWKS. did.json's assertionMethod lists
// ONLY #key-2, so a #key-3 VC (a forgery with a stolen token key) must be
// rejected on the `kid` alone — before any signature helps an attacker.
// ---------------------------------------------------------------------------
describe("verifyMinisterBadge — DID assertionMethod pinning", () => {
  const KEY2 = `${DID}#key-2`;
  const KEY3 = `${DID}#key-3`;

  async function setup() {
    const badge = await generateKeyPair("EdDSA", { extractable: true });
    const token = await generateKeyPair("EdDSA", { extractable: true });
    const badgeJwk = await exportJWK(badge.publicKey);

    // Mirror Minister's did.json: only #key-2 is a verificationMethod and the
    // sole assertionMethod entry. #key-3 lives in JWKS only, never here.
    const didDoc = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: DID,
      verificationMethod: [
        { id: KEY2, type: "JsonWebKey2020", controller: DID, publicKeyJwk: badgeJwk },
      ],
      assertionMethod: [KEY2],
      authentication: [KEY2],
    };

    const fetchMock = vi.fn(async (input: unknown) => {
      if (String(input) === `${ISSUER}/.well-known/did.json`) {
        return new Response(JSON.stringify(didDoc), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    async function sign(kid: string, key: KeyLike) {
      return new SignJWT({
        vc: {
          type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
          credentialSubject: { id: SUB, domain: "a.com" },
        },
      })
        .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt", kid })
        .setIssuer(DID)
        .setSubject(SUB)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 31536000)
        .sign(key);
    }

    return { badge, token, sign, fetchMock };
  }

  afterEach(() => {
    _resetBadgeKeyCache();
    vi.unstubAllGlobals();
  });

  it("ACCEPTS a badge signed by the assertionMethod key (#key-2)", async () => {
    const { badge, sign } = await setup();
    const jwt = await sign(KEY2, badge.privateKey);
    const verified = await verifyMinisterBadge(jwt, { issuer: ISSUER });
    expect(verified.type).toBe("email-domain");
    expect(verified.subject).toBe(SUB);
  });

  it("REJECTS a badge signed by the token key (#key-3, not in assertionMethod)", async () => {
    const { token, sign } = await setup();
    const jwt = await sign(KEY3, token.privateKey);
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("REJECTS on the kid alone: a #key-3-labelled VC signed by the real badge key still fails", async () => {
    // kid pinning, not signature strength: even a signature that WOULD verify
    // against #key-2 is refused when presented under a kid outside assertionMethod.
    const { badge, sign } = await setup();
    const jwt = await sign(KEY3, badge.privateKey);
    await expect(
      verifyMinisterBadge(jwt, { issuer: ISSUER }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });
});
