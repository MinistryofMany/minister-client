import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterBadge } from "./verify-badge";
import { VcVerificationError } from "./errors";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";

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
});
