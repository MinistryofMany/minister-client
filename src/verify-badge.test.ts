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
  // Absolute `exp` (epoch seconds); omitted when undefined.
  exp?: number;
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
    if (opts.exp !== undefined) signer = signer.setExpirationTime(opts.exp);
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
});
