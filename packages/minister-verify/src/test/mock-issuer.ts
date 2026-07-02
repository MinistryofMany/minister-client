import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

const KID = "did:web:mock.minister#key-1";
export const MOCK_VC_ISSUER = "did:web:mock.minister";
export const MOCK_ISSUER = "https://mock.minister";
export const MOCK_CLIENT_ID = "minister_verify_test";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

export async function jwks(): Promise<{ keys: JWK[] }> {
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, alg: "EdDSA", use: "sig", kid: KID }] };
}

export interface MockBadge {
  type: string;
  attributes: Record<string, string | number | boolean>;
  /**
   * The badge's TRUE issuance instant (unix seconds). Mirrors the real
   * Minister disclosure shape: the VC's `iat` is ALWAYS the disclosure
   * instant (MIN-1 re-stamps it), and the only issuance-derived residue is
   * the coarse `credentialSubject.issuanceMonth` bucket ("YYYY-MM", UTC)
   * computed from this value. Defaults to now.
   */
  issuedAtSec?: number;
  /**
   * Convenience: true issuance N days ago (`issuedAtSec = now - N days`).
   * Ignored when `issuedAtSec` is set. Note this backdates ONLY the coarse
   * issuanceMonth claim — never the `iat`, which the real Minister always
   * stamps at disclosure time.
   */
  ageDays?: number;
  /**
   * Omit the issuanceMonth claim entirely — the shape a pre-upgrade
   * ("legacy") Minister discloses. Verifiers must fail CLOSED on maxAgeDays
   * for such badges.
   */
  omitIssuanceMonth?: boolean;
  expired?: boolean;
  /**
   * Override the VC `iss` (and the matching holder-DID prefix). Still signed
   * by the mock key, so the signature verifies against the JWKS, but the SDK
   * derives the expected DID from the OIDC issuer host and rejects any badge
   * whose `iss` differs - it lands in `rejected`. Defaults to MOCK_VC_ISSUER,
   * which equals didFromIssuer(MOCK_ISSUER).
   */
  vcIssuer?: string;
  /**
   * Override the pairwise sub baked into the badge subject, independently of
   * the id_token's sub. Post-MIN-1 the wrapper binds a badge to the login by
   * requiring `subject === did:web:<host>:u:<id_token sub>`, so a badge minted
   * with a DIFFERENT sub here simulates a borrowed/mismatched credential and
   * must land in `rejected`. Defaults to the id_token's sub (a correctly-bound
   * badge).
   */
  subOverride?: string;
}

function badgeTypeToCredType(type: string): string {
  const pascal = type
    .split("-")
    .map((p) => p[0]!.toUpperCase() + p.slice(1))
    .join("");
  return `Minister${pascal}Credential`;
}

// The UTC calendar month ("YYYY-MM") containing `sec` — Minister's bucket
// function for the coarse `issuanceMonth` disclosure claim.
export function issuanceMonthOf(sec: number): string {
  return new Date(sec * 1000).toISOString().slice(0, 7);
}

// Mirrors Minister's re-mint-at-disclosure shape: the badge subject is the
// per-RP PAIRWISE DID `did:web:<host>:u:<sub>` (the SAME sub the id_token
// carries), the jti is a per-RP value driven by that sub — never a stable
// cross-RP identifier — and `iat` is ALWAYS the disclosure instant. The only
// issuance-derived field is the coarse `issuanceMonth` credentialSubject
// claim (from the badge's true issuance instant), exactly what the real
// re-mint emits.
async function signVc(idTokenSub: string, badge: MockBadge): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  // Post-MIN-1 fidelity: iat is DISCLOSURE-stamped, never issuance-derived.
  const iatSec = badge.expired ? nowSec - 120 : nowSec;
  const issuedAtSec = badge.issuedAtSec ?? nowSec - (badge.ageDays ?? 0) * 86_400;
  const vcIssuer = badge.vcIssuer ?? MOCK_VC_ISSUER;
  const sub = badge.subOverride ?? idTokenSub;
  const subjectId = `${vcIssuer}:u:${sub}`;
  const builder = new SignJWT({
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", badgeTypeToCredType(badge.type)],
      credentialSubject: {
        id: subjectId,
        ...badge.attributes,
        ...(badge.omitIssuanceMonth ? {} : { issuanceMonth: issuanceMonthOf(issuedAtSec) }),
      },
    },
  })
    .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "vc+jwt" })
    .setIssuer(vcIssuer)
    .setSubject(subjectId)
    .setJti(`mock-pairwise-jti:${sub}:${badge.type}`)
    .setIssuedAt(iatSec)
    // Presentation-shaped, like the real re-mint (1h disclosure TTL).
    .setExpirationTime(badge.expired ? nowSec - 60 : nowSec + 3_600);
  return builder.sign(privateKey);
}

export async function signIdToken(opts: {
  sub: string;
  badges?: MockBadge[];
  aud?: string;
  issuer?: string;
  nonce?: string;
}): Promise<string> {
  const minister_badges = await Promise.all((opts.badges ?? []).map((b) => signVc(opts.sub, b)));
  return new SignJWT({ nonce: opts.nonce ?? "n", minister_badges })
    .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "JWT" })
    .setIssuer(opts.issuer ?? MOCK_ISSUER)
    .setSubject(opts.sub)
    .setAudience(opts.aud ?? MOCK_CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}
