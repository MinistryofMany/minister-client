import { badgeTypeOf, getBadgeClaimSchema } from "./badges/helpers";
import { didFromIssuer } from "./did";
import { assertionResolverFor, _resetAssertionCache } from "./did-assertion";
import { verifyJwt } from "./jwt";
import { VcVerificationError } from "./errors";
import { parseCredentialStatus, type BadgeStatusRef } from "./status-list";
import type { KeyInput, MinisterGatingNullifier, VerifiedBadge } from "./types";

// The disclosed per-RP Sybil nullifier is version-prefixed `mnv1:` followed by
// base64url. Strictly format-checked; a malformed value fails the badge closed.
// LENGTH-BOUNDED: Minister derives the tag as base64url of a 32-byte HMAC/VOPRF
// output — exactly 43 chars (Minister's own signet trust boundary pins {43}).
// The value is issuer-signed, so this is defense-in-depth: a bounded tail keeps
// a buggy/compromised issuer from stamping an arbitrarily long tag that RPs then
// persist in ban/dedup tables. The window is generous (20..64) rather than a
// hard {43} so a future same-shape construction is not brittle; a genuinely new
// wire shape versions behind `mnv2` and gets its own check.
const NULLIFIER_RE = /^mnv1:[A-Za-z0-9_-]{20,64}$/;

// Verify a Minister-issued verifiable credential against Minister's PUBLIC badge
// key. Unlike `@ministryofmany/vc`'s `verifyVc` (which threads a full Issuer
// carrying the private key), an RP only ever holds public material.
//
// Badge keys are pinned to the issuer's DID document `assertionMethod` — NOT the
// raw JWKS (see did-assertion.ts for the full KMS-split rationale). The token key
// (#key-3) is never in `assertionMethod`, so it can never attest a badge.

export interface VerifyBadgeOptions {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // Inject the verification key. Defaults to the issuer's DID assertionMethod
  // key set (kid-pinned to #key-2). Pass a public JWK in tests so verification
  // never touches the network.
  key?: KeyInput;
}

// Verify a received VC JWT (standalone).
//
// Beyond `@ministryofmany/vc`'s structural checks, this asserts the VC-INTERNAL
// invariant `credentialSubject.id === payload.sub` — that the claims are bound
// to the subject the issuer signed them for. It does NOT (and cannot) bind the
// badge to any LOGIN: there is no id_token here, so nothing ties this VC to the
// user in front of you. A valid Minister badge belonging to some OTHER user
// (e.g. one received via a share link) verifies successfully. Treating a
// standalone `verifyMinisterBadge` success as "the current user holds this
// badge" is an authorization bug.
//
// The holder-to-login binding lives in the wrapper (`verifyMinisterBadges`),
// which requires `subject === did:web:<host>:u:<id_token sub>`. Use the wrapper
// for any access decision; use this only to certify issuance of an out-of-band
// VC.
export async function verifyMinisterBadge(
  vcJwt: string,
  options: VerifyBadgeOptions,
): Promise<VerifiedBadge> {
  const issuer = options.issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(issuer);
  const key = options.key ?? assertionResolverFor(issuer);

  let payload;
  try {
    const result = await verifyJwt(vcJwt, key, {
      issuer: expectedIss,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
      requiredClaims: ["exp"],
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause),
    );
  }

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new VcVerificationError("VC payload missing string `sub`");
  }

  const vc = payload.vc as
    | { type?: unknown; credentialSubject?: unknown }
    | undefined;
  if (!vc || typeof vc !== "object") {
    throw new VcVerificationError("VC payload missing `vc` envelope");
  }
  if (!Array.isArray(vc.type) || !vc.type.every((t) => typeof t === "string")) {
    throw new VcVerificationError("VC `type` must be a string array");
  }
  if (
    !vc.credentialSubject ||
    typeof vc.credentialSubject !== "object" ||
    Array.isArray(vc.credentialSubject)
  ) {
    throw new VcVerificationError("VC missing `credentialSubject` object");
  }

  const credentialSubject = vc.credentialSubject as Record<string, unknown>;
  const subjectId = credentialSubject["id"];
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw new VcVerificationError("VC `credentialSubject.id` missing");
  }

  // Holder-binding invariant: the JWT subject must equal the credential
  // subject the issuer signed. (Additional check beyond @ministryofmany/vc.)
  if (subjectId !== payload.sub) {
    throw new VcVerificationError(
      "VC `credentialSubject.id` does not match `sub`",
    );
  }

  // Map the VC type to a known Minister badge slug.
  const slug = badgeTypeOf(vc.type as string[]);
  if (!slug) {
    throw new VcVerificationError(
      `Unknown Minister badge type: ${(vc.type as string[]).join(",")}`,
    );
  }

  // Validate the claims against that badge type's schema. THREE RESERVED keys
  // are stripped first: `id` (redundant with `sub`), `issuanceMonth` (Minister's
  // coarse-issuance metadata), and `nullifier` (the per-RP Sybil-dedup tag,
  // stamped at disclosure re-mint). All three are cross-cutting VC metadata,
  // never per-type claims; stripping them BEFORE the schema parse keeps strict
  // per-type schemas (account-age, social-following, tlsn-attestation) passing
  // — a nullifier-bearing account-age badge would otherwise fail `.strict()`.
  const {
    id: _id,
    issuanceMonth: rawIssuanceMonth,
    nullifier: rawNullifier,
    ...rawClaims
  } = credentialSubject;

  // Strictly format-check the coarse issuance bucket when present. A
  // malformed value means issuer drift or a claim-shaped smuggle upstream of
  // the signature — fail closed rather than hand policy code a garbage
  // timestamp. Absent is fine (legacy Minister); downstream freshness checks
  // then fail closed on maxAgeDays.
  let issuanceMonth: string | undefined;
  if (rawIssuanceMonth !== undefined) {
    if (
      typeof rawIssuanceMonth !== "string" ||
      !/^\d{4}-(0[1-9]|1[0-2])$/.test(rawIssuanceMonth)
    ) {
      throw new VcVerificationError(
        "VC `credentialSubject.issuanceMonth` is not a YYYY-MM UTC month",
      );
    }
    issuanceMonth = rawIssuanceMonth;
  }

  // Format-check the per-RP nullifier when present. A malformed value means
  // issuer drift or a claim-shaped smuggle upstream of the signature — fail
  // closed rather than gate on garbage. Absent is fine (no wired nullifier, or
  // a pre-M5 disclosure); gating code then treats the badge as untagged.
  let nullifier: MinisterGatingNullifier | undefined;
  if (rawNullifier !== undefined) {
    if (typeof rawNullifier !== "string" || !NULLIFIER_RE.test(rawNullifier)) {
      throw new VcVerificationError(
        "VC `credentialSubject.nullifier` is not a well-formed mnv1 nullifier",
      );
    }
    nullifier = rawNullifier as MinisterGatingNullifier;
  }

  const schema = getBadgeClaimSchema(slug);
  let claims: Record<string, unknown>;
  try {
    claims = schema
      ? (schema.parse(rawClaims) as Record<string, unknown>)
      : rawClaims;
  } catch (cause) {
    throw new VcVerificationError(
      `Badge ${slug} claims failed validation: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }

  // Revocation (§5.8): parse `vc.credentialStatus` when present. It lives at the
  // `vc` level (sibling of credentialSubject), so it never touched the per-type
  // schema parse above. Strict shape check (type, purpose, https URL pinned to
  // the configured issuer origin, integer index); MALFORMED => fail the badge
  // closed (issuer drift, same posture as a malformed nullifier). Absent => the
  // badge simply carries no `status` (non-revocable, or a pre-revocation issuer).
  let status: BadgeStatusRef | undefined;
  try {
    status = parseCredentialStatus((vc as { credentialStatus?: unknown }).credentialStatus, issuer);
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause),
    );
  }

  return {
    type: slug,
    claims,
    subject: payload.sub,
    ...(issuanceMonth !== undefined ? { issuanceMonth } : {}),
    ...(nullifier !== undefined ? { nullifier } : {}),
    ...(status !== undefined ? { status } : {}),
    raw: vcJwt,
  };
}

// Test seam: drop the cached DID assertionMethod key resolver for an issuer (or
// all issuers). Re-exported for back-compat; the cache now lives in did-assertion.
export function _resetBadgeKeyCache(issuer?: string): void {
  _resetAssertionCache(issuer);
}
