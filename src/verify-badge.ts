import { createRemoteJWKSet } from "jose";

import { badgeTypeOf, getBadgeClaimSchema } from "./badges/helpers";
import { didFromIssuer } from "./did";
import { verifyJwt } from "./jwt";
import { VcVerificationError } from "./errors";
import type { KeyInput, VerifiedBadge } from "./types";

// Verify a Minister-issued verifiable credential against Minister's
// PUBLIC keys. Unlike `@ministryofmany/vc`'s `verifyVc` (which threads a full
// Issuer carrying the private key), an RP only ever holds public
// material — the JWKS Minister serves at /.well-known/jwks.json.

// Cache one remote JWKS per issuer for the process lifetime. The set
// fetches lazily and rotates keys on its own.
// Cache key is the trusted RP-config issuer (not request input), so this stays bounded.
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function remoteJwksFor(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  let set = jwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache.set(issuer, set);
  }
  return set;
}

export interface VerifyBadgeOptions {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // Inject the verification key (defaults to the remote JWKS). Pass a
  // public JWK in tests so verification never touches the network.
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
  const key = options.key ?? remoteJwksFor(issuer);

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

  // Validate the claims against that badge type's schema. `id` is
  // stripped — it's redundant with `sub` and not part of the claims.
  const { id: _id, ...rawClaims } = credentialSubject;
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

  return { type: slug, claims, subject: payload.sub, raw: vcJwt };
}

// Test seam: drop the cached remote JWKS for an issuer (or all issuers).
export function _resetBadgeJwksCache(issuer?: string): void {
  if (issuer) jwksCache.delete(issuer.replace(/\/$/, ""));
  else jwksCache.clear();
}
