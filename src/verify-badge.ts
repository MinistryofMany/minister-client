import { createRemoteJWKSet } from "jose";

import { didFromIssuer } from "./did";
import { verifyJwt } from "./jwt";
import { VcVerificationError } from "./errors";
import type { KeyInput, VerifiedBadge } from "./types";

// Verify a Minister-issued verifiable credential against Minister's
// PUBLIC keys. Unlike `@minister/vc`'s `verifyVc` (which threads a full
// Issuer carrying the private key), an RP only ever holds public
// material — the JWKS Minister serves at /.well-known/jwks.json.

// Cache one remote JWKS per issuer for the process lifetime. The set
// fetches lazily and rotates keys on its own.
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
  // Inject the verification key source (defaults to the remote JWKS at
  // `${issuer}/.well-known/jwks.json`). Pass a public key in tests so
  // verification never touches the network.
  key?: KeyInput;
}

// Verify a received VC JWT.
//
// Beyond `@minister/vc`'s structural checks, this ALSO asserts
// `credentialSubject.id === payload.sub` — the holder-binding invariant
// `@minister/vc` does not currently enforce. Without it, a VC's claims
// could be presented as bound to a subject other than the one the
// issuer signed them for.
export async function verifyMinisterBadge(
  issuer: string,
  vcJwt: string,
  options: VerifyBadgeOptions = {},
): Promise<VerifiedBadge> {
  const normalizedIssuer = issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(normalizedIssuer);
  const key = options.key ?? remoteJwksFor(normalizedIssuer);

  let payload;
  try {
    const result = await verifyJwt(vcJwt, key, {
      issuer: expectedIss,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
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
  // subject the issuer signed. (Additional check beyond @minister/vc.)
  if (subjectId !== payload.sub) {
    throw new VcVerificationError(
      "VC `credentialSubject.id` does not match `sub`",
    );
  }

  // Strip `id` from the surfaced claims — it's redundant with `sub`.
  const { id: _id, ...claims } = credentialSubject;

  return {
    type: vc.type,
    claims,
    sub: payload.sub,
    raw: vcJwt,
  };
}

// Test seam: drop the cached remote JWKS for an issuer (or all issuers).
export function _resetBadgeJwksCache(issuer?: string): void {
  if (issuer) jwksCache.delete(issuer.replace(/\/$/, ""));
  else jwksCache.clear();
}
