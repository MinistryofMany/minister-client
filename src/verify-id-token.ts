import { createRemoteJWKSet, type JWTPayload } from "jose";
import { verifyJwt } from "./jwt";
import { MinisterTokenError } from "./errors";
import type { KeyInput, MinisterClaims } from "./types";

// Cache key is the trusted RP-config issuer (not request input), so this stays bounded.
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function remoteJwksFor(issuer: string) {
  let set = jwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache.set(issuer, set);
  }
  return set;
}

export interface VerifyIdTokenOptions {
  issuer: string;
  // REQUIRED (fail-closed audience): the id_token `aud` must equal it. A
  // verifier built without a clientId would silently accept a token minted for
  // another relying party (cross-RP impersonation), so this is not optional and
  // is also enforced at runtime.
  clientId: string;
  // Replay nonce; when set, must equal the id_token `nonce`.
  nonce?: string;
  // Inject the verification key (defaults to the remote JWKS).
  key?: KeyInput;
}

// Internal: verify the id_token and return the full payload (callers that
// need minister_badges use this; verifyMinisterIdToken maps to claims).
export async function verifyIdTokenPayload(idToken: string, options: VerifyIdTokenOptions): Promise<JWTPayload> {
  const issuer = options.issuer.replace(/\/$/, "");
  // Fail closed: never verify an id_token without an expected audience. A JS
  // caller can defeat the required-type at runtime, so guard here too.
  if (!options.clientId) {
    throw new MinisterTokenError("clientId (expected audience) is required to verify an id_token");
  }
  const key = options.key ?? remoteJwksFor(issuer);
  let payload: JWTPayload;
  try {
    const result = await verifyJwt(idToken, key, {
      issuer,
      algorithms: ["EdDSA"],
      requiredClaims: ["exp", "iat"],
      clockTolerance: "30s",
      audience: options.clientId,
    });
    payload = result.payload;
  } catch (cause) {
    throw new MinisterTokenError(cause instanceof Error ? cause.message : String(cause));
  }
  if (options.nonce !== undefined && payload["nonce"] !== options.nonce) {
    throw new MinisterTokenError("id_token `nonce` mismatch");
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new MinisterTokenError("id_token missing string `sub`");
  }
  return payload;
}

// Map a verified id_token payload to the public identity claims. Shared by
// verifyMinisterIdToken and the flow client so the mapping lives in one place.
export function claimsFromPayload(payload: JWTPayload, raw: string): MinisterClaims {
  // Fail-closed range validation for the opt-in Sybil bucket. The id_token
  // signature/issuer/audience/nonce are already verified upstream, so the
  // value is authenticated; here we only accept an integer in [0,4] (0 is a
  // real bucket, must survive) and OMIT anything else — non-number,
  // non-integer, or out of range — never throwing and never coercing.
  const rawBucket = payload["sybil_bucket"];
  const sybil_bucket =
    typeof rawBucket === "number" &&
    Number.isInteger(rawBucket) &&
    rawBucket >= 0 &&
    rawBucket <= 4
      ? rawBucket
      : undefined;
  // Same discipline as sybil_bucket: authenticated upstream, range-validated on
  // the way out. An epoch is a positive integer (>= 1, no upper bound); omit
  // anything else rather than coerce, so a missing/garbage claim reads as "no
  // epoch" and decideAnonAction fails closed.
  const rawEpoch = payload["minister_anon_epoch"];
  const minister_anon_epoch =
    typeof rawEpoch === "number" && Number.isInteger(rawEpoch) && rawEpoch >= 1
      ? rawEpoch
      : undefined;
  return {
    sub: payload.sub as string,
    name: typeof payload["name"] === "string" ? (payload["name"] as string) : undefined,
    picture: typeof payload["picture"] === "string" ? (payload["picture"] as string) : undefined,
    sybil_bucket,
    minister_anon_epoch,
    raw,
  };
}

// Verify a Minister id_token and return its identity claims.
export async function verifyMinisterIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<MinisterClaims> {
  const payload = await verifyIdTokenPayload(idToken, options);
  return claimsFromPayload(payload, idToken);
}
