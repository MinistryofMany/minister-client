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
  // When set, the id_token `aud` must equal it. Omit only to skip audience enforcement.
  clientId?: string;
  // Replay nonce; when set, must equal the id_token `nonce`.
  nonce?: string;
  // Inject the verification key (defaults to the remote JWKS).
  key?: KeyInput;
}

// Internal: verify the id_token and return the full payload (callers that
// need minister_badges use this; verifyMinisterIdToken maps to claims).
export async function verifyIdTokenPayload(idToken: string, options: VerifyIdTokenOptions): Promise<JWTPayload> {
  const issuer = options.issuer.replace(/\/$/, "");
  const key = options.key ?? remoteJwksFor(issuer);
  let payload: JWTPayload;
  try {
    const result = await verifyJwt(idToken, key, {
      issuer,
      algorithms: ["EdDSA"],
      requiredClaims: ["exp", "iat"],
      clockTolerance: "30s",
      ...(options.clientId ? { audience: options.clientId } : {}),
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

// Verify a Minister id_token and return its identity claims.
export async function verifyMinisterIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<MinisterClaims> {
  const payload = await verifyIdTokenPayload(idToken, options);
  return {
    sub: payload.sub as string,
    name: typeof payload["name"] === "string" ? (payload["name"] as string) : undefined,
    picture: typeof payload["picture"] === "string" ? (payload["picture"] as string) : undefined,
    raw: idToken,
  };
}

export function _resetIdTokenJwksCache(issuer?: string): void {
  if (issuer) jwksCache.delete(issuer.replace(/\/$/, ""));
  else jwksCache.clear();
}
