import {
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type JWTVerifyOptions,
  type JWTVerifyResult,
} from "jose";

import type { KeyInput } from "./types";

// A bare JWK is a plain object carrying `kty`. A resolved `KeyLike`
// (CryptoKey/KeyObject) has `type` but never `kty`; a `Uint8Array` and a
// resolver function are not plain objects with `kty`. So this is total and
// unambiguous over the `KeyInput` union.
function isJwk(key: KeyInput): key is JWK {
  return (
    typeof key === "object" &&
    key !== null &&
    !(key instanceof Uint8Array) &&
    typeof (key as JWK).kty === "string"
  );
}

// jose's `jwtVerify` is overloaded: one signature takes a resolved key
// (KeyLike/Uint8Array/JWK), the other a key-resolver function (e.g.
// createRemoteJWKSet). `KeyInput` is the union of both. Narrow on the key
// shape and dispatch to the right call so the rest of the SDK can pass a single
// injectable key source — including a raw JWK, which we import ourselves
// (pinned to EdDSA, the only alg Minister signs with) so a caller never has to.
export async function verifyJwt(
  jwt: string,
  key: KeyInput,
  options: JWTVerifyOptions,
): Promise<JWTVerifyResult<JWTPayload>> {
  if (typeof key === "function") {
    return jwtVerify(jwt, key, options);
  }
  const resolved = isJwk(key) ? await importJWK(key, "EdDSA") : key;
  return jwtVerify(jwt, resolved, options);
}
