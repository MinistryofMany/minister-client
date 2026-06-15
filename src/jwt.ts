import {
  jwtVerify,
  type JWTPayload,
  type JWTVerifyOptions,
  type JWTVerifyResult,
} from "jose";

import type { KeyInput } from "./types";

// jose's `jwtVerify` is overloaded: one signature takes a resolved key
// (KeyLike/Uint8Array), the other a key-resolver function (e.g.
// createRemoteJWKSet). `KeyInput` is the union of both, which doesn't
// match either overload directly. Narrow on `typeof key` and dispatch to
// the right call so the rest of the SDK can pass a single injectable
// key source.
export function verifyJwt(
  jwt: string,
  key: KeyInput,
  options: JWTVerifyOptions,
): Promise<JWTVerifyResult<JWTPayload>> {
  if (typeof key === "function") {
    return jwtVerify(jwt, key, options);
  }
  return jwtVerify(jwt, key, options);
}
