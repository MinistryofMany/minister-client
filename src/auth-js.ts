// @minister/client/auth-js — non-invasive helpers for Auth.js (next-auth).
// We do NOT modify Auth.js; these are values/functions you hand to it via
// its documented extension points. `@auth/core` is a types-only optional
// peer used solely for the OIDCConfig return type.
import type { OIDCConfig } from "@auth/core/providers";
import type { JWTPayload } from "jose";
import { verifyMinisterBadges } from "./verify-badges";
import type { KeyInput, BadgesResult } from "./types";

export interface MinisterProviderOptions {
  clientId: string;
  clientSecret?: string;
  issuer: string;
  // Defaults to ["openid", "profile"]. Add badge:<type> scopes to request badges.
  scopes?: string[];
}

// Build the Auth.js OIDC provider config object. Drop it into
// NextAuth({ providers: [ministerProvider({...})] }). Auth.js owns the
// flow, session, and cookies; this is only its provider configuration.
export function ministerProvider(options: MinisterProviderOptions): OIDCConfig<Record<string, unknown>> {
  const scopes = options.scopes ?? ["openid", "profile"];
  return {
    id: "minister",
    name: "Minister",
    type: "oidc",
    issuer: options.issuer,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: { params: { scope: scopes.join(" ") } },
    checks: ["pkce", "state", "nonce"],
  };
}

export interface MinisterBadgesFromProfileOptions {
  issuer: string;
  key?: KeyInput;
}

// Verify the minister_badges in an Auth.js `profile` (already-verified
// id_token payload). Call inside your own jwt/profile callback.
export function ministerBadgesFromProfile(
  profile: JWTPayload | Record<string, unknown>,
  options: MinisterBadgesFromProfileOptions,
): Promise<BadgesResult> {
  return verifyMinisterBadges(profile as JWTPayload, { issuer: options.issuer, key: options.key });
}
