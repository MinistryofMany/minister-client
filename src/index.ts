// @ministryofmany/client - Minister relying-party SDK.

// Flow client (for apps hand-rolling OIDC). `createMinisterClient` is the
// intended surface; the underlying `OidcCore` class stays internal.
export { createMinisterClient } from "./client";
export type { MinisterClient } from "./client";
export type { GetAuthorizationUrlArgs, ExchangeCodeArgs } from "./oidc";
export { generatePkce, randomUrlToken } from "./pkce";
export { buildDid, didFromIssuer } from "./did";

// Verification layer
export { createMinisterVerifier } from "./verifier";
export type { MinisterVerifier, MinisterVerifierConfig } from "./verifier";
export { verifyMinisterIdToken } from "./verify-id-token";
export type { VerifyIdTokenOptions } from "./verify-id-token";
export { verifyMinisterBadges } from "./verify-badges";
export type { VerifyBadgesOptions } from "./verify-badges";
export { verifyMinisterBadge } from "./verify-badge";
export type { VerifyBadgeOptions } from "./verify-badge";

// Errors
export { VcVerificationError, OidcError, MinisterTokenError } from "./errors";

// Shared types
export type {
  MinisterClientConfig,
  PkcePair,
  OidcFlowState,
  MinisterClaims,
  VerifiedBadge,
  RejectedBadge,
  BadgesResult,
  ExchangeResult,
  KeyInput,
} from "./types";

// Badge vocabulary (also available standalone at "@ministryofmany/client/badges")
export * from "./badges/index";
