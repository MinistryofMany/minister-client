// @minister/client — OIDC relying-party SDK for Minister.
//
// Public API for apps that "Sign in with Minister" and consume the
// W3C verifiable-credential badges users disclose.

export { createMinisterClient } from "./client";
export type { MinisterClient } from "./client";

export { OidcCore, badgeScope } from "./oidc";
export type {
  GetAuthorizationUrlArgs,
  ExchangeCodeArgs,
} from "./oidc";

export { generatePkce, randomUrlToken } from "./pkce";

export { verifyMinisterBadge } from "./verify-badge";
export type { VerifyBadgeOptions } from "./verify-badge";

export { buildDid, didFromIssuer } from "./did";

export { VcVerificationError, OidcError } from "./errors";

export type {
  MinisterClientConfig,
  PkcePair,
  OidcFlowState,
  MinisterClaims,
  VerifiedBadge,
  ExchangeResult,
  KeyInput,
} from "./types";

// Badge vocabulary (mirrors Minister's registry; see badge-types.ts).
export {
  EmailDomainClaims,
  EmailExactClaims,
  OAUTH_PROVIDERS,
  OAuthAccountClaims,
  AGE_THRESHOLDS,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  ResidencyCityClaims,
  InviteCodeClaims,
  TlsnAttestationClaims,
  getBadgeClaimSchema,
  knownBadgeTypes,
} from "./badge-types";
// Each `*Claims` export above is both a Zod schema (value) and its
// inferred type, so no separate type re-export is needed. AgeThreshold is
// type-only.
export type { AgeThreshold } from "./badge-types";
