import {
  badgeScope,
  OidcCore,
  type ExchangeCodeArgs,
  type GetAuthorizationUrlArgs,
} from "./oidc";
import { generatePkce, randomUrlToken } from "./pkce";
import type {
  ExchangeResult,
  MinisterClientConfig,
  PkcePair,
} from "./types";
import {
  verifyMinisterBadge,
  type VerifyBadgeOptions,
} from "./verify-badge";

// The relying-party client surface returned by createMinisterClient.
export interface MinisterClient {
  // Discover the authorization endpoint and build the redirect URL.
  // Pass the scopes you want, e.g. ["openid","profile","badge:age-over-21"].
  getAuthorizationUrl(args: GetAuthorizationUrlArgs): Promise<string>;

  // Exchange the callback `code` for verified id_token claims plus
  // signature-verified, holder-bound badges.
  exchangeCode(args: ExchangeCodeArgs): Promise<ExchangeResult>;

  // Verify a single received VC badge against Minister's public keys.
  // Useful for badges received out of band (e.g. share links), not just
  // those returned from exchangeCode.
  verifyMinisterBadge(
    vcJwt: string,
    options?: VerifyBadgeOptions,
  ): ReturnType<typeof verifyMinisterBadge>;

  // PKCE S256 pair. Keep `verifier` server-side; put `challenge` in the
  // auth URL.
  generatePkce(): Promise<PkcePair>;

  // 128-bit URL-safe random token for `state` / `nonce`.
  randomToken(bytes?: number): string;

  // Build a `badge:<slug>` scope string.
  badgeScope(slug: string): string;
}

// Create a Minister relying-party client. `issuer` is Minister's origin
// (e.g. "https://ministry.id"). The SDK stores no state: persistence of
// the per-request OidcFlowState is the app's responsibility.
export function createMinisterClient(
  config: MinisterClientConfig,
): MinisterClient {
  const core = new OidcCore(config);
  const issuer = config.issuer.replace(/\/$/, "");

  return {
    getAuthorizationUrl: (args) => core.getAuthorizationUrl(args),
    exchangeCode: (args) => core.exchangeCode(args),
    verifyMinisterBadge: (vcJwt, options) =>
      verifyMinisterBadge(issuer, vcJwt, options),
    generatePkce: () => generatePkce(),
    randomToken: (bytes) => randomUrlToken(bytes),
    badgeScope: (slug) => badgeScope(slug),
  };
}
