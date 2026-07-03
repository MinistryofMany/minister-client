import { z } from "zod";

export const EmailDomainClaims = z.object({
  domain: z
    .string()
    .min(1)
    .toLowerCase()
    .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain"),
});
export type EmailDomainClaims = z.infer<typeof EmailDomainClaims>;

export const EmailExactClaims = z.object({ email: z.string().email().toLowerCase() });
export type EmailExactClaims = z.infer<typeof EmailExactClaims>;

export const OAUTH_PROVIDERS = ["github", "google", "discord"] as const;
export const OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  accountId: z.string().min(1),
  handle: z.string().min(1).optional(),
});
export type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;

// GitHub-derived (provider-generic) badge types. Mirror of Minister's
// @minister/shared registry; kept in sync by hand (drift-check planned).

// Account age - coarse "older than N months" threshold, never the exact date.
export const ACCOUNT_AGE_MONTHS = [12, 24, 36, 60] as const;
export type AccountAgeMonths = (typeof ACCOUNT_AGE_MONTHS)[number];
export const AccountAgeClaims = z
  .object({
    provider: z.enum(OAUTH_PROVIDERS),
    olderThanMonths: z.union([z.literal(12), z.literal(24), z.literal(36), z.literal(60)]),
  })
  .strict();
export type AccountAgeClaims = z.infer<typeof AccountAgeClaims>;

// Two-factor enabled - bare presence badge; provider is the only field.
export const TwoFactorClaims = z.object({ provider: z.enum(OAUTH_PROVIDERS) }).strict();
export type TwoFactorClaims = z.infer<typeof TwoFactorClaims>;

// Social following - coarse "at least N followers" bucket, never the exact count.
export const FOLLOWERS_BUCKETS = [10, 50, 100, 500, 1000] as const;
export type FollowersBucket = (typeof FOLLOWERS_BUCKETS)[number];
export const SocialFollowingClaims = z
  .object({
    provider: z.enum(OAUTH_PROVIDERS),
    followersAtLeast: z.union([
      z.literal(10),
      z.literal(50),
      z.literal(100),
      z.literal(500),
      z.literal(1000),
    ]),
  })
  .strict();
export type SocialFollowingClaims = z.infer<typeof SocialFollowingClaims>;

export const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;
export type AgeThreshold = (typeof AGE_THRESHOLDS)[number];
export const AgeOverClaimsFor = (threshold: AgeThreshold) =>
  z.object({ threshold: z.literal(threshold) });

const COUNTRY_RE = /^[A-Z]{2}$/u; // ISO 3166-1 alpha-2
export const ResidencyCountryClaims = z.object({ country: z.string().regex(COUNTRY_RE) });
export const ResidencyStateClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1),
});
export const ResidencyCityClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1),
  city: z.string().min(1),
});
export type ResidencyCountryClaims = z.infer<typeof ResidencyCountryClaims>;
export type ResidencyStateClaims = z.infer<typeof ResidencyStateClaims>;
export type ResidencyCityClaims = z.infer<typeof ResidencyCityClaims>;

// The label identifies the invite campaign/cohort, not the code - the
// code string itself never appears in claims.
export const InviteCodeClaims = z.object({ label: z.string().min(1) });
export type InviteCodeClaims = z.infer<typeof InviteCodeClaims>;

// Generic TLSNotary attestation: domain plus a single structured claim.
// Strict (no `.passthrough()`): unknown keys are rejected.
export const TlsnAttestationClaims = z
  .object({
    domain: z.string().min(1),
    claim: z.string().min(1),
  })
  .strict();
export type TlsnAttestationClaims = z.infer<typeof TlsnAttestationClaims>;
