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
// accountId REMOVED (crypto-core Phase 1): the provider's numeric account id was
// the raw Sybil anchor. Minister now nullifies it into an opaque per-RP nullifier
// and DISCARDS it; only the renameable handle is revealed. Kept in sync with
// Minister's @ministryofmany/shared OAuthAccountClaims.
export const OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  handle: z.string().min(1).optional(),
});
export type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;

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
