import { z } from "zod";

// Badge type vocabulary for relying parties.
//
// This MIRRORS Minister's authoritative registry in
// `@minister/shared` (`../minister-shared/src/badge-types.ts`). It is
// copied here (rather than imported) so this SDK has no dependency on
// Minister's internal packages and can be published standalone.
//
// Provider/UI-only concerns from the source registry are intentionally
// OMITTED: the `iconKey` field, the `BadgeIconKey` union, the display
// `label`/`description` metadata, and the issuance helpers. An RP only
// needs the claim shapes (to validate disclosed badges) and the set of
// known slugs.
//
// DRIFT RISK: because this is a copy, it can drift from Minister's
// registry. A drift-check (asserting these schemas/slugs match the
// upstream `@minister/shared` export) will be added later.

// ---------------------------------------------------------------------------
// Individual badge claim schemas
// ---------------------------------------------------------------------------

export const EmailDomainClaims = z.object({
  domain: z
    .string()
    .min(1)
    .toLowerCase()
    .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain"),
});
export type EmailDomainClaims = z.infer<typeof EmailDomainClaims>;

export const EmailExactClaims = z.object({
  email: z.string().email().toLowerCase(),
});
export type EmailExactClaims = z.infer<typeof EmailExactClaims>;

export const OAUTH_PROVIDERS = ["github", "google", "discord"] as const;
export const OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  accountId: z.string().min(1),
  handle: z.string().min(1).optional(),
});
export type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;

export const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;
export type AgeThreshold = (typeof AGE_THRESHOLDS)[number];

const AgeOverClaimsFor = (threshold: AgeThreshold) =>
  z.object({
    threshold: z.literal(threshold),
  });

const COUNTRY_RE = /^[A-Z]{2}$/u; // ISO 3166-1 alpha-2
export const ResidencyCountryClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
});
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

// The label identifies the invite campaign/cohort, not the code — the
// code string itself never appears in claims.
export const InviteCodeClaims = z.object({
  label: z.string().min(1),
});
export type InviteCodeClaims = z.infer<typeof InviteCodeClaims>;

// Generic TLSNotary attestation — domain + a single structured claim.
// Strict (no `.passthrough()`): unknown keys are rejected.
export const TlsnAttestationClaims = z
  .object({
    domain: z.string().min(1),
    claim: z.string().min(1),
  })
  .strict();
export type TlsnAttestationClaims = z.infer<typeof TlsnAttestationClaims>;

// ---------------------------------------------------------------------------
// Slug → claim schema registry
// ---------------------------------------------------------------------------

// All known badge type slugs mapped to the Zod schema for their
// `credentialSubject` claims (excluding the always-present `id` field,
// which an RP reads via the verified badge's `sub`).
const BADGE_CLAIM_SCHEMAS: Record<string, z.ZodType<unknown>> = {
  "email-domain": EmailDomainClaims,
  "email-exact": EmailExactClaims,
  "oauth-account": OAuthAccountClaims,
  "residency-country": ResidencyCountryClaims,
  "residency-state": ResidencyStateClaims,
  "residency-city": ResidencyCityClaims,
  "invite-code": InviteCodeClaims,
  "tlsn-attestation": TlsnAttestationClaims,
  ...Object.fromEntries(
    AGE_THRESHOLDS.map(
      (t) => [`age-over-${t}`, AgeOverClaimsFor(t)] as const,
    ),
  ),
};

// The Zod schema for a badge type's claims, or undefined if the slug is
// not a known Minister badge type. Use this to validate the claims of a
// disclosed badge before trusting them.
export function getBadgeClaimSchema(slug: string): z.ZodType<unknown> | undefined {
  return BADGE_CLAIM_SCHEMAS[slug];
}

// Every badge type slug this SDK knows how to validate.
export function knownBadgeTypes(): string[] {
  return Object.keys(BADGE_CLAIM_SCHEMAS);
}
