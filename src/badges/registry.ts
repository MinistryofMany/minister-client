import type { z } from "zod";
import {
  EmailDomainClaims,
  EmailExactClaims,
  OAuthAccountClaims,
  AccountAgeClaims,
  TwoFactorClaims,
  SocialFollowingClaims,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  ResidencyCityClaims,
  InviteCodeClaims,
  TlsnAttestationClaims,
  AGE_THRESHOLDS,
  AgeOverClaimsFor,
} from "./schemas";

// One self-describing badge type. Adding a Minister badge type to this
// SDK is a single `defineBadgeType(...)` entry; every helper, scope, and
// the verifier's type->slug mapping derive from BADGE_TYPES.
export interface BadgeTypeDef {
  // Minister badge slug, e.g. "email-domain".
  slug: string;
  // The VC `type[]` entry Minister stamps, e.g. "MinisterEmailDomainCredential".
  credentialType: string;
  // The OIDC scope a relying party requests to ask for this badge.
  scope: string;
  // Zod schema for the credentialSubject claims (excluding `id`).
  claims: z.ZodType<unknown>;
}

// Build a BadgeTypeDef, deriving `scope` from the slug.
export function defineBadgeType(input: {
  slug: string;
  credentialType: string;
  claims: z.ZodType<unknown>;
}): BadgeTypeDef {
  return { ...input, scope: `badge:${input.slug}` };
}

// NOTE: `credentialType` values must match Minister's @ministryofmany/shared
// `ministerCredentialType(slug)` output exactly. If a future Minister slug
// uses irregular casing, fix the literal here (this file is the one place
// to do it). The planned drift-check will assert these against @ministryofmany/shared.
const ENTRIES: BadgeTypeDef[] = [
  defineBadgeType({ slug: "email-domain", credentialType: "MinisterEmailDomainCredential", claims: EmailDomainClaims }),
  defineBadgeType({ slug: "email-exact", credentialType: "MinisterEmailExactCredential", claims: EmailExactClaims }),
  defineBadgeType({ slug: "oauth-account", credentialType: "MinisterOauthAccountCredential", claims: OAuthAccountClaims }),
  defineBadgeType({ slug: "account-age", credentialType: "MinisterAccountAgeCredential", claims: AccountAgeClaims }),
  defineBadgeType({ slug: "two-factor", credentialType: "MinisterTwoFactorCredential", claims: TwoFactorClaims }),
  defineBadgeType({ slug: "social-following", credentialType: "MinisterSocialFollowingCredential", claims: SocialFollowingClaims }),
  defineBadgeType({ slug: "residency-country", credentialType: "MinisterResidencyCountryCredential", claims: ResidencyCountryClaims }),
  defineBadgeType({ slug: "residency-state", credentialType: "MinisterResidencyStateCredential", claims: ResidencyStateClaims }),
  defineBadgeType({ slug: "residency-city", credentialType: "MinisterResidencyCityCredential", claims: ResidencyCityClaims }),
  defineBadgeType({ slug: "invite-code", credentialType: "MinisterInviteCodeCredential", claims: InviteCodeClaims }),
  defineBadgeType({ slug: "tlsn-attestation", credentialType: "MinisterTlsnAttestationCredential", claims: TlsnAttestationClaims }),
  ...AGE_THRESHOLDS.map((t) =>
    defineBadgeType({
      slug: `age-over-${t}`,
      credentialType: `MinisterAgeOver${t}Credential`,
      claims: AgeOverClaimsFor(t),
    }),
  ),
];

// slug -> def
export const BADGE_TYPES: Record<string, BadgeTypeDef> = Object.fromEntries(
  ENTRIES.map((d) => [d.slug, d]),
);

// credentialType -> slug (reverse index for badgeTypeOf)
const CREDENTIAL_TYPE_INDEX: Record<string, string> = Object.fromEntries(
  ENTRIES.map((d) => [d.credentialType, d.slug]),
);

// The Minister badge slug for a VC credentialType, or undefined if unknown.
export function slugForCredentialType(credentialType: string): string | undefined {
  return CREDENTIAL_TYPE_INDEX[credentialType];
}
