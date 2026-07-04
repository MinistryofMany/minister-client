import type { z } from "zod";
import {
  EmailDomainClaims,
  EmailExactClaims,
  OAuthAccountClaims,
  AccountAgeClaims,
  SocialFollowingClaims,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  ResidencyCityClaims,
  InviteCodeClaims,
  TlsnAttestationClaims,
  AGE_THRESHOLDS,
  AgeOverClaimsFor,
} from "./schemas";

// How much Sybil resistance a badge type provides — the HONEST claim is "one
// credential", never "one person". Informational (weight it yourself), NOT
// policy-enforced. Mirrors Minister's @ministryofmany/shared `SybilResistance`.
//   none     = no dedup nullifier is wired for this type.
//   weak     = anchored to a cheap-to-farm credential (catch-all domains, cheap
//              github accounts).
//   moderate = anchored to a costlier-to-farm signal (aged/followed accounts).
export type SybilResistance = "none" | "weak" | "moderate";

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
  // REQUIRED — mirrors Minister's per-type Sybil-resistance metadata.
  sybilResistance: SybilResistance;
}

// Build a BadgeTypeDef, deriving `scope` from the slug.
export function defineBadgeType(input: {
  slug: string;
  credentialType: string;
  claims: z.ZodType<unknown>;
  sybilResistance: SybilResistance;
}): BadgeTypeDef {
  return { ...input, scope: `badge:${input.slug}` };
}

// NOTE: `credentialType` values must match Minister's @ministryofmany/shared
// `ministerCredentialType(slug)` output exactly. If a future Minister slug
// uses irregular casing, fix the literal here (this file is the one place
// to do it). The planned drift-check will assert these against @ministryofmany/shared.
// NOTE: sybilResistance values mirror Minister's @ministryofmany/shared §2.3
// table for every type. `account-age` and `social-following` are the two
// `moderate` (nullifier-anchored) github-derived types — they MUST be registered
// here or an RP could not verify them (badgeTypeOf → undefined → rejected). The
// planned drift-check will assert this registry's (slug, sybilResistance) set
// against @ministryofmany/shared.
const ENTRIES: BadgeTypeDef[] = [
  defineBadgeType({ slug: "email-domain", credentialType: "MinisterEmailDomainCredential", claims: EmailDomainClaims, sybilResistance: "weak" }),
  defineBadgeType({ slug: "email-exact", credentialType: "MinisterEmailExactCredential", claims: EmailExactClaims, sybilResistance: "weak" }),
  defineBadgeType({ slug: "oauth-account", credentialType: "MinisterOauthAccountCredential", claims: OAuthAccountClaims, sybilResistance: "weak" }),
  defineBadgeType({ slug: "account-age", credentialType: "MinisterAccountAgeCredential", claims: AccountAgeClaims, sybilResistance: "moderate" }),
  defineBadgeType({ slug: "social-following", credentialType: "MinisterSocialFollowingCredential", claims: SocialFollowingClaims, sybilResistance: "moderate" }),
  defineBadgeType({ slug: "residency-country", credentialType: "MinisterResidencyCountryCredential", claims: ResidencyCountryClaims, sybilResistance: "none" }),
  defineBadgeType({ slug: "residency-state", credentialType: "MinisterResidencyStateCredential", claims: ResidencyStateClaims, sybilResistance: "none" }),
  defineBadgeType({ slug: "residency-city", credentialType: "MinisterResidencyCityCredential", claims: ResidencyCityClaims, sybilResistance: "none" }),
  defineBadgeType({ slug: "invite-code", credentialType: "MinisterInviteCodeCredential", claims: InviteCodeClaims, sybilResistance: "none" }),
  defineBadgeType({ slug: "tlsn-attestation", credentialType: "MinisterTlsnAttestationCredential", claims: TlsnAttestationClaims, sybilResistance: "none" }),
  ...AGE_THRESHOLDS.map((t) =>
    defineBadgeType({
      slug: `age-over-${t}`,
      credentialType: `MinisterAgeOver${t}Credential`,
      claims: AgeOverClaimsFor(t),
      sybilResistance: "none",
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
