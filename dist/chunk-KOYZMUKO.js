// src/badges/schemas.ts
import { z } from "zod";
var EmailDomainClaims = z.object({
  domain: z.string().min(1).toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain")
});
var EmailExactClaims = z.object({ email: z.string().email().toLowerCase() });
var OAUTH_PROVIDERS = ["github", "google", "discord"];
var OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  handle: z.string().min(1).optional()
});
var ACCOUNT_AGE_MONTHS = [12, 24, 36, 60];
var AccountAgeClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  olderThanMonths: z.union([z.literal(12), z.literal(24), z.literal(36), z.literal(60)])
}).strict();
var FOLLOWERS_BUCKETS = [10, 50, 100, 500, 1e3];
var SocialFollowingClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  followersAtLeast: z.union([
    z.literal(10),
    z.literal(50),
    z.literal(100),
    z.literal(500),
    z.literal(1e3)
  ])
}).strict();
var AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65];
var AgeOverClaimsFor = (threshold) => z.object({ threshold: z.literal(threshold) });
var COUNTRY_RE = /^[A-Z]{2}$/u;
var ResidencyCountryClaims = z.object({ country: z.string().regex(COUNTRY_RE) });
var ResidencyStateClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1)
});
var ResidencyCityClaims = z.object({
  country: z.string().regex(COUNTRY_RE),
  state: z.string().min(1),
  city: z.string().min(1)
});
var InviteCodeClaims = z.object({ label: z.string().min(1) });
var TlsnAttestationClaims = z.object({
  domain: z.string().min(1),
  claim: z.string().min(1)
}).strict();

// src/badges/registry.ts
var ENTRIES = [
  { slug: "email-domain", credentialType: "MinisterEmailDomainCredential", claims: EmailDomainClaims, sybilResistance: "weak" },
  { slug: "email-exact", credentialType: "MinisterEmailExactCredential", claims: EmailExactClaims, sybilResistance: "weak" },
  { slug: "oauth-account", credentialType: "MinisterOauthAccountCredential", claims: OAuthAccountClaims, sybilResistance: "weak" },
  { slug: "account-age", credentialType: "MinisterAccountAgeCredential", claims: AccountAgeClaims, sybilResistance: "moderate" },
  { slug: "social-following", credentialType: "MinisterSocialFollowingCredential", claims: SocialFollowingClaims, sybilResistance: "moderate" },
  { slug: "residency-country", credentialType: "MinisterResidencyCountryCredential", claims: ResidencyCountryClaims, sybilResistance: "none" },
  { slug: "residency-state", credentialType: "MinisterResidencyStateCredential", claims: ResidencyStateClaims, sybilResistance: "none" },
  { slug: "residency-city", credentialType: "MinisterResidencyCityCredential", claims: ResidencyCityClaims, sybilResistance: "none" },
  { slug: "invite-code", credentialType: "MinisterInviteCodeCredential", claims: InviteCodeClaims, sybilResistance: "none" },
  { slug: "tlsn-attestation", credentialType: "MinisterTlsnAttestationCredential", claims: TlsnAttestationClaims, sybilResistance: "none" },
  ...AGE_THRESHOLDS.map((t) => ({
    slug: `age-over-${t}`,
    credentialType: `MinisterAgeOver${t}Credential`,
    claims: AgeOverClaimsFor(t),
    sybilResistance: "none"
  }))
];
var BADGE_TYPES = Object.fromEntries(
  ENTRIES.map((d) => [d.slug, d])
);
var CREDENTIAL_TYPE_INDEX = Object.fromEntries(
  ENTRIES.map((d) => [d.credentialType, d.slug])
);
function slugForCredentialType(credentialType) {
  return CREDENTIAL_TYPE_INDEX[credentialType];
}

// src/badges/helpers.ts
function badgeScope(slug) {
  return `badge:${slug}`;
}
function badgeScopes(slugs) {
  return slugs.map(badgeScope);
}
function badgeTypeOf(vcType) {
  for (const t of vcType) {
    const slug = slugForCredentialType(t);
    if (slug) return slug;
  }
  return void 0;
}
function getBadgeClaimSchema(slug) {
  return BADGE_TYPES[slug]?.claims;
}
function knownBadgeTypes() {
  return Object.keys(BADGE_TYPES);
}

export {
  EmailDomainClaims,
  EmailExactClaims,
  OAUTH_PROVIDERS,
  OAuthAccountClaims,
  ACCOUNT_AGE_MONTHS,
  AccountAgeClaims,
  FOLLOWERS_BUCKETS,
  SocialFollowingClaims,
  AGE_THRESHOLDS,
  AgeOverClaimsFor,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  ResidencyCityClaims,
  InviteCodeClaims,
  TlsnAttestationClaims,
  BADGE_TYPES,
  slugForCredentialType,
  badgeScope,
  badgeScopes,
  badgeTypeOf,
  getBadgeClaimSchema,
  knownBadgeTypes
};
//# sourceMappingURL=chunk-KOYZMUKO.js.map