// src/badges/schemas.ts
import { z } from "zod";
var EmailDomainClaims = z.object({
  domain: z.string().min(1).toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain")
});
var EmailExactClaims = z.object({ email: z.string().email().toLowerCase() });
var OAUTH_PROVIDERS = ["github", "google", "discord"];
var OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  accountId: z.string().min(1),
  handle: z.string().min(1).optional()
});
var ACCOUNT_AGE_MONTHS = [12, 24, 36, 60];
var AccountAgeClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  olderThanMonths: z.union([z.literal(12), z.literal(24), z.literal(36), z.literal(60)])
}).strict();
var TwoFactorClaims = z.object({ provider: z.enum(OAUTH_PROVIDERS) }).strict();
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
function defineBadgeType(input) {
  return { ...input, scope: `badge:${input.slug}` };
}
var ENTRIES = [
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
  ...AGE_THRESHOLDS.map(
    (t) => defineBadgeType({
      slug: `age-over-${t}`,
      credentialType: `MinisterAgeOver${t}Credential`,
      claims: AgeOverClaimsFor(t)
    })
  )
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
  TwoFactorClaims,
  FOLLOWERS_BUCKETS,
  SocialFollowingClaims,
  AGE_THRESHOLDS,
  AgeOverClaimsFor,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  ResidencyCityClaims,
  InviteCodeClaims,
  TlsnAttestationClaims,
  defineBadgeType,
  BADGE_TYPES,
  slugForCredentialType,
  badgeScope,
  badgeScopes,
  badgeTypeOf,
  getBadgeClaimSchema,
  knownBadgeTypes
};
//# sourceMappingURL=chunk-4E5KJT4H.js.map