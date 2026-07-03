import { z } from 'zod';

declare const EmailDomainClaims: z.ZodObject<{
    domain: z.ZodString;
}, "strip", z.ZodTypeAny, {
    domain: string;
}, {
    domain: string;
}>;
type EmailDomainClaims = z.infer<typeof EmailDomainClaims>;
declare const EmailExactClaims: z.ZodObject<{
    email: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
}, {
    email: string;
}>;
type EmailExactClaims = z.infer<typeof EmailExactClaims>;
declare const OAUTH_PROVIDERS: readonly ["github", "google", "discord"];
declare const OAuthAccountClaims: z.ZodObject<{
    provider: z.ZodEnum<["github", "google", "discord"]>;
    accountId: z.ZodString;
    handle: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    provider: "github" | "google" | "discord";
    accountId: string;
    handle?: string | undefined;
}, {
    provider: "github" | "google" | "discord";
    accountId: string;
    handle?: string | undefined;
}>;
type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;
declare const ACCOUNT_AGE_MONTHS: readonly [12, 24, 36, 60];
type AccountAgeMonths = (typeof ACCOUNT_AGE_MONTHS)[number];
declare const AccountAgeClaims: z.ZodObject<{
    provider: z.ZodEnum<["github", "google", "discord"]>;
    olderThanMonths: z.ZodUnion<[z.ZodLiteral<12>, z.ZodLiteral<24>, z.ZodLiteral<36>, z.ZodLiteral<60>]>;
}, "strict", z.ZodTypeAny, {
    provider: "github" | "google" | "discord";
    olderThanMonths: 12 | 24 | 36 | 60;
}, {
    provider: "github" | "google" | "discord";
    olderThanMonths: 12 | 24 | 36 | 60;
}>;
type AccountAgeClaims = z.infer<typeof AccountAgeClaims>;
declare const TwoFactorClaims: z.ZodObject<{
    provider: z.ZodEnum<["github", "google", "discord"]>;
}, "strict", z.ZodTypeAny, {
    provider: "github" | "google" | "discord";
}, {
    provider: "github" | "google" | "discord";
}>;
type TwoFactorClaims = z.infer<typeof TwoFactorClaims>;
declare const FOLLOWERS_BUCKETS: readonly [10, 50, 100, 500, 1000];
type FollowersBucket = (typeof FOLLOWERS_BUCKETS)[number];
declare const SocialFollowingClaims: z.ZodObject<{
    provider: z.ZodEnum<["github", "google", "discord"]>;
    followersAtLeast: z.ZodUnion<[z.ZodLiteral<10>, z.ZodLiteral<50>, z.ZodLiteral<100>, z.ZodLiteral<500>, z.ZodLiteral<1000>]>;
}, "strict", z.ZodTypeAny, {
    provider: "github" | "google" | "discord";
    followersAtLeast: 10 | 50 | 100 | 500 | 1000;
}, {
    provider: "github" | "google" | "discord";
    followersAtLeast: 10 | 50 | 100 | 500 | 1000;
}>;
type SocialFollowingClaims = z.infer<typeof SocialFollowingClaims>;
declare const AGE_THRESHOLDS: readonly [16, 18, 21, 25, 30, 35, 40, 45, 55, 65];
type AgeThreshold = (typeof AGE_THRESHOLDS)[number];
declare const AgeOverClaimsFor: (threshold: AgeThreshold) => z.ZodObject<{
    threshold: z.ZodLiteral<16 | 18 | 21 | 25 | 30 | 35 | 40 | 45 | 55 | 65>;
}, "strip", z.ZodTypeAny, {
    threshold: 16 | 18 | 21 | 25 | 30 | 35 | 40 | 45 | 55 | 65;
}, {
    threshold: 16 | 18 | 21 | 25 | 30 | 35 | 40 | 45 | 55 | 65;
}>;
declare const ResidencyCountryClaims: z.ZodObject<{
    country: z.ZodString;
}, "strip", z.ZodTypeAny, {
    country: string;
}, {
    country: string;
}>;
type ResidencyCountryClaims = z.infer<typeof ResidencyCountryClaims>;
declare const ResidencyStateClaims: z.ZodObject<{
    country: z.ZodString;
    state: z.ZodString;
}, "strip", z.ZodTypeAny, {
    state: string;
    country: string;
}, {
    state: string;
    country: string;
}>;
type ResidencyStateClaims = z.infer<typeof ResidencyStateClaims>;
declare const ResidencyCityClaims: z.ZodObject<{
    country: z.ZodString;
    state: z.ZodString;
    city: z.ZodString;
}, "strip", z.ZodTypeAny, {
    state: string;
    country: string;
    city: string;
}, {
    state: string;
    country: string;
    city: string;
}>;
type ResidencyCityClaims = z.infer<typeof ResidencyCityClaims>;
declare const InviteCodeClaims: z.ZodObject<{
    label: z.ZodString;
}, "strip", z.ZodTypeAny, {
    label: string;
}, {
    label: string;
}>;
type InviteCodeClaims = z.infer<typeof InviteCodeClaims>;
declare const TlsnAttestationClaims: z.ZodObject<{
    domain: z.ZodString;
    claim: z.ZodString;
}, "strict", z.ZodTypeAny, {
    domain: string;
    claim: string;
}, {
    domain: string;
    claim: string;
}>;
type TlsnAttestationClaims = z.infer<typeof TlsnAttestationClaims>;

interface BadgeTypeDef {
    slug: string;
    credentialType: string;
    scope: string;
    claims: z.ZodType<unknown>;
}
declare function defineBadgeType(input: {
    slug: string;
    credentialType: string;
    claims: z.ZodType<unknown>;
}): BadgeTypeDef;
declare const BADGE_TYPES: Record<string, BadgeTypeDef>;
declare function slugForCredentialType(credentialType: string): string | undefined;

declare function badgeScope(slug: string): string;
declare function badgeScopes(slugs: string[]): string[];
declare function badgeTypeOf(vcType: string[]): string | undefined;
declare function getBadgeClaimSchema(slug: string): z.ZodType<unknown> | undefined;
declare function knownBadgeTypes(): string[];

export { ACCOUNT_AGE_MONTHS, AGE_THRESHOLDS, AccountAgeClaims, type AccountAgeMonths, AgeOverClaimsFor, type AgeThreshold, BADGE_TYPES, type BadgeTypeDef, EmailDomainClaims, EmailExactClaims, FOLLOWERS_BUCKETS, type FollowersBucket, InviteCodeClaims, OAUTH_PROVIDERS, OAuthAccountClaims, ResidencyCityClaims, ResidencyCountryClaims, ResidencyStateClaims, SocialFollowingClaims, TlsnAttestationClaims, TwoFactorClaims, badgeScope, badgeScopes, badgeTypeOf, defineBadgeType, getBadgeClaimSchema, knownBadgeTypes, slugForCredentialType };
