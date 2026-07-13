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

// GitHub-derived (provider-generic) coarse anti-sybil badges. Kept in sync with
// Minister's @ministryofmany/shared. Both are `moderate` sybilResistance (an
// aged/followed account is costlier to farm), and both are STRICT — unknown keys
// are rejected, never stripped.

// "Account is older than N months" — a coarse lower bound, never the exact date.
export const ACCOUNT_AGE_MONTHS = [12, 24, 36, 60] as const;
export type AccountAgeMonths = (typeof ACCOUNT_AGE_MONTHS)[number];
export const AccountAgeClaims = z
  .object({
    provider: z.enum(OAUTH_PROVIDERS),
    olderThanMonths: z.union([z.literal(12), z.literal(24), z.literal(36), z.literal(60)]),
  })
  .strict();
export type AccountAgeClaims = z.infer<typeof AccountAgeClaims>;

// "At least N followers" — a coarse bucket, never the exact count.
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

// Group membership — the holder belongs to a Ministry group with a role. The
// `group` slug is the RP gating key (rooms gate on `where: { group: "<slug>" }`);
// `groupId` pins the claim to a specific group row so a renamed or
// deleted-and-recreated slug can't let a stale VC satisfy a gate for a different
// group under the same name. STRICT — unknown keys are rejected, never stripped
// (the disclosure path re-signs whatever this schema returns). This is the one
// REVOCABLE badge type (see registry `revocable`): a kicked member's disclosed
// VC carries a `credentialStatus` the RP sweeps via createMinisterStatusChecker.
// Kept in sync with Minister's @ministryofmany/shared GroupMembershipClaims.
export const GROUP_ROLES = ["owner", "admin", "member"] as const;
export type GroupRole = (typeof GROUP_ROLES)[number];
export const GroupMembershipClaims = z
  .object({
    // The group's canonical slug — same charset as the server-side founding
    // validator ([a-z0-9] with single internal hyphens).
    group: z
      .string()
      .min(1)
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u, "Not a valid group slug"),
    role: z.enum(GROUP_ROLES),
    // Opaque Group.id, pinning the claim to a specific group row.
    groupId: z.string().min(1),
  })
  .strict();
export type GroupMembershipClaims = z.infer<typeof GroupMembershipClaims>;
