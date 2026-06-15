import type { z } from "zod";
import { BADGE_TYPES, slugForCredentialType } from "./registry";

// The OIDC scope a relying party requests to ask for a badge type.
export function badgeScope(slug: string): string {
  return `badge:${slug}`;
}

// Map an array of slugs to their scope strings.
export function badgeScopes(slugs: string[]): string[] {
  return slugs.map(badgeScope);
}

// Given a VC `type` array, return the Minister badge slug it represents,
// or undefined if it is not a known Minister badge type.
export function badgeTypeOf(vcType: string[]): string | undefined {
  for (const t of vcType) {
    const slug = slugForCredentialType(t);
    if (slug) return slug;
  }
  return undefined;
}

// The Zod claim schema for a badge slug, or undefined if unknown.
export function getBadgeClaimSchema(slug: string): z.ZodType<unknown> | undefined {
  return BADGE_TYPES[slug]?.claims;
}

// Every badge slug this SDK knows.
export function knownBadgeTypes(): string[] {
  return Object.keys(BADGE_TYPES);
}
