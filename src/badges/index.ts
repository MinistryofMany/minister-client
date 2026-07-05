// @ministryofmany/client/badges - the Minister badge-type vocabulary.
//
// Dependency-free; safe to import without the verifier or flow client.
//
// This vocabulary is a deliberate COPY of Minister's authoritative
// registry (`@ministryofmany/shared`), not an import, so this SDK publishes
// standalone with no dependency on Minister's internal packages. It
// carries only what a relying party needs - claim schemas, slugs,
// credentialType mappings, and scope helpers - and omits provider/UI
// concerns (icon keys, display labels, issuance helpers). Because it is a
// copy it can drift; `drift.test.ts` pins this registry (slug set,
// credentialType, sybilResistance, and schema shape) against a frozen
// transcription of `@ministryofmany/shared` — update both in lockstep.
export * from "./schemas";
export { BADGE_TYPES, defineBadgeType, slugForCredentialType } from "./registry";
export type { BadgeTypeDef, SybilResistance } from "./registry";
export { badgeScope, badgeScopes, badgeTypeOf, getBadgeClaimSchema, knownBadgeTypes } from "./helpers";
