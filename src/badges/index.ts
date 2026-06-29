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
// copy it can drift; a drift-check against `@ministryofmany/shared` is planned.
export * from "./schemas";
export { BADGE_TYPES, defineBadgeType, slugForCredentialType } from "./registry";
export type { BadgeTypeDef } from "./registry";
export { badgeScope, badgeScopes, badgeTypeOf, getBadgeClaimSchema, knownBadgeTypes } from "./helpers";
