# @minister/client v0.2 — Design

Date: 2026-06-15
Status: Approved (brainstorming) — ready for implementation planning

## Context & goal

`@minister/client` v0.1 is a full hand-rolled OIDC relying-party (RP) flow plus
badge-VC verification — it assumes the app implements OIDC itself (the FreedInk
case). But most client-app developers use an OIDC library (Auth.js, openid-client,
Passport). For those apps the flow is a commodity their library already handles
well; what they cannot get elsewhere is the **Minister-specific badge layer** —
verifying the nested `minister_badges` verifiable credentials, the badge
vocabulary, and scope helpers (Auth.js verifies the id_token but treats the badge
VCs as opaque strings).

v0.2 reshapes the SDK so the badge/verification layer is first-class and usable
*independently of the flow*, and adds **non-invasive** helpers that plug into
Auth.js through its public extension points. We do **not** modify, fork, vendor,
or version-pin Auth.js; the app brings its own.

Goal: the easiest, most transparent DX for someone building a Minister client app,
whether they hand-roll OIDC or use a library, without hiding the security-relevant
mechanics.

## Decisions (settled during brainstorming)

1. **Scope:** this spec covers the SDK v0.2 capability only. Migrating Discreetly
   to consume it is a separate follow-on spec.
2. **Verification surface:** a `createMinisterVerifier({ issuer })` factory
   (configure once, reuse; caches Minister's JWKS) is the headline. The underlying
   standalone functions are also exported for one-off use.
3. **Packaging:** one package, `@minister/client`, with sub-imports
   `@minister/client/auth-js` (Auth.js helpers) and `@minister/client/badges`
   (vocabulary). Only Auth.js users pull anything Auth.js-related.
4. **Bad badges:** `verifyBadges` returns the valid badges *and* a separate
   `rejected` list (with reasons). It never throws on an individual bad badge — a
   failed/expired badge simply isn't usable, login still proceeds.
5. **Auth.js integration is non-invasive:** a provider-config factory plus a
   callback helper, both consumed by Auth.js via its documented extension points.
   `@auth/core` is an optional **types-only peer**, scoped to the `auth-js`
   sub-import.

## Architecture

Three layers by consumer, plus the opt-in Auth.js adapter. Each layer is
independently usable; dependencies point one direction only.

### Layer 1 — Verification (the universal core)

For backends / API authorities that receive a Minister token and must confirm it
and read the user's badges. Depends only on Layer 2 (vocabulary) and `jose`.

```
createMinisterVerifier({ issuer, clientId?, jwks? }) → MinisterVerifier
  verifyIdToken(idToken, { nonce? }) → Promise<MinisterClaims>   // throws MinisterTokenError on a bad token
  verifyBadges(idTokenOrPayload)     → Promise<BadgesResult>     // { badges, rejected } — never throws per-badge
  verifyBadge(vcJwt)                 → Promise<VerifiedBadge>    // throws VcVerificationError
```

The verifier holds a cached remote JWKS (fetched once from
`${issuer}/.well-known/jwks.json`, reused). `jwks` is injectable for tests and
custom key sources. The same three operations are exported as standalone
functions: `verifyMinisterIdToken(idToken, opts)`,
`verifyMinisterBadges(tokenOrPayload, opts)`, `verifyMinisterBadge(vcJwt, opts)`.

Two clarifications on the contract:

- **`clientId` enables the audience check.** When set, the id_token's `aud` must
  equal it. Omit `clientId` only if you intentionally do not enforce audience.
  Recommended for any backend verifying tokens addressed to it.
- **`verifyBadges` input — raw token vs already-verified payload.** Given a raw
  id_token **string**, `verifyBadges` first verifies the id_token in full (same
  checks as `verifyIdToken`) before reading `minister_badges` — so the badge list
  is never trusted from an unverified wrapper. Given an **already-verified
  claims/payload object** (e.g. the `profile` Auth.js hands you, which Auth.js has
  already verified, or the result of a prior `verifyIdToken`), it skips the wrapper
  re-verification and only verifies the badge VCs. The Auth.js helper uses the
  payload path.

### Layer 2 — Badge-type vocabulary (built to grow)

Dependency-free module (`src/badges/`). Imports nothing from the verifier or flow
client; they depend on it, never the reverse. Each badge type is **one
self-describing entry**:

```
const ageOver18 = defineBadgeType({
  slug: "age-over-18",
  credentialType: "MinisterAgeOver18Credential",  // matches the VC's type[] entry
  scope: "badge:age-over-18",
  claims: z.object({ threshold: z.literal(18) }),
});
// BADGE_TYPES: Record<slug, BadgeTypeDef> assembled from all entries
```

Everything else is a thin derivation of `BADGE_TYPES` — no parallel lists:
`badgeScope(slug)`, `badgeScopes(slugs[])`, `badgeTypeOf(vc)` (reverse lookup by
`credentialType` → slug), `getBadgeClaimSchema(slug)`, `knownBadgeTypes()`, and
the per-type TS claim types. Adding a badge type = adding one
`defineBadgeType(...)` entry; every helper, scope, schema, and the verifier's
type-mapping pick it up automatically. This module is the sync point with
Minister's `packages/shared` registry (see Follow-ons: drift-check).

Exported from the main entry and as `@minister/client/badges` for
vocabulary-only consumers (scope lists, claim parsing, UI badge metadata).

### Layer 3 — Flow client (existing, lightly refactored)

For hand-rollers (the original v0.1 surface): `createMinisterClient(...)` →
`getAuthorizationUrl`, `exchangeCode`, `generatePkce`. `exchangeCode` is
refactored to call Layer 1 internally for its id_token/badge verification, which
also removes the redundant double-verify flagged in the v0.1 build.

### Auth.js adapter — `@minister/client/auth-js` (opt-in)

Non-invasive: returns data/functions the app hands to Auth.js; Auth.js itself is
untouched.

```
ministerProvider({ clientId, clientSecret, issuer, scopes? }) → OIDCConfig
  // the provider-config object you drop into NextAuth({ providers: [...] })

ministerBadgesFromProfile(profile, { issuer, jwks? }) → Promise<BadgesResult>
  // call inside your own Auth.js jwt/profile callback to verify minister_badges
```

`@auth/core` is an optional peer dependency, types only, used solely to type
`OIDCConfig` for this sub-import. Apps using the adapter already have it; others
never load it.

## Public types

```
interface MinisterClaims  { sub: string; name?: string; picture?: string; raw: string }
interface VerifiedBadge   { type: string /* slug */; claims: Record<string, unknown> /* schema-validated */; subject: string; raw: string }
interface RejectedBadge   { raw: string; error: VcVerificationError }
interface BadgesResult    { badges: VerifiedBadge[]; rejected: RejectedBadge[] }
```

`VerifiedBadge.type` is the friendly slug (via `badgeTypeOf`). `claims` is
validated against that badge's Zod schema. `subject` is the holder-bound
`credentialSubject.id`, asserted equal to the id_token `sub`.

## Behavior

### Consent model (background — Minister-side, not implemented here)

A client app *requests* badge types via `badge:<type>` scopes (the scopes passed
to `getAuthorizationUrl` / `ministerProvider`). Minister shows the user a consent
screen with a per-badge toggle; only approved badges land in `minister_badges`.
Declining does not abort login. **DX consequence:** a requested badge may simply
be absent from the token. The app's usable set is *disclosed AND valid*; the app
decides whether that satisfies the action and otherwise prompts the user to share
more. The SDK surfaces the disclosed-and-valid badges plus the `rejected` list; it
never forces disclosure.

### Bad-badge handling

`verifyBadges` extracts `minister_badges`, verifies each VC independently, and
returns `{ badges, rejected }`. A badge that fails (bad signature, wrong issuer,
expired, subject mismatch) goes in `rejected` with its error; it never counts as
valid and never blocks the other badges or the login.

### Errors

Typed and predictable. `verifyIdToken` throws `MinisterTokenError` on a bad token
itself (signature / issuer / audience / expiry) — the token is the trust root.
`verifyBadge` throws `VcVerificationError`. `verifyBadges` never throws on
individual bad badges (they go in `rejected`). When given a raw id_token string it
verifies the wrapper first, so it throws `MinisterTokenError` if that fails; given
an already-verified payload it throws only on malformed input.

## Testing

Fully offline. Tests generate an Ed25519 key, sign test id_tokens and VCs, and
inject the public key / JWKS (no network), mirroring Minister's real contract
(EdDSA, `typ: vc+jwt`, `did:web` issuer, pairwise `sub`). Cases: valid; expired;
bad signature; wrong issuer; subject mismatch; declined/absent badge; and a mixed
valid+invalid set (proves the `{ badges, rejected }` split). These fixtures match
Discreetly's mock-issuer oracle.

## Packaging & dependencies

- Build: `tsup` → `dist` (`.js` + `.d.ts`). `prepare` script builds on install
  (keeps git-URL consumers working until npm publish).
- `package.json` `exports`: `.` (main: verifier, standalone fns, vocabulary,
  flow client), `./auth-js`, `./badges`.
- Dependencies: `jose`, `zod` (regular). `@auth/core` — optional peer, types only,
  for the `auth-js` entry.

## Non-goals / out of scope

- No `openid-client` / Passport adapters. Those apps consume the standalone
  verification functions directly; we do not wrap their internals (YAGNI).
- No modification, fork, vendoring, or version-pinning of Auth.js.
- The Discreetly migration (consuming this SDK) is a separate spec.
- npm publishing is a separate operational step (see Follow-ons).

## Follow-ons (tracked, not in this spec)

- **Drift-check** comparing `@minister/client`'s badge registry against Minister's
  `packages/shared` registry entry-for-entry (CI).
- **npm publish** of `@minister/client` (adds an `integrity` hash; lets consumers
  use semver instead of a commit-pinned git URL).
- Align the `jose` major version across `@minister/client` and consuming apps when
  convenient (FreedInk currently pins `jose@^6`, the SDK `^5`; separate copies,
  runtime unaffected).
