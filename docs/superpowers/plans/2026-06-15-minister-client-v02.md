# @minister/client v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape `@minister/client` so its Minister badge/verification layer is first-class and usable independently of the OIDC flow, and add non-invasive Auth.js helpers — without modifying Auth.js.

**Architecture:** One package, three layers (verification, badge vocabulary, flow client) plus an opt-in `auth-js` sub-import. The badge vocabulary becomes a `defineBadgeType` registry (single source of truth). A `createMinisterVerifier` factory (backed by exported standalone functions) verifies id_tokens and badges; `verifyBadges` returns `{ badges, rejected }`. Three package entry points: `.`, `./auth-js`, `./badges`.

**Tech Stack:** TypeScript (strict, ESM), `jose` (JWT/JWKS, EdDSA), `zod` (claim schemas), `tsup` (build), `vitest` (test, offline with injected keys). `@auth/core` is a types-only optional peer used solely by `./auth-js`.

**Spec:** `docs/superpowers/specs/2026-06-15-minister-client-v02-design.md`

**Working directory:** `/Users/atheartengineer/Nextcloud/workspace/MinistryOfMany/minister-client`. Run all commands from there. Tests: `pnpm exec vitest run <path>`. Typecheck: `pnpm exec tsc --noEmit`.

---

## File Structure

Created:
- `src/badges/schemas.ts` — Zod claim schemas + inferred types + `OAUTH_PROVIDERS`/`AGE_THRESHOLDS` (moved from `src/badge-types.ts`).
- `src/badges/registry.ts` — `BadgeTypeDef`, `defineBadgeType`, the per-type entries, `BADGE_TYPES`, and a credentialType→slug index.
- `src/badges/helpers.ts` — `badgeScope`, `badgeScopes`, `badgeTypeOf`, `getBadgeClaimSchema`, `knownBadgeTypes` (derived from `BADGE_TYPES`).
- `src/badges/index.ts` — barrel; the `@minister/client/badges` entry point.
- `src/verify-id-token.ts` — `verifyMinisterIdToken` (+ internal `verifyIdTokenPayload`).
- `src/verify-badges.ts` — `verifyMinisterBadges` (the `{ badges, rejected }` logic).
- `src/verifier.ts` — `createMinisterVerifier` / `MinisterVerifier`.
- `src/auth-js.ts` — `ministerProvider`, `ministerBadgesFromProfile`; the `@minister/client/auth-js` entry point.
- `tsup.config.ts` — multi-entry build (if not already present; otherwise modify).

Modified:
- `src/types.ts` — `VerifiedBadge` (`type` becomes slug, `sub`→`subject`); add `RejectedBadge`, `BadgesResult`; add `raw` to `MinisterClaims`.
- `src/errors.ts` — add `MinisterTokenError`.
- `src/verify-badge.ts` — reshape signature to `(vcJwt, { issuer, jwks? })`; map VC type→slug and schema-validate claims.
- `src/oidc.ts` — `exchangeCode` delegates to the verification layer (removes the double-verify).
- `src/index.ts` — update barrel for the new surface.
- `package.json` — `exports` (`.`, `./auth-js`, `./badges`), optional `@auth/core` peer, scripts unchanged.

Deleted:
- `src/badge-types.ts` (content moves into `src/badges/`).
- `src/badge-types.test.ts` (replaced by `src/badges/*.test.ts`).

---

## Task 1: Badge claim schemas module

Move the Zod schemas out of `badge-types.ts` unchanged so the registry can build on them.

**Files:**
- Create: `src/badges/schemas.ts`
- Test: `src/badges/schemas.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/badges/schemas.test.ts
import { describe, expect, it } from "vitest";
import {
  EmailDomainClaims,
  OAuthAccountClaims,
  TlsnAttestationClaims,
  AGE_THRESHOLDS,
} from "./schemas";

describe("badge claim schemas", () => {
  it("lowercases and validates an email domain", () => {
    expect(EmailDomainClaims.parse({ domain: "Example.COM" })).toEqual({ domain: "example.com" });
  });
  it("rejects a bad domain", () => {
    expect(() => EmailDomainClaims.parse({ domain: "nope" })).toThrow();
  });
  it("rejects unknown keys on tlsn-attestation (strict)", () => {
    expect(() => TlsnAttestationClaims.parse({ domain: "x.com", claim: "a", extra: 1 })).toThrow();
  });
  it("accepts a known oauth provider", () => {
    expect(OAuthAccountClaims.parse({ provider: "github", accountId: "1" }).provider).toBe("github");
  });
  it("exposes the age thresholds", () => {
    expect(AGE_THRESHOLDS).toContain(18);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/badges/schemas.test.ts`
Expected: FAIL — cannot find module `./schemas`.

- [ ] **Step 3: Create `src/badges/schemas.ts`**

Copy the schema bodies from the current `src/badge-types.ts` lines 24–86 verbatim (EmailDomainClaims, EmailExactClaims, OAUTH_PROVIDERS, OAuthAccountClaims, AGE_THRESHOLDS, AgeThreshold, `AgeOverClaimsFor`, COUNTRY_RE, ResidencyCountryClaims/StateClaims/CityClaims, InviteCodeClaims, TlsnAttestationClaims) including their `export type` lines. Export `AgeOverClaimsFor` and `COUNTRY_RE` too (the registry needs them):

```ts
import { z } from "zod";

export const EmailDomainClaims = z.object({
  domain: z.string().min(1).toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/u, "Not a valid domain"),
});
export type EmailDomainClaims = z.infer<typeof EmailDomainClaims>;

export const EmailExactClaims = z.object({ email: z.string().email().toLowerCase() });
export type EmailExactClaims = z.infer<typeof EmailExactClaims>;

export const OAUTH_PROVIDERS = ["github", "google", "discord"] as const;
export const OAuthAccountClaims = z.object({
  provider: z.enum(OAUTH_PROVIDERS),
  accountId: z.string().min(1),
  handle: z.string().min(1).optional(),
});
export type OAuthAccountClaims = z.infer<typeof OAuthAccountClaims>;

export const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;
export type AgeThreshold = (typeof AGE_THRESHOLDS)[number];
export const AgeOverClaimsFor = (threshold: AgeThreshold) => z.object({ threshold: z.literal(threshold) });

const COUNTRY_RE = /^[A-Z]{2}$/u;
export const ResidencyCountryClaims = z.object({ country: z.string().regex(COUNTRY_RE) });
export const ResidencyStateClaims = z.object({ country: z.string().regex(COUNTRY_RE), state: z.string().min(1) });
export const ResidencyCityClaims = z.object({ country: z.string().regex(COUNTRY_RE), state: z.string().min(1), city: z.string().min(1) });
export type ResidencyCountryClaims = z.infer<typeof ResidencyCountryClaims>;
export type ResidencyStateClaims = z.infer<typeof ResidencyStateClaims>;
export type ResidencyCityClaims = z.infer<typeof ResidencyCityClaims>;

export const InviteCodeClaims = z.object({ label: z.string().min(1) });
export type InviteCodeClaims = z.infer<typeof InviteCodeClaims>;

export const TlsnAttestationClaims = z.object({ domain: z.string().min(1), claim: z.string().min(1) }).strict();
export type TlsnAttestationClaims = z.infer<typeof TlsnAttestationClaims>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run src/badges/schemas.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/badges/schemas.ts src/badges/schemas.test.ts
git commit -m "refactor(badges): extract claim schemas into src/badges/schemas.ts"
```

---

## Task 2: Badge-type registry

The single source of truth: one self-describing entry per badge type.

**Files:**
- Create: `src/badges/registry.ts`
- Test: `src/badges/registry.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/badges/registry.test.ts
import { describe, expect, it } from "vitest";
import { BADGE_TYPES, defineBadgeType, slugForCredentialType } from "./registry";
import { z } from "zod";

describe("badge registry", () => {
  it("defineBadgeType derives the scope from the slug", () => {
    const def = defineBadgeType({ slug: "x-test", credentialType: "MinisterXTestCredential", claims: z.object({}) });
    expect(def.scope).toBe("badge:x-test");
  });
  it("registers email-domain with its credentialType and schema", () => {
    const def = BADGE_TYPES["email-domain"];
    expect(def?.credentialType).toBe("MinisterEmailDomainCredential");
    expect(def?.scope).toBe("badge:email-domain");
    expect(def?.claims.parse({ domain: "a.com" })).toEqual({ domain: "a.com" });
  });
  it("registers every age threshold", () => {
    expect(BADGE_TYPES["age-over-18"]?.credentialType).toBe("MinisterAgeOver18Credential");
    expect(BADGE_TYPES["age-over-65"]?.credentialType).toBe("MinisterAgeOver65Credential");
  });
  it("reverse-maps a credentialType to its slug", () => {
    expect(slugForCredentialType("MinisterEmailDomainCredential")).toBe("email-domain");
    expect(slugForCredentialType("MinisterAgeOver21Credential")).toBe("age-over-21");
    expect(slugForCredentialType("NotAThing")).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/badges/registry.test.ts`
Expected: FAIL — cannot find module `./registry`.

- [ ] **Step 3: Create `src/badges/registry.ts`**

```ts
import type { z } from "zod";
import {
  EmailDomainClaims,
  EmailExactClaims,
  OAuthAccountClaims,
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

const ENTRIES: BadgeTypeDef[] = [
  defineBadgeType({ slug: "email-domain", credentialType: "MinisterEmailDomainCredential", claims: EmailDomainClaims }),
  defineBadgeType({ slug: "email-exact", credentialType: "MinisterEmailExactCredential", claims: EmailExactClaims }),
  defineBadgeType({ slug: "oauth-account", credentialType: "MinisterOauthAccountCredential", claims: OAuthAccountClaims }),
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
```

> NOTE: `credentialType` values must match Minister's `@minister/shared` `ministerCredentialType(slug)` output exactly. If a future Minister slug uses irregular casing, fix the literal here (this file is the one place to do it). The planned drift-check will assert these against `@minister/shared`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run src/badges/registry.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/badges/registry.ts src/badges/registry.test.ts
git commit -m "feat(badges): add defineBadgeType registry as the single source of truth"
```

---

## Task 3: Badge vocabulary helpers + `/badges` barrel

**Files:**
- Create: `src/badges/helpers.ts`, `src/badges/index.ts`
- Test: `src/badges/helpers.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/badges/helpers.test.ts
import { describe, expect, it } from "vitest";
import { badgeScope, badgeScopes, badgeTypeOf, getBadgeClaimSchema, knownBadgeTypes } from "./helpers";

describe("badge helpers", () => {
  it("builds a scope string", () => {
    expect(badgeScope("age-over-18")).toBe("badge:age-over-18");
    expect(badgeScopes(["email-domain", "age-over-18"])).toEqual(["badge:email-domain", "badge:age-over-18"]);
  });
  it("maps a VC type array to its slug", () => {
    expect(badgeTypeOf(["VerifiableCredential", "MinisterEmailDomainCredential"])).toBe("email-domain");
    expect(badgeTypeOf(["VerifiableCredential"])).toBeUndefined();
  });
  it("returns a claim schema for a known slug", () => {
    expect(getBadgeClaimSchema("email-domain")?.parse({ domain: "a.com" })).toEqual({ domain: "a.com" });
    expect(getBadgeClaimSchema("nope")).toBeUndefined();
  });
  it("lists known badge types", () => {
    expect(knownBadgeTypes()).toContain("email-domain");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/badges/helpers.test.ts`
Expected: FAIL — cannot find module `./helpers`.

- [ ] **Step 3: Create `src/badges/helpers.ts`**

```ts
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
```

- [ ] **Step 4: Create `src/badges/index.ts` (the `/badges` entry point)**

```ts
// @minister/client/badges — the Minister badge-type vocabulary.
// Dependency-free; safe to import without the verifier or flow client.
export * from "./schemas";
export { BADGE_TYPES, defineBadgeType, slugForCredentialType } from "./registry";
export type { BadgeTypeDef } from "./registry";
export { badgeScope, badgeScopes, badgeTypeOf, getBadgeClaimSchema, knownBadgeTypes } from "./helpers";
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm exec vitest run src/badges/helpers.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 6: Delete the old vocabulary files**

```bash
git rm src/badge-types.ts src/badge-types.test.ts
```

(Their exports are now re-exported from `src/badges/`. `src/index.ts` and `src/verify-badge.ts` are updated in later tasks; a typecheck failure here is expected until then.)

- [ ] **Step 7: Commit**

```bash
git add src/badges/helpers.ts src/badges/helpers.test.ts src/badges/index.ts
git commit -m "feat(badges): add derived helpers and the /badges barrel; drop badge-types.ts"
```

---

## Task 4: Types and errors

**Files:**
- Modify: `src/types.ts`, `src/errors.ts`
- Test: `src/errors.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/errors.test.ts
import { describe, expect, it } from "vitest";
import { MinisterTokenError, VcVerificationError } from "./errors";

describe("errors", () => {
  it("MinisterTokenError carries its name", () => {
    const e = new MinisterTokenError("bad aud");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("MinisterTokenError");
    expect(e.message).toBe("bad aud");
  });
  it("VcVerificationError still exists", () => {
    expect(new VcVerificationError("x").name).toBe("VcVerificationError");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/errors.test.ts`
Expected: FAIL — `MinisterTokenError` is not exported.

- [ ] **Step 3: Add `MinisterTokenError` to `src/errors.ts`**

Append:

```ts
// Thrown when an id_token itself fails verification — signature, issuer,
// audience, expiry, or nonce. The token is the trust root, so this is a
// hard failure (distinct from an individual bad badge, which is reported
// in BadgesResult.rejected rather than thrown).
export class MinisterTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MinisterTokenError";
  }
}
```

- [ ] **Step 4: Update `src/types.ts`**

Replace `MinisterClaims` and `VerifiedBadge` and add the new result types:

```ts
// Identity claims from a verified id_token.
export interface MinisterClaims {
  // Pairwise pseudonymous subject — stable per (issuer, clientId).
  sub: string;
  name?: string;
  picture?: string;
  // The original id_token JWT, for forwarding/storage.
  raw: string;
}

// A signature-verified, schema-validated badge.
export interface VerifiedBadge {
  // The Minister badge slug, e.g. "age-over-18".
  type: string;
  // The credentialSubject claims, validated against the badge's schema
  // (the `id` field is surfaced as `subject`).
  claims: Record<string, unknown>;
  // The credential subject DID (holder), equal to the id_token `sub`.
  subject: string;
  // The original VC JWT, for storage or forwarding.
  raw: string;
}

// A badge that failed verification (bad signature, wrong issuer, expired,
// subject mismatch, unknown type, or invalid claims).
export interface RejectedBadge {
  raw: string;
  error: VcVerificationError;
}

// The outcome of verifying the badges in a token: the usable badges and
// the ones that failed (with reasons). verifyBadges never throws on an
// individual bad badge.
export interface BadgesResult {
  badges: VerifiedBadge[];
  rejected: RejectedBadge[];
}
```

Add the import at the top of `src/types.ts`:

```ts
import type { VcVerificationError } from "./errors";
```

Keep `ExchangeResult` but change its `badges` to reuse `VerifiedBadge[]` (already does). Leave `MinisterClientConfig`, `PkcePair`, `OidcFlowState`, `KeyInput` unchanged.

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm exec vitest run src/errors.test.ts`
Expected: PASS (2 tests). (Project-wide typecheck still fails until Task 5 updates `verify-badge.ts`; that is expected.)

- [ ] **Step 6: Commit**

```bash
git add src/types.ts src/errors.ts src/errors.test.ts
git commit -m "feat(types): add MinisterTokenError, RejectedBadge, BadgesResult; slug-typed VerifiedBadge"
```

---

## Task 5: Reshape `verifyMinisterBadge` (slug + schema-validated claims)

**Files:**
- Modify: `src/verify-badge.ts`, `src/verify-badge.test.ts`
- Reference: `src/test-helpers.ts` (existing offline key/JWT fixtures)

- [ ] **Step 1: Read the existing test helpers**

Run: `sed -n '1,200p' src/test-helpers.ts` — note the helper that signs a VC JWT and the one that returns an injectable public key. Reuse them; do not add network calls. (If a VC-signing helper does not exist, add one that signs `{ iss: did, sub, vc: { type, credentialSubject } }` with `typ: "vc+jwt"`, EdDSA, using a generated key — mirror the existing pattern.)

- [ ] **Step 2: Write the failing test**

```ts
// src/verify-badge.test.ts  (replace the file)
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterBadge } from "./verify-badge";
import { VcVerificationError } from "./errors";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";

async function makeKeyAndSigner() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  async function signVc(claims: Record<string, unknown>, credentialType: string, sub: string) {
    return new SignJWT({ vc: { type: ["VerifiableCredential", credentialType], credentialSubject: { id: sub, ...claims } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" })
      .setIssuer(DID)
      .setSubject(sub)
      .sign(privateKey);
  }
  return { publicJwk, signVc };
}

describe("verifyMinisterBadge", () => {
  it("returns a slug-typed, schema-validated badge", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential", "did:web:ministry.test:users:u1");
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk });
    expect(badge.type).toBe("email-domain");
    expect(badge.claims).toEqual({ domain: "a.com" });
    expect(badge.subject).toBe("did:web:ministry.test:users:u1");
    expect(badge.raw).toBe(jwt);
  });
  it("rejects an unknown credential type", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ x: 1 }, "MinisterMysteryCredential", "did:web:ministry.test:users:u1");
    await expect(verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk })).rejects.toBeInstanceOf(VcVerificationError);
  });
  it("rejects claims that fail the schema", async () => {
    const { publicJwk, signVc } = await makeKeyAndSigner();
    const jwt = await signVc({ domain: "not-a-domain" }, "MinisterEmailDomainCredential", "did:web:ministry.test:users:u1");
    await expect(verifyMinisterBadge(jwt, { issuer: ISSUER, key: publicJwk })).rejects.toBeInstanceOf(VcVerificationError);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pnpm exec vitest run src/verify-badge.test.ts`
Expected: FAIL — `verifyMinisterBadge` old signature `(issuer, vcJwt, options)` does not match `(vcJwt, { issuer, key })`.

- [ ] **Step 4: Reshape `src/verify-badge.ts`**

Change the signature and add slug-mapping + claim validation. Keep the JWKS cache, `remoteJwksFor`, the EdDSA/typ/iss verification, and the holder-binding check (`credentialSubject.id === sub`). Replace the `VerifyBadgeOptions`/signature/return section:

```ts
import { badgeTypeOf, getBadgeClaimSchema } from "./badges/helpers";
// ...keep: createRemoteJWKSet import, didFromIssuer, verifyJwt, VcVerificationError, KeyInput/VerifiedBadge types, jwksCache, remoteJwksFor...

export interface VerifyBadgeOptions {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // Inject the verification key (defaults to the remote JWKS). Pass a
  // public JWK in tests so verification never touches the network.
  key?: KeyInput;
}

export async function verifyMinisterBadge(
  vcJwt: string,
  options: VerifyBadgeOptions,
): Promise<VerifiedBadge> {
  const issuer = options.issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(issuer);
  const key = options.key ?? remoteJwksFor(issuer);

  let payload;
  try {
    const result = await verifyJwt(vcJwt, key, { issuer: expectedIss, algorithms: ["EdDSA"], typ: "vc+jwt" });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(cause instanceof Error ? cause.message : String(cause));
  }

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new VcVerificationError("VC payload missing string `sub`");
  }
  const vc = payload.vc as { type?: unknown; credentialSubject?: unknown } | undefined;
  if (!vc || typeof vc !== "object") throw new VcVerificationError("VC payload missing `vc` envelope");
  if (!Array.isArray(vc.type) || !vc.type.every((t) => typeof t === "string")) {
    throw new VcVerificationError("VC `type` must be a string array");
  }
  if (!vc.credentialSubject || typeof vc.credentialSubject !== "object" || Array.isArray(vc.credentialSubject)) {
    throw new VcVerificationError("VC missing `credentialSubject` object");
  }
  const credentialSubject = vc.credentialSubject as Record<string, unknown>;
  const subjectId = credentialSubject["id"];
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw new VcVerificationError("VC `credentialSubject.id` missing");
  }
  if (subjectId !== payload.sub) {
    throw new VcVerificationError("VC `credentialSubject.id` does not match `sub`");
  }

  // Map the VC type to a known Minister badge slug.
  const slug = badgeTypeOf(vc.type as string[]);
  if (!slug) throw new VcVerificationError(`Unknown Minister badge type: ${(vc.type as string[]).join(",")}`);

  // Validate the claims against that badge type's schema.
  const { id: _id, ...rawClaims } = credentialSubject;
  const schema = getBadgeClaimSchema(slug);
  let claims: Record<string, unknown>;
  try {
    claims = schema ? (schema.parse(rawClaims) as Record<string, unknown>) : rawClaims;
  } catch (cause) {
    throw new VcVerificationError(`Badge ${slug} claims failed validation: ${cause instanceof Error ? cause.message : String(cause)}`);
  }

  return { type: slug, claims, subject: payload.sub, raw: vcJwt };
}
```

Keep `_resetBadgeJwksCache` as-is.

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm exec vitest run src/verify-badge.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add src/verify-badge.ts src/verify-badge.test.ts
git commit -m "feat(verify): verifyMinisterBadge returns slug + schema-validated claims"
```

---

## Task 6: `verifyMinisterIdToken`

**Files:**
- Create: `src/verify-id-token.ts`, `src/verify-id-token.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/verify-id-token.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterIdToken } from "./verify-id-token";
import { MinisterTokenError } from "./errors";

const ISSUER = "https://ministry.test";
const CLIENT = "client-1";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  async function signId(over: Record<string, unknown> = {}, aud = CLIENT) {
    return new SignJWT({ name: "Ada", picture: "p", ...over })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(ISSUER).setSubject("pairwise-sub").setAudience(aud)
      .setExpirationTime("5m").sign(privateKey);
  }
  return { publicJwk, signId };
}

describe("verifyMinisterIdToken", () => {
  it("returns claims for a valid token", async () => {
    const { publicJwk, signId } = await setup();
    const claims = await verifyMinisterIdToken(await signId(), { issuer: ISSUER, clientId: CLIENT, key: publicJwk });
    expect(claims.sub).toBe("pairwise-sub");
    expect(claims.name).toBe("Ada");
  });
  it("rejects a wrong audience when clientId is set", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({}, "other"), { issuer: ISSUER, clientId: CLIENT, key: publicJwk }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
  it("rejects a wrong nonce", async () => {
    const { publicJwk, signId } = await setup();
    await expect(verifyMinisterIdToken(await signId({ nonce: "a" }), { issuer: ISSUER, clientId: CLIENT, key: publicJwk, nonce: "b" }))
      .rejects.toBeInstanceOf(MinisterTokenError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/verify-id-token.test.ts`
Expected: FAIL — cannot find module `./verify-id-token`.

- [ ] **Step 3: Create `src/verify-id-token.ts`**

```ts
import { createRemoteJWKSet, type JWTPayload } from "jose";
import { verifyJwt } from "./jwt";
import { MinisterTokenError } from "./errors";
import type { KeyInput, MinisterClaims } from "./types";

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function remoteJwksFor(issuer: string) {
  let set = jwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache.set(issuer, set);
  }
  return set;
}

export interface VerifyIdTokenOptions {
  issuer: string;
  // When set, the id_token `aud` must equal it. Omit only to skip audience enforcement.
  clientId?: string;
  // Replay nonce; when set, must equal the id_token `nonce`.
  nonce?: string;
  // Inject the verification key (defaults to the remote JWKS).
  key?: KeyInput;
}

// Internal: verify the id_token and return the full payload (callers that
// need minister_badges use this; verifyMinisterIdToken maps to claims).
export async function verifyIdTokenPayload(idToken: string, options: VerifyIdTokenOptions): Promise<JWTPayload> {
  const issuer = options.issuer.replace(/\/$/, "");
  const key = options.key ?? remoteJwksFor(issuer);
  let payload: JWTPayload;
  try {
    const result = await verifyJwt(idToken, key, {
      issuer,
      algorithms: ["EdDSA"],
      ...(options.clientId ? { audience: options.clientId } : {}),
    });
    payload = result.payload;
  } catch (cause) {
    throw new MinisterTokenError(cause instanceof Error ? cause.message : String(cause));
  }
  if (options.nonce !== undefined && payload["nonce"] !== options.nonce) {
    throw new MinisterTokenError("id_token `nonce` mismatch");
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new MinisterTokenError("id_token missing string `sub`");
  }
  return payload;
}

// Verify a Minister id_token and return its identity claims.
export async function verifyMinisterIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<MinisterClaims> {
  const payload = await verifyIdTokenPayload(idToken, options);
  return {
    sub: payload.sub as string,
    name: typeof payload["name"] === "string" ? (payload["name"] as string) : undefined,
    picture: typeof payload["picture"] === "string" ? (payload["picture"] as string) : undefined,
    raw: idToken,
  };
}

export function _resetIdTokenJwksCache(issuer?: string): void {
  if (issuer) jwksCache.delete(issuer.replace(/\/$/, ""));
  else jwksCache.clear();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run src/verify-id-token.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/verify-id-token.ts src/verify-id-token.test.ts
git commit -m "feat(verify): add verifyMinisterIdToken"
```

---

## Task 7: `verifyMinisterBadges` (`{ badges, rejected }`)

**Files:**
- Create: `src/verify-badges.ts`, `src/verify-badges.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/verify-badges.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyMinisterBadges } from "./verify-badges";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  const signVc = (claims: Record<string, unknown>, ct: string) =>
    new SignJWT({ vc: { type: ["VerifiableCredential", ct], credentialSubject: { id: SUB, ...claims } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB).sign(privateKey);
  return { publicJwk, signVc };
}

describe("verifyMinisterBadges", () => {
  it("splits valid and invalid badges from an already-verified payload", async () => {
    const { publicJwk, signVc } = await setup();
    const good = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const bad = await signVc({ domain: "not-a-domain" }, "MinisterEmailDomainCredential");
    const payload = { sub: SUB, minister_badges: [good, bad] };
    const result = await verifyMinisterBadges(payload, { issuer: ISSUER, key: publicJwk });
    expect(result.badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.raw).toBe(bad);
  });
  it("returns empty lists when there are no badges", async () => {
    const { publicJwk } = await setup();
    const result = await verifyMinisterBadges({ sub: SUB }, { issuer: ISSUER, key: publicJwk });
    expect(result).toEqual({ badges: [], rejected: [] });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/verify-badges.test.ts`
Expected: FAIL — cannot find module `./verify-badges`.

- [ ] **Step 3: Create `src/verify-badges.ts`**

```ts
import type { JWTPayload } from "jose";
import { verifyMinisterBadge } from "./verify-badge";
import { verifyIdTokenPayload } from "./verify-id-token";
import { VcVerificationError } from "./errors";
import type { KeyInput, BadgesResult } from "./types";

export interface VerifyBadgesOptions {
  issuer: string;
  // Needed only when a raw id_token string is passed (to verify the wrapper).
  clientId?: string;
  key?: KeyInput;
}

// Verify the `minister_badges` carried by a token.
//
// - Given a raw id_token STRING, the wrapper is verified first (throws
//   MinisterTokenError if it fails), then its badges are read.
// - Given an already-verified PAYLOAD object (e.g. Auth.js's profile, or
//   a prior verifyIdToken result), the wrapper is trusted and only the
//   badges are verified.
//
// Individual bad badges never throw — they are returned in `rejected`.
export async function verifyMinisterBadges(
  tokenOrPayload: string | JWTPayload,
  options: VerifyBadgesOptions,
): Promise<BadgesResult> {
  const payload =
    typeof tokenOrPayload === "string"
      ? await verifyIdTokenPayload(tokenOrPayload, options)
      : tokenOrPayload;

  const raw = (payload as Record<string, unknown>)["minister_badges"];
  if (raw === undefined || raw === null) return { badges: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { badges: [], rejected: [{ raw: String(raw), error: new VcVerificationError("minister_badges is not an array") }] };
  }

  const result: BadgesResult = { badges: [], rejected: [] };
  for (const entry of raw) {
    if (typeof entry !== "string") {
      result.rejected.push({ raw: String(entry), error: new VcVerificationError("badge entry is not a JWT string") });
      continue;
    }
    try {
      result.badges.push(await verifyMinisterBadge(entry, { issuer: options.issuer, key: options.key }));
    } catch (cause) {
      result.rejected.push({
        raw: entry,
        error: cause instanceof VcVerificationError ? cause : new VcVerificationError(String(cause)),
      });
    }
  }
  return result;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run src/verify-badges.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/verify-badges.ts src/verify-badges.test.ts
git commit -m "feat(verify): add verifyMinisterBadges returning { badges, rejected }"
```

---

## Task 8: `createMinisterVerifier` factory

**Files:**
- Create: `src/verifier.ts`, `src/verifier.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/verifier.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { createMinisterVerifier } from "./verifier";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const CLIENT = "client-1";
const SUB = "did:web:ministry.test:users:u1";

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  const signVc = (claims: Record<string, unknown>, ct: string) =>
    new SignJWT({ vc: { type: ["VerifiableCredential", ct], credentialSubject: { id: SUB, ...claims } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB).sign(privateKey);
  const signId = (over: Record<string, unknown> = {}) =>
    new SignJWT(over).setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuer(ISSUER).setSubject("pairwise").setAudience(CLIENT).setExpirationTime("5m").sign(privateKey);
  return { publicJwk, signVc, signId };
}

describe("createMinisterVerifier", () => {
  it("verifies an id_token and its badges with one configured instance", async () => {
    const { publicJwk, signVc, signId } = await setup();
    const badge = await signVc({ domain: "a.com" }, "MinisterEmailDomainCredential");
    const idToken = await signId({ name: "Ada", minister_badges: [badge] });
    const verifier = createMinisterVerifier({ issuer: ISSUER, clientId: CLIENT, jwks: publicJwk });

    const claims = await verifier.verifyIdToken(idToken);
    expect(claims.sub).toBe("pairwise");

    const { badges, rejected } = await verifier.verifyBadges(idToken);
    expect(badges.map((b) => b.type)).toEqual(["email-domain"]);
    expect(rejected).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm exec vitest run src/verifier.test.ts`
Expected: FAIL — cannot find module `./verifier`.

- [ ] **Step 3: Create `src/verifier.ts`**

```ts
import { verifyMinisterIdToken } from "./verify-id-token";
import { verifyMinisterBadges } from "./verify-badges";
import { verifyMinisterBadge } from "./verify-badge";
import type { JWTPayload } from "jose";
import type { KeyInput, MinisterClaims, VerifiedBadge, BadgesResult } from "./types";

export interface MinisterVerifierConfig {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // When set, id_token `aud` is checked against it. Recommended.
  clientId?: string;
  // Inject the verification key (defaults to Minister's remote JWKS,
  // fetched once and reused). Pass a public JWK in tests.
  jwks?: KeyInput;
}

export interface MinisterVerifier {
  verifyIdToken(idToken: string, opts?: { nonce?: string }): Promise<MinisterClaims>;
  verifyBadges(tokenOrPayload: string | JWTPayload): Promise<BadgesResult>;
  verifyBadge(vcJwt: string): Promise<VerifiedBadge>;
}

// Configure-once, reuse: holds issuer/clientId and the (shared) key source
// so the underlying verifiers reuse the same cached JWKS.
export function createMinisterVerifier(config: MinisterVerifierConfig): MinisterVerifier {
  const { issuer, clientId, jwks } = config;
  return {
    verifyIdToken: (idToken, opts) =>
      verifyMinisterIdToken(idToken, { issuer, clientId, key: jwks, nonce: opts?.nonce }),
    verifyBadges: (tokenOrPayload) =>
      verifyMinisterBadges(tokenOrPayload, { issuer, clientId, key: jwks }),
    verifyBadge: (vcJwt) => verifyMinisterBadge(vcJwt, { issuer, key: jwks }),
  };
}
```

> NOTE: when `jwks` is omitted, each underlying function falls back to its own module-level remote-JWKS cache keyed by issuer, so keys are still fetched at most once per issuer per process.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm exec vitest run src/verifier.test.ts`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add src/verifier.ts src/verifier.test.ts
git commit -m "feat(verify): add createMinisterVerifier factory"
```

---

## Task 9: Refactor flow client `exchangeCode` to use the verifier

`OidcCore.exchangeCode` (`src/oidc.ts`) currently calls a private `verifyIdToken` then a private `extractBadges`, and `extractBadges` re-verifies the id_token just to read `minister_badges` (the double-verify). Replace both with the verification layer: verify the id_token once, pass the payload to `verifyMinisterBadges`. Also delete the duplicate `badgeScope` (now in `src/badges/helpers.ts`) and the now-stale `verifyMinisterBadge` call (its signature changed in Task 5).

**Files:**
- Modify: `src/oidc.ts`, `src/oidc.test.ts`

- [ ] **Step 1: See the current oidc test assertions**

Run: `pnpm exec vitest run src/oidc.test.ts` — note any assertion on a badge's `type` (was `string[]`, becomes the slug string) or `sub` (becomes `subject`), and whether a bad id_token is asserted to throw `OidcError` (it will now throw `MinisterTokenError`).

- [ ] **Step 2: Update imports in `src/oidc.ts`**

Remove `import { verifyJwt } from "./jwt";` and `import { verifyMinisterBadge } from "./verify-badge";`. Add:

```ts
import { verifyIdTokenPayload } from "./verify-id-token";
import { verifyMinisterBadges } from "./verify-badges";
```

Drop `VerifiedBadge` from the `./types` import (unused after the private methods are deleted); keep `ExchangeResult`, `KeyInput`, `MinisterClaims`, `MinisterClientConfig`.

- [ ] **Step 3: Delete the duplicate `badgeScope`**

Delete the `export function badgeScope(slug: string): string { return \`badge:${slug}\`; }` block (and its doc comment). The root barrel re-exports `badgeScope` from `./badges` in Task 11.

- [ ] **Step 4: Rewrite `exchangeCode`'s verification tail and delete the private methods**

In `exchangeCode`, replace the `this.verifyIdToken(...)` call, the `this.extractBadges(...)` call, and the `return { claims, badges }` with:

```ts
    const idKey = args.idTokenKey ?? idTokenJwks(this.issuer, d.jwks_uri);
    const payload = await verifyIdTokenPayload(tokens.id_token, {
      issuer: d.issuer,
      clientId: this.clientId,
      nonce: args.expectedNonce,
      key: idKey,
    });
    const claims: MinisterClaims = {
      sub: payload.sub as string,
      name: typeof payload["name"] === "string" ? (payload["name"] as string) : undefined,
      picture: typeof payload["picture"] === "string" ? (payload["picture"] as string) : undefined,
      raw: tokens.id_token,
    };
    const { badges } = await verifyMinisterBadges(payload, {
      issuer: this.issuer,
      key: args.badgeKey,
    });
    return { claims, badges };
```

Then DELETE the private `verifyIdToken(...)` method and the private `extractBadges(...)` method entirely. Keep `discover`, `idTokenJwks`, and `_resetOidcCaches`.

Behavior changes to note in the commit message: a bad id_token now throws `MinisterTokenError` (was `OidcError`); a badge that fails verification is now dropped from `badges` (was: threw `OidcError`). Both match the v0.2 model. (`verifyIdTokenPayload` uses `issuer: d.issuer` and the discovery-derived `idTokenJwks`, preserving the current discovery-driven verification; badge verification uses the `${issuer}/.well-known/jwks.json` default via `args.badgeKey`.)

- [ ] **Step 5: Update `src/oidc.test.ts`**

Change badge assertions to the new shape (`badge.type` is the slug string; `badge.subject`). If a test asserted `OidcError` on an invalid id_token, change it to `MinisterTokenError` (import from `./errors`). If a test asserted a throw on a bad badge, change it to assert that badge is absent from `badges`.

- [ ] **Step 6: Run the oidc tests**

Run: `pnpm exec vitest run src/oidc.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/oidc.ts src/oidc.test.ts
git commit -m "refactor(flow): exchangeCode verifies the id_token once via the verification layer"
```

---

## Task 10: Auth.js adapter (`@minister/client/auth-js`)

**Files:**
- Create: `src/auth-js.ts`, `src/auth-js.test.ts`
- Modify: `package.json` (add `@auth/core` optional peer)

- [ ] **Step 1: Add `@auth/core` as a types-only optional peer**

Run:
```bash
pnpm add -D @auth/core@^0.37.0
```
Then in `package.json` add (merge, do not overwrite existing keys):
```json
"peerDependencies": { "@auth/core": "^0.37.0" },
"peerDependenciesMeta": { "@auth/core": { "optional": true } }
```
(Keep it in `devDependencies` too so this package's own typecheck/tests resolve it. Consumers who do not use `./auth-js` never load it.)

- [ ] **Step 2: Write the failing test**

```ts
// src/auth-js.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { ministerProvider, ministerBadgesFromProfile } from "./auth-js";

const ISSUER = "https://ministry.test";
const DID = "did:web:ministry.test";
const SUB = "did:web:ministry.test:users:u1";

describe("auth-js adapter", () => {
  it("ministerProvider returns an oidc provider config with the requested scopes", () => {
    const p = ministerProvider({ clientId: "c", clientSecret: "s", issuer: ISSUER, scopes: ["openid", "badge:age-over-18"] });
    expect(p.id).toBe("minister");
    expect(p.type).toBe("oidc");
    expect(p.issuer).toBe(ISSUER);
    expect(p.authorization).toMatchObject({ params: { scope: "openid badge:age-over-18" } });
    expect(p.checks).toEqual(expect.arrayContaining(["pkce", "state", "nonce"]));
  });
  it("ministerBadgesFromProfile verifies badges from a profile payload", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const publicJwk = await exportJWK(publicKey);
    const vc = await new SignJWT({ vc: { type: ["VerifiableCredential", "MinisterEmailDomainCredential"], credentialSubject: { id: SUB, domain: "a.com" } } })
      .setProtectedHeader({ alg: "EdDSA", typ: "vc+jwt" }).setIssuer(DID).setSubject(SUB).sign(privateKey);
    const profile = { sub: SUB, minister_badges: [vc] };
    const { badges } = await ministerBadgesFromProfile(profile, { issuer: ISSUER, key: publicJwk });
    expect(badges.map((b) => b.type)).toEqual(["email-domain"]);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pnpm exec vitest run src/auth-js.test.ts`
Expected: FAIL — cannot find module `./auth-js`.

- [ ] **Step 4: Create `src/auth-js.ts`**

```ts
// @minister/client/auth-js — non-invasive helpers for Auth.js (next-auth).
// We do NOT modify Auth.js; these are values/functions you hand to it via
// its documented extension points. `@auth/core` is a types-only optional
// peer used solely for the OIDCConfig return type.
import type { OIDCConfig } from "@auth/core/providers";
import type { JWTPayload } from "jose";
import { verifyMinisterBadges } from "./verify-badges";
import type { KeyInput, BadgesResult } from "./types";

export interface MinisterProviderOptions {
  clientId: string;
  clientSecret?: string;
  issuer: string;
  // Defaults to ["openid", "profile"]. Add badge:<type> scopes to request badges.
  scopes?: string[];
}

// Build the Auth.js OIDC provider config object. Drop it into
// NextAuth({ providers: [ministerProvider({...})] }). Auth.js owns the
// flow, session, and cookies; this is only its provider configuration.
export function ministerProvider(options: MinisterProviderOptions): OIDCConfig<Record<string, unknown>> {
  const scopes = options.scopes ?? ["openid", "profile"];
  return {
    id: "minister",
    name: "Minister",
    type: "oidc",
    issuer: options.issuer,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: { params: { scope: scopes.join(" ") } },
    checks: ["pkce", "state", "nonce"],
  };
}

export interface MinisterBadgesFromProfileOptions {
  issuer: string;
  key?: KeyInput;
}

// Verify the minister_badges in an Auth.js `profile` (already-verified
// id_token payload). Call inside your own jwt/profile callback.
export function ministerBadgesFromProfile(
  profile: JWTPayload | Record<string, unknown>,
  options: MinisterBadgesFromProfileOptions,
): Promise<BadgesResult> {
  return verifyMinisterBadges(profile as JWTPayload, { issuer: options.issuer, key: options.key });
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm exec vitest run src/auth-js.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add src/auth-js.ts src/auth-js.test.ts package.json
git commit -m "feat(auth-js): add non-invasive ministerProvider + ministerBadgesFromProfile"
```

---

## Task 11: Packaging — entry points, barrel, build

**Files:**
- Modify: `package.json`, `tsup.config.ts`, `src/index.ts`

- [ ] **Step 1: Update `package.json` `exports`**

Set `exports` to the three entry points (keep `main`/`module`/`types` for the root):

```json
"exports": {
  ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
  "./auth-js": { "types": "./dist/auth-js.d.ts", "import": "./dist/auth-js.js" },
  "./badges": { "types": "./dist/badges/index.d.ts", "import": "./dist/badges/index.js" }
}
```

- [ ] **Step 2: Update `tsup.config.ts` to multi-entry**

```ts
import { defineConfig } from "tsup";
export default defineConfig({
  entry: ["src/index.ts", "src/auth-js.ts", "src/badges/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  external: ["jose", "zod", "@auth/core"],
});
```

- [ ] **Step 3: Update `src/index.ts` barrel**

```ts
// @minister/client — Minister relying-party SDK.

// Flow client (for apps hand-rolling OIDC)
export { createMinisterClient } from "./client";
export type { MinisterClient } from "./client";
export { OidcCore } from "./oidc";
export type { GetAuthorizationUrlArgs, ExchangeCodeArgs } from "./oidc";
export { generatePkce, randomUrlToken } from "./pkce";
export { buildDid, didFromIssuer } from "./did";

// Verification layer
export { createMinisterVerifier } from "./verifier";
export type { MinisterVerifier, MinisterVerifierConfig } from "./verifier";
export { verifyMinisterIdToken } from "./verify-id-token";
export type { VerifyIdTokenOptions } from "./verify-id-token";
export { verifyMinisterBadges } from "./verify-badges";
export type { VerifyBadgesOptions } from "./verify-badges";
export { verifyMinisterBadge } from "./verify-badge";
export type { VerifyBadgeOptions } from "./verify-badge";

// Errors
export { VcVerificationError, OidcError, MinisterTokenError } from "./errors";

// Shared types
export type {
  MinisterClientConfig, PkcePair, OidcFlowState, MinisterClaims,
  VerifiedBadge, RejectedBadge, BadgesResult, ExchangeResult, KeyInput,
} from "./types";

// Badge vocabulary (also available standalone at "@minister/client/badges")
export * from "./badges/index";
```

> If `badgeScope` is exported from both `./oidc` and `./badges/index`, keep only one — prefer the `./badges` one and remove the `./oidc` re-export from this barrel (and from `oidc.ts` if it duplicates the helper). Resolve the duplicate so typecheck passes.

- [ ] **Step 4: Typecheck, full test, build**

Run:
```bash
pnpm exec tsc --noEmit
pnpm exec vitest run
pnpm run build
```
Expected: typecheck clean; all tests pass; `dist/` emits `index.*`, `auth-js.*`, `badges/index.*` (`.js` + `.d.ts`).

- [ ] **Step 5: Commit**

```bash
git add package.json tsup.config.ts src/index.ts src/oidc.ts
git commit -m "build: expose ./auth-js and ./badges entry points; update root barrel"
```

---

## Task 12: README — document the two integration modes

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Verifying tokens & badges" section**

Show the backend verifier path (the common case):

````md
## Verify a Minister login on your backend

```ts
import { createMinisterVerifier } from "@minister/client";

const minister = createMinisterVerifier({ issuer: "https://ministry.id", clientId: "your-client-id" });

const claims = await minister.verifyIdToken(idToken);          // throws on a bad token
const { badges, rejected } = await minister.verifyBadges(idToken);
// badges: [{ type: "age-over-18", claims: { threshold: 18 }, subject, raw }]
```
````

- [ ] **Step 2: Add an "Auth.js" section**

````md
## With Auth.js (next-auth)

```ts
import NextAuth from "next-auth";
import { ministerProvider, ministerBadgesFromProfile } from "@minister/client/auth-js";
import { badgeScopes } from "@minister/client/badges";

export const { handlers, auth } = NextAuth({
  providers: [
    ministerProvider({
      clientId: process.env.MINISTER_CLIENT_ID!,
      clientSecret: process.env.MINISTER_CLIENT_SECRET,
      issuer: process.env.MINISTER_ISSUER!,
      scopes: ["openid", "profile", ...badgeScopes(["age-over-18"])],
    }),
  ],
  callbacks: {
    async jwt({ token, profile }) {
      if (profile) {
        const { badges } = await ministerBadgesFromProfile(profile, { issuer: process.env.MINISTER_ISSUER! });
        token.ministerBadges = badges;
      }
      return token;
    },
  },
});
```

We do not modify Auth.js — `ministerProvider` returns a standard OIDC provider config and `ministerBadgesFromProfile` runs inside your own callback.
````

- [ ] **Step 3: Note the hand-rolled flow + the `/badges` import**

Add a one-paragraph pointer that apps hand-rolling OIDC use `createMinisterClient` (existing v0.1 surface), and that the badge vocabulary is importable standalone from `@minister/client/badges`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document backend verifier and Auth.js integration modes"
```

---

## Final verification

- [ ] Run the whole suite and build once more:

```bash
pnpm exec tsc --noEmit && pnpm exec vitest run && pnpm run build
```
Expected: typecheck clean, all tests pass, `dist/` contains the three entry points.

- [ ] Confirm no `src/badge-types.ts` references remain: `grep -rn "badge-types" src` returns nothing.

---

## Notes for the implementer

- **TDD throughout:** every task is test-first. Do not write implementation before the failing test.
- **Offline tests only:** generate keys with `jose`'s `generateKeyPair("EdDSA")`, sign fixtures, and pass the public JWK via the `key`/`jwks` option. Never hit the network in tests.
- **id_token `iss` vs VC `iss`:** the id_token issuer is the https origin (e.g. `https://ministry.id`); the VC issuer is the `did:web` (`didFromIssuer(issuer)`). `verify-id-token.ts` checks the former, `verify-badge.ts` the latter. Do not conflate them.
- **Non-invasive Auth.js:** `src/auth-js.ts` may import `@auth/core` types ONLY; never import its runtime, and never add it as a non-optional dependency.
- **Out of scope (do not build):** openid-client/Passport adapters; the drift-check against `@minister/shared`; npm publish. These are tracked follow-ons in the spec.
