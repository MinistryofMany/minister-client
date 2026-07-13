import { describe, expect, it } from "vitest";

import { BADGE_TYPES } from "./registry";
import { getBadgeClaimSchema, knownBadgeTypes } from "./helpers";

// ===========================================================================
// Cross-package drift gate: this SDK's badge registry is a MIRROR of Minister's
// `@ministryofmany/shared` provider-side registry. The two live in separate
// repos with no shared dependency, so this test pins the SDK against a frozen
// CANONICAL contract that transcribes `@ministryofmany/shared`
// (packages/shared/src/badge-types.ts): the slug set, each type's
// `credentialType` (the VC `type[]` entry Minister stamps), its
// `sybilResistance`, and its claim-schema SHAPE (sample validity + strictness).
//
// When Minister's shared registry changes, update EXPECTED here in the same
// change and re-run — a diff here is the drift alarm. (A stronger gate would
// import both registries into one process; that is impossible across the repo
// boundary, so this frozen transcription is the cheapest real drift gate, and
// this M5 change — which touches both sides — is the moment to land it.)
// ===========================================================================

type Sybil = "none" | "weak" | "moderate";

interface Expected {
  credentialType: string;
  sybilResistance: Sybil;
  // A claims object that MUST parse for this type.
  sample: Record<string, unknown>;
  // z.object(...).strict() rejects unknown keys; plain z.object strips them.
  strict: boolean;
  // Revocable-after-disclosure via a Bitstring Status List. Omitted => false.
  // Only group-membership is revocable today (docs/groups-revocation-design.md).
  // Kept in lockstep with the provider-side badge-types.drift.test.
  revocable?: boolean;
}

const AGE_THRESHOLDS = [16, 18, 21, 25, 30, 35, 40, 45, 55, 65] as const;

// Reserved cross-cutting VC-metadata keys, stripped by verify-badge.ts before
// the per-type schema parse. No claim schema may declare one (see the guard
// test below). Kept in lockstep with the provider-side badge-types.drift.test.
const RESERVED_KEYS = ["id", "issuanceMonth", "nullifier"] as const;

const EXPECTED: Record<string, Expected> = {
  "email-domain": {
    credentialType: "MinisterEmailDomainCredential",
    sybilResistance: "weak",
    sample: { domain: "example.com" },
    strict: false,
  },
  "email-exact": {
    credentialType: "MinisterEmailExactCredential",
    sybilResistance: "weak",
    sample: { email: "user@example.com" },
    strict: false,
  },
  "oauth-account": {
    credentialType: "MinisterOauthAccountCredential",
    sybilResistance: "weak",
    sample: { provider: "github", handle: "octocat" },
    strict: false,
  },
  "account-age": {
    credentialType: "MinisterAccountAgeCredential",
    sybilResistance: "moderate",
    sample: { provider: "github", olderThanMonths: 24 },
    strict: true,
  },
  "social-following": {
    credentialType: "MinisterSocialFollowingCredential",
    sybilResistance: "moderate",
    sample: { provider: "github", followersAtLeast: 100 },
    strict: true,
  },
  "residency-country": {
    credentialType: "MinisterResidencyCountryCredential",
    sybilResistance: "none",
    sample: { country: "US" },
    strict: false,
  },
  "residency-state": {
    credentialType: "MinisterResidencyStateCredential",
    sybilResistance: "none",
    sample: { country: "US", state: "California" },
    strict: false,
  },
  "residency-city": {
    credentialType: "MinisterResidencyCityCredential",
    sybilResistance: "none",
    sample: { country: "US", state: "California", city: "San Francisco" },
    strict: false,
  },
  "invite-code": {
    credentialType: "MinisterInviteCodeCredential",
    sybilResistance: "none",
    sample: { label: "spring-2026" },
    strict: false,
  },
  "tlsn-attestation": {
    credentialType: "MinisterTlsnAttestationCredential",
    sybilResistance: "none",
    sample: { domain: "id.me", claim: "verified" },
    strict: true,
  },
  "group-membership": {
    credentialType: "MinisterGroupMembershipCredential",
    sybilResistance: "none",
    sample: { group: "acme", role: "member", groupId: "grp_abc123" },
    strict: true,
    revocable: true,
  },
  ...Object.fromEntries(
    AGE_THRESHOLDS.map((t) => [
      `age-over-${t}`,
      {
        credentialType: `MinisterAgeOver${t}Credential`,
        sybilResistance: "none" as Sybil,
        sample: { threshold: t },
        strict: false,
      },
    ]),
  ),
};

describe("badge registry drift vs @ministryofmany/shared (frozen contract)", () => {
  it("has the exact same slug set as the canonical contract", () => {
    expect(new Set(knownBadgeTypes())).toEqual(new Set(Object.keys(EXPECTED)));
  });

  for (const [slug, exp] of Object.entries(EXPECTED)) {
    describe(slug, () => {
      it("matches credentialType and sybilResistance", () => {
        const def = BADGE_TYPES[slug];
        expect(def, `SDK is missing badge type ${slug}`).toBeDefined();
        expect(def!.credentialType).toBe(exp.credentialType);
        expect(def!.sybilResistance).toBe(exp.sybilResistance);
      });

      // Drift guard for the revocable flag (mirror of the provider-side
      // badge-types.drift.test). A revocable type silently registered as
      // non-revocable would strip the RP's status handling — the exact
      // vocabulary drift §5.8 warns must not ship unnoticed.
      it("matches revocable", () => {
        const def = BADGE_TYPES[slug];
        expect(def!.revocable ?? false).toBe(exp.revocable ?? false);
      });

      it("accepts the canonical sample claims", () => {
        const schema = getBadgeClaimSchema(slug);
        expect(schema).toBeDefined();
        expect(() => schema!.parse(exp.sample)).not.toThrow();
      });

      it(`is ${exp.strict ? "STRICT (rejects)" : "lax (strips)"} on an unknown key`, () => {
        const schema = getBadgeClaimSchema(slug)!;
        const withExtra = { ...exp.sample, __driftProbe: 1 };
        if (exp.strict) {
          expect(() => schema.parse(withExtra)).toThrow();
        } else {
          const parsed = schema.parse(withExtra) as Record<string, unknown>;
          expect(parsed).not.toHaveProperty("__driftProbe");
        }
      });

      // Reserved-key guard (mirror of the provider-side badge-types.drift.test).
      // `id`, `issuanceMonth`, and `nullifier` are cross-cutting VC metadata that
      // verify-badge.ts strips BEFORE schema.parse. No per-type schema may
      // declare/echo one: a schema-declared `nullifier` would be silently eaten
      // (and a strict schema requiring it would reject every badge of that type),
      // and a schema-declared `id` would override the pairwise subject and fail
      // every RP holder-binding check.
      it("never echoes a reserved metadata key back through its schema", () => {
        const schema = getBadgeClaimSchema(slug)!;
        const withReserved = {
          ...exp.sample,
          id: "did:web:evil:u:attacker",
          issuanceMonth: "1999-01",
          nullifier: "mnv1:SMUGGLED",
        };
        if (exp.strict) {
          expect(() => schema.parse(withReserved)).toThrow();
        } else {
          const parsed = schema.parse(withReserved) as Record<string, unknown>;
          for (const key of RESERVED_KEYS) {
            expect(parsed, `${slug} echoed reserved key ${key}`).not.toHaveProperty(key);
          }
        }
      });
    });
  }
});
