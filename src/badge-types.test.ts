import { describe, expect, it } from "vitest";

import {
  AGE_THRESHOLDS,
  getBadgeClaimSchema,
  knownBadgeTypes,
  OAUTH_PROVIDERS,
} from "./badge-types";
import { badgeScope } from "./oidc";

describe("badgeScope", () => {
  it("prefixes a slug with badge:", () => {
    expect(badgeScope("age-over-21")).toBe("badge:age-over-21");
    expect(badgeScope("oauth-account")).toBe("badge:oauth-account");
  });
});

describe("knownBadgeTypes", () => {
  it("includes the static and age-threshold types", () => {
    const types = knownBadgeTypes();
    expect(types).toContain("email-domain");
    expect(types).toContain("oauth-account");
    for (const t of AGE_THRESHOLDS) {
      expect(types).toContain(`age-over-${t}`);
    }
  });
});

describe("getBadgeClaimSchema", () => {
  it("returns undefined for unknown slugs", () => {
    expect(getBadgeClaimSchema("not-a-badge")).toBeUndefined();
  });

  it("validates email-domain claims", () => {
    const schema = getBadgeClaimSchema("email-domain");
    expect(schema).toBeDefined();
    expect(schema!.safeParse({ domain: "example.com" }).success).toBe(true);
    // not a valid domain
    expect(schema!.safeParse({ domain: "nope" }).success).toBe(false);
    // missing field
    expect(schema!.safeParse({}).success).toBe(false);
  });

  it("validates oauth-account claims against the provider enum", () => {
    const schema = getBadgeClaimSchema("oauth-account")!;
    for (const provider of OAUTH_PROVIDERS) {
      expect(
        schema.safeParse({ provider, accountId: "123" }).success,
      ).toBe(true);
    }
    expect(
      schema.safeParse({ provider: "myspace", accountId: "1" }).success,
    ).toBe(false);
  });

  it("validates age-over-21 with a literal threshold", () => {
    const schema = getBadgeClaimSchema("age-over-21")!;
    expect(schema.safeParse({ threshold: 21 }).success).toBe(true);
    // wrong threshold for this badge type
    expect(schema.safeParse({ threshold: 18 }).success).toBe(false);
  });

  it("rejects unknown keys on tlsn-attestation (strict)", () => {
    const schema = getBadgeClaimSchema("tlsn-attestation")!;
    expect(
      schema.safeParse({ domain: "id.me", claim: "verified" }).success,
    ).toBe(true);
    expect(
      schema.safeParse({ domain: "id.me", claim: "v", extra: "x" }).success,
    ).toBe(false);
  });
});
