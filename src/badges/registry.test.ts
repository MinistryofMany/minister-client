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
