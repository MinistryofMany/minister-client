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
