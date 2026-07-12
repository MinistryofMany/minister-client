// src/badges/registry.test.ts
import { describe, expect, it } from "vitest";
import { BADGE_TYPES, slugForCredentialType } from "./registry";

describe("badge registry", () => {
  it("carries a sybilResistance value for every registered type", () => {
    for (const def of Object.values(BADGE_TYPES)) {
      expect(["none", "weak", "moderate"]).toContain(def.sybilResistance);
    }
    // §2.3 spot-checks.
    expect(BADGE_TYPES["oauth-account"]?.sybilResistance).toBe("weak");
    expect(BADGE_TYPES["email-domain"]?.sybilResistance).toBe("weak");
    expect(BADGE_TYPES["invite-code"]?.sybilResistance).toBe("none");
    expect(BADGE_TYPES["age-over-21"]?.sybilResistance).toBe("none");
    // The two nullifier-anchored github-derived types — RPs must be able to
    // verify them, so they must be present (not silently absent) and moderate.
    expect(BADGE_TYPES["account-age"]?.sybilResistance).toBe("moderate");
    expect(BADGE_TYPES["social-following"]?.sybilResistance).toBe("moderate");
  });

  it("registers account-age and social-following with their credentialTypes", () => {
    expect(BADGE_TYPES["account-age"]?.credentialType).toBe("MinisterAccountAgeCredential");
    expect(slugForCredentialType("MinisterAccountAgeCredential")).toBe("account-age");
    expect(BADGE_TYPES["social-following"]?.credentialType).toBe(
      "MinisterSocialFollowingCredential",
    );
    expect(slugForCredentialType("MinisterSocialFollowingCredential")).toBe("social-following");
  });
  it("registers email-domain with its credentialType and schema", () => {
    const def = BADGE_TYPES["email-domain"];
    expect(def?.credentialType).toBe("MinisterEmailDomainCredential");
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
