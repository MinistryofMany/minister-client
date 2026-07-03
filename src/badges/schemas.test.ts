// src/badges/schemas.test.ts
import { describe, expect, it } from "vitest";
import {
  EmailDomainClaims,
  OAuthAccountClaims,
  TlsnAttestationClaims,
  AGE_THRESHOLDS,
  AccountAgeClaims,
  TwoFactorClaims,
  SocialFollowingClaims,
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
  it("account-age accepts a declared bucket and rejects off-grid/unknown keys", () => {
    expect(AccountAgeClaims.parse({ provider: "github", olderThanMonths: 60 })).toEqual({
      provider: "github",
      olderThanMonths: 60,
    });
    expect(() => AccountAgeClaims.parse({ provider: "github", olderThanMonths: 30 })).toThrow();
    expect(() =>
      AccountAgeClaims.parse({ provider: "github", olderThanMonths: 12, createdAt: "x" }),
    ).toThrow();
  });
  it("two-factor is a strict bare-provider claim", () => {
    expect(TwoFactorClaims.parse({ provider: "github" })).toEqual({ provider: "github" });
    expect(() => TwoFactorClaims.parse({ provider: "github", enabled: true })).toThrow();
  });
  it("social-following buckets the follower count", () => {
    expect(SocialFollowingClaims.parse({ provider: "github", followersAtLeast: 1000 }).followersAtLeast).toBe(1000);
    expect(() => SocialFollowingClaims.parse({ provider: "github", followersAtLeast: 742 })).toThrow();
  });
});
