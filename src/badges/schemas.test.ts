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
