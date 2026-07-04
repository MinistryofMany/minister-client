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
  it("accepts a known oauth provider and no longer carries accountId", () => {
    // accountId (the raw Sybil anchor) was removed in crypto-core Phase 1; the
    // non-strict schema strips a stray one so a legacy shape can't smuggle it back.
    const parsed = OAuthAccountClaims.parse({ provider: "github", accountId: "1", handle: "x" });
    expect(parsed.provider).toBe("github");
    expect("accountId" in parsed).toBe(false);
  });
  it("exposes the age thresholds", () => {
    expect(AGE_THRESHOLDS).toContain(18);
  });
});
