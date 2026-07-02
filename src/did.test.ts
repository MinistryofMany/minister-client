import { describe, expect, it } from "vitest";
import {
  buildDid,
  buildPairwiseSubjectDid,
  didFromIssuer,
  parsePairwiseSubjectDid,
} from "./did";

describe("didFromIssuer", () => {
  it("derives a host-only did:web from an origin", () => {
    expect(didFromIssuer("https://ministry.id")).toBe("did:web:ministry.id");
  });

  it("percent-encodes a non-default port per did:web", () => {
    expect(didFromIssuer("https://localhost:3000")).toBe("did:web:localhost%3A3000");
  });

  it("tolerates a trailing-slash-only path (bare origin)", () => {
    expect(didFromIssuer("https://ministry.id/")).toBe("did:web:ministry.id");
  });

  it("throws on a path-bearing issuer instead of silently dropping the path", () => {
    // Minister's did:web is host-only; a path would silently diverge and fail
    // every badge closed. Fail loud at config time instead.
    expect(() => didFromIssuer("https://ministry.id/oidc")).toThrow(/path/i);
  });

  it("throws on an issuer carrying a query or fragment", () => {
    expect(() => didFromIssuer("https://ministry.id?x=1")).toThrow();
    expect(() => didFromIssuer("https://ministry.id#f")).toThrow();
  });
});

describe("buildPairwiseSubjectDid", () => {
  it("builds did:web:<host>:u:<sub> from the issuer origin and sub", () => {
    expect(buildPairwiseSubjectDid("https://ministry.id", "PAIRWISE_SUB")).toBe(
      "did:web:ministry.id:u:PAIRWISE_SUB",
    );
  });

  it("matches buildDid(host) + :u: for a ported issuer", () => {
    expect(buildPairwiseSubjectDid("https://localhost:3000", "s")).toBe(
      `${buildDid("localhost%3A3000")}:u:s`,
    );
  });
});

describe("parsePairwiseSubjectDid", () => {
  it("round-trips a well-formed pairwise subject", () => {
    const subject = buildPairwiseSubjectDid("https://ministry.id", "abc_123");
    expect(parsePairwiseSubjectDid(subject)).toEqual({
      issuerDid: "did:web:ministry.id",
      sub: "abc_123",
    });
  });

  it("rejects the legacy :users: shape (not a pairwise subject)", () => {
    expect(parsePairwiseSubjectDid("did:web:ministry.id:users:u1")).toBeNull();
  });

  it("rejects a non-did prefix or an empty sub", () => {
    expect(parsePairwiseSubjectDid("https://evil:u:x")).toBeNull();
    expect(parsePairwiseSubjectDid("did:web:ministry.id:u:")).toBeNull();
  });

  it("does not mis-split when a colon follows the marker (sub must be a single segment)", () => {
    // A trailing segment with a colon is not a valid single pairwise sub.
    expect(parsePairwiseSubjectDid("did:web:ministry.id:u:a:b")).toBeNull();
  });
});
