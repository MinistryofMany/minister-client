import { describe, expect, it } from "vitest";

import { makeKeys, newStatusBits, setStatusBit, signStatusList } from "./test-helpers";
import { parseCredentialStatus, verifyStatusListCredential, bitIsSet } from "./status-list";
import { VcVerificationError } from "./errors";

const ISSUER = "https://ministry.id";
const ISSUER_DID = "did:web:ministry.id";
const LIST_URL = "https://ministry.id/status/list_abc";

function validEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: `${LIST_URL}#42`,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: "42",
    statusListCredential: LIST_URL,
    ...overrides,
  };
}

describe("parseCredentialStatus", () => {
  it("parses a well-formed entry", () => {
    const ref = parseCredentialStatus(validEntry(), ISSUER);
    expect(ref).toEqual({ uri: LIST_URL, index: 42 });
  });

  it("returns undefined when absent", () => {
    expect(parseCredentialStatus(undefined, ISSUER)).toBeUndefined();
    expect(parseCredentialStatus(null, ISSUER)).toBeUndefined();
  });

  it("rejects a wrong type", () => {
    expect(() => parseCredentialStatus(validEntry({ type: "RevocationList2020Status" }), ISSUER)).toThrow(
      VcVerificationError,
    );
  });

  it("rejects a non-revocation purpose", () => {
    expect(() => parseCredentialStatus(validEntry({ statusPurpose: "suspension" }), ISSUER)).toThrow(
      VcVerificationError,
    );
  });

  it("rejects a list URL on a foreign origin (attacker-controlled always-valid list)", () => {
    expect(() =>
      parseCredentialStatus(
        validEntry({
          statusListCredential: "https://evil.example/status/x",
          id: "https://evil.example/status/x#42",
        }),
        ISSUER,
      ),
    ).toThrow(/origin/);
  });

  it("rejects a non-integer / out-of-range index", () => {
    expect(() => parseCredentialStatus(validEntry({ statusListIndex: "-1" }), ISSUER)).toThrow();
    expect(() => parseCredentialStatus(validEntry({ statusListIndex: "not-a-number" }), ISSUER)).toThrow();
  });
});

describe("verifyStatusListCredential", () => {
  it("verifies a signed list, binds sub to the URL, and decodes the bitstring", async () => {
    const keys = await makeKeys();
    const bits = newStatusBits();
    setStatusBit(bits, 42);
    const jwt = await signStatusList({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      listUrl: LIST_URL,
      version: 7,
      bits,
    });

    const snap = await verifyStatusListCredential(jwt, {
      fetchedUrl: LIST_URL,
      issuer: ISSUER,
      key: keys.publicJwk,
    });

    expect(snap.version).toBe(7);
    expect(bitIsSet(snap.bits, 42)).toBe(true);
    expect(bitIsSet(snap.bits, 41)).toBe(false);
    expect(snap.expiresAtMs).toBeGreaterThan(Date.now());
  });

  it("rejects a list whose sub does not match the fetched URL (defense 1)", async () => {
    const keys = await makeKeys();
    const jwt = await signStatusList({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      listUrl: LIST_URL,
      version: 1,
      bits: newStatusBits(),
      subOverride: "https://ministry.id/status/OTHER",
    });
    await expect(
      verifyStatusListCredential(jwt, { fetchedUrl: LIST_URL, issuer: ISSUER, key: keys.publicJwk }),
    ).rejects.toThrow(/sub/);
  });

  it("rejects an expired list (defense 2 / hard max-age)", async () => {
    const keys = await makeKeys();
    const jwt = await signStatusList({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      listUrl: LIST_URL,
      version: 1,
      bits: newStatusBits(),
      expDeltaSec: -120, // expired 2 min ago (beyond the 30s tolerance)
    });
    await expect(
      verifyStatusListCredential(jwt, { fetchedUrl: LIST_URL, issuer: ISSUER, key: keys.publicJwk }),
    ).rejects.toThrow();
  });

  it("rejects a badge VC replayed as a status list (type confusion)", async () => {
    const keys = await makeKeys();
    // A well-signed vc+jwt for the same URL but WITHOUT the status-list vc.type.
    const { signVc } = await import("./test-helpers");
    const jwt = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: LIST_URL,
    });
    await expect(
      verifyStatusListCredential(jwt, { fetchedUrl: LIST_URL, issuer: ISSUER, key: keys.publicJwk }),
    ).rejects.toThrow();
  });
});
