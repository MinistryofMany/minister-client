import { describe, expect, it } from "vitest";

import { VcVerificationError } from "./errors";
import { makeKeys, signVc } from "./test-helpers";
import { verifyMinisterBadge } from "./verify-badge";

const ISSUER = "https://ministry.id";
const ISSUER_DID = "did:web:ministry.id";
const SUBJECT = "did:web:ministry.id:users:alice";

describe("verifyMinisterBadge", () => {
  it("verifies a well-formed VC and returns typed claims", async () => {
    const keys = await makeKeys();
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
      type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
      claims: { domain: "example.com" },
    });

    const badge = await verifyMinisterBadge(ISSUER, vc, {
      key: keys.publicKey,
    });

    expect(badge.sub).toBe(SUBJECT);
    expect(badge.type).toEqual([
      "VerifiableCredential",
      "MinisterEmailDomainCredential",
    ]);
    expect(badge.claims).toEqual({ domain: "example.com" });
    // `id` is stripped from claims (surfaced as `sub`).
    expect(badge.claims).not.toHaveProperty("id");
    expect(badge.raw).toBe(vc);
  });

  it("rejects a tampered token", async () => {
    const keys = await makeKeys();
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
    });
    // Flip a character in the signature segment.
    const parts = vc.split(".");
    parts[2] = parts[2]!.slice(0, -2) + (parts[2]!.endsWith("AA") ? "BB" : "AA");
    const tampered = parts.join(".");

    await expect(
      verifyMinisterBadge(ISSUER, tampered, { key: keys.publicKey }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a VC signed by a different key", async () => {
    const signer = await makeKeys();
    const attacker = await makeKeys();
    const vc = await signVc({
      privateKey: signer.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
    });

    await expect(
      verifyMinisterBadge(ISSUER, vc, { key: attacker.publicKey }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a wrong issuer DID", async () => {
    const keys = await makeKeys();
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: "did:web:evil.example",
      subject: SUBJECT,
    });

    await expect(
      verifyMinisterBadge(ISSUER, vc, { key: keys.publicKey }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects the wrong JWT typ", async () => {
    const keys = await makeKeys();
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
      typ: "JWT",
    });

    await expect(
      verifyMinisterBadge(ISSUER, vc, { key: keys.publicKey }),
    ).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a credentialSubject.id / sub mismatch (holder binding)", async () => {
    const keys = await makeKeys();
    // credentialSubject.id = SUBJECT but the JWT sub is someone else.
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
      subOverride: "did:web:ministry.id:users:mallory",
    });

    await expect(
      verifyMinisterBadge(ISSUER, vc, { key: keys.publicKey }),
    ).rejects.toThrow(/does not match/u);
  });

  it("derives the issuer DID from an issuer with a port", async () => {
    const keys = await makeKeys();
    const vc = await signVc({
      privateKey: keys.privateKey,
      issuerDid: "did:web:localhost%3A3000",
      subject: "did:web:localhost%3A3000:users:dev",
    });

    const badge = await verifyMinisterBadge("http://localhost:3000", vc, {
      key: keys.publicKey,
    });
    expect(badge.sub).toBe("did:web:localhost%3A3000:users:dev");
  });
});
