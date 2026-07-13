import { describe, expect, it } from "vitest";

import { verifyMinisterBadge } from "./verify-badge";
import { makeKeys, signVc } from "./test-helpers";
import { VcVerificationError } from "./errors";

const ISSUER = "https://ministry.id";
const ISSUER_DID = "did:web:ministry.id";
const SUBJECT = "did:web:ministry.id:u:pairwise-sub-1";
const LIST_URL = "https://ministry.id/status/list_xyz";

// verifyMinisterBadge surfaces a well-formed `vc.credentialStatus` as `.status`
// (§5.8), leaving the per-type claim schema (which never sees it) untouched, and
// fails the badge closed on a malformed one.

describe("verifyMinisterBadge credentialStatus exposure", () => {
  it("exposes a well-formed credentialStatus as { uri, index }", async () => {
    const keys = await makeKeys();
    const jwt = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
      credentialStatus: {
        id: `${LIST_URL}#99`,
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "99",
        statusListCredential: LIST_URL,
      },
    });

    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: keys.publicJwk });
    expect(badge.status).toEqual({ uri: LIST_URL, index: 99 });
    // The claim schema is unaffected by the vc-level status entry.
    expect(badge.claims).toEqual({ domain: "example.com" });
  });

  it("leaves .status undefined for a badge with no credentialStatus", async () => {
    const keys = await makeKeys();
    const jwt = await signVc({ privateKey: keys.privateKey, issuerDid: ISSUER_DID, subject: SUBJECT });
    const badge = await verifyMinisterBadge(jwt, { issuer: ISSUER, key: keys.publicJwk });
    expect(badge.status).toBeUndefined();
  });

  it("fails the badge closed on a malformed credentialStatus (foreign-origin list)", async () => {
    const keys = await makeKeys();
    const jwt = await signVc({
      privateKey: keys.privateKey,
      issuerDid: ISSUER_DID,
      subject: SUBJECT,
      credentialStatus: {
        id: "https://evil.example/status/x#1",
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "1",
        statusListCredential: "https://evil.example/status/x",
      },
    });
    await expect(verifyMinisterBadge(jwt, { issuer: ISSUER, key: keys.publicJwk })).rejects.toThrow(
      VcVerificationError,
    );
  });
});
