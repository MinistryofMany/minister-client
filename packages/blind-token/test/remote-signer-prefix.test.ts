// RemoteSigner Signet-prefix coupling guard.
//
// The deployed Signet hard-codes its prefix (Signet/src/crypto.rs:47) and signs
// over `<compiled prefix>:<version_id>`. If the client's info.infoPrefix does not
// match the RemoteSigner's configured prefix (which must equal Signet's compiled
// prefix), every signature fails closed at redemption. The RemoteSigner surfaces
// this as a LOUD error at sign() time - BEFORE any network call - rather than a
// silent misconfiguration. This test asserts that guard fires (and does not touch
// the network).

import { describe, it, expect } from "vitest";
import { createRemoteSigner } from "../src/server/index.js";
import type { ActionInfo } from "../src/server/index.js";

// Dummy PEMs - the guard fires before the Agent/transport is exercised, so these
// are never used for a real handshake.
const DUMMY_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

function remote(infoPrefix?: string) {
  return createRemoteSigner({
    baseUrl: "https://signet.invalid:8443",
    clientCert: DUMMY_PEM,
    clientKey: DUMMY_PEM,
    caCert: DUMMY_PEM,
    infoPrefix,
  });
}

describe("RemoteSigner prefix coupling", () => {
  it("backend reports 'remote'", () => {
    expect(remote().backend).toBe("remote");
  });

  it("throws on a prefix mismatch BEFORE any network call", async () => {
    // Configured for 'freedink-vote' (the default), but the client uses 'deforum-ban'.
    const signer = remote(); // default freedink-vote
    const info: ActionInfo = { infoPrefix: "deforum-ban", actionKey: "round-9" };
    await expect(
      signer.sign({
        group: "g",
        participant: "p",
        info,
        blindedMessage: new Uint8Array([1, 2, 3]),
      }),
    ).rejects.toThrow(/info prefix mismatch/);
  });

  it("throws on a prefix mismatch when a custom prefix is configured", async () => {
    const signer = remote("deforum-ban");
    const info: ActionInfo = { infoPrefix: "freedink-vote", actionKey: "v1" };
    await expect(
      signer.sign({
        group: "g",
        participant: "p",
        info,
        blindedMessage: new Uint8Array([1, 2, 3]),
      }),
    ).rejects.toThrow(/info prefix mismatch/);
  });
});
