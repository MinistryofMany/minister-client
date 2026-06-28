// rotateKey on the Signer + KeyStore seam (added NOW so adding per-round rotation
// later is not a breaking change to a shipped interface). LocalSigner rotation:
//   - retires the old active key and installs a fresh one (a new key row);
//   - the new public key differs from the old;
//   - a token signed under the OLD key fails to verify under the NEW key.

import { describe, it, expect } from "vitest";
import { prepareToken, finalizeToken } from "../src/client/index.js";
import { createLocalSigner, createIssuer, verifyToken, b64urlToBytes } from "../src/server/index.js";
import type { ActionInfo } from "../src/server/index.js";
import { MemoryIssuanceStore, MemoryKeyStore } from "./fixtures/memory-stores.js";

const info: ActionInfo = { infoPrefix: "deforum-ban", actionKey: "round-1" };

describe("rotateKey (local)", () => {
  it("installs a fresh key, retires the old, and invalidates old-key tokens", async () => {
    const keyStore = new MemoryKeyStore();
    const signer = createLocalSigner({ keyStore, modulusLength: 1024 });
    const issuer = createIssuer({ signer, issuanceStore: new MemoryIssuanceStore() });
    const group = "subforum-1";

    // Issue + finalize a token under the ORIGINAL key.
    const pk0 = await issuer.getPublicKey(group);
    if (pk0.status !== "ready") throw new Error("key0 not ready");
    const oldPub = pk0.publicKeySpki;

    const { blindedMessage, prepared, inv } = await prepareToken({
      publicKey: oldPub,
      info,
    });
    const issued = await issuer.issue({
      group,
      participant: "mod-1",
      info,
      blindedMessage,
    });
    if (issued.status !== "issued") throw new Error("issue failed");
    const token = await finalizeToken({
      publicKey: oldPub,
      info,
      prepared,
      inv,
      blindSignature: issued.blindSignature,
    });
    // Verifies under the original key.
    expect(
      await verifyToken({
        publicKeySpki: oldPub,
        signature: b64urlToBytes(token.signature),
        preparedNonce: b64urlToBytes(token.preparedNonce),
        info,
      }),
    ).toBe(true);
    expect(keyStore.count(group)).toBe(1);

    // Rotate.
    const rot = await issuer.rotateKey(group);
    expect(rot.status).toBe("rotated");
    if (rot.status !== "rotated") throw new Error("rotate failed");
    const newPub = rot.publicKeySpki;

    // A fresh key row exists; the old one is retired (still counted, not active).
    expect(keyStore.count(group)).toBe(2);
    expect(await keyStore.getActivePublicKey(group)).toEqual(newPub);
    // The new public key differs from the old.
    expect(Array.from(newPub)).not.toEqual(Array.from(oldPub));

    // The old-key token no longer verifies under the NEW key (rotation invalidates
    // outstanding tokens, matching Signet's rotate contract).
    expect(
      await verifyToken({
        publicKeySpki: newPub,
        signature: b64urlToBytes(token.signature),
        preparedNonce: b64urlToBytes(token.preparedNonce),
        info,
      }),
    ).toBe(false);
  });
});
