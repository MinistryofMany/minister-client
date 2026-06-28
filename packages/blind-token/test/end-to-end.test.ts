// End-to-end + byte-identical interop.
//
//   1. A token issued (LocalSigner via the Issuer) + finalized (client
//      finalizeToken) + verified (server verifyToken) end-to-end.
//   2. BYTE-IDENTICAL interop: a token produced via this package verifies under
//      the UNMODIFIED @cloudflare/blindrsa-ts SUITE.verify with FreedInk's exact
//      info bytes (`freedink-vote:<actionKey>`) - the same check FreedInk's
//      verifyVoteToken performs - AND the bytes the RemoteSigner would put on the
//      wire to Signet (version_id = actionKey, base64 blinded_message) reconstruct
//      to a Signet-compatible /sign over `freedink-vote:<actionKey>`, proven by
//      having the library blind-sign over exactly those reconstructed bytes and
//      the package finalize+verify succeeding.
//   3. Cross-action replay is impossible (actionKey B token fails under A).

import { describe, it, expect } from "vitest";
import { RSAPBSSA } from "@cloudflare/blindrsa-ts";
import { webcrypto } from "node:crypto";
import { prepareToken, finalizeToken } from "../src/client/index.js";
import {
  createLocalSigner,
  createIssuer,
  verifyToken,
  buildInfo,
  b64urlToBytes,
} from "../src/server/index.js";
import type { ActionInfo } from "../src/server/index.js";
import { MemoryIssuanceStore, MemoryKeyStore } from "./fixtures/memory-stores.js";

const SUITE = RSAPBSSA.SHA384.PSS.Randomized();
// 1024-bit keeps keygen fast while exercising the exact protocol; the package's
// default modulus is 2048 (FreedInk's), tested for parity in the interop case.
const TEST_MODULUS = 1024;

function freshSigner() {
  const keyStore = new MemoryKeyStore();
  const issuanceStore = new MemoryIssuanceStore();
  const signer = createLocalSigner({ keyStore, modulusLength: TEST_MODULUS });
  const issuer = createIssuer({ signer, issuanceStore });
  return { keyStore, issuanceStore, signer, issuer };
}

describe("end-to-end issuance + finalize + verify", () => {
  it("issues, finalizes, and verifies a single token", async () => {
    const { signer, issuer } = freshSigner();
    const group = "blog-1";
    const participant = "user-1";
    const info: ActionInfo = { infoPrefix: "freedink-vote", actionKey: "version-A" };

    // Client preflight: fetch the issuer public key.
    const pk = await issuer.getPublicKey(group);
    expect(pk.status).toBe("ready");
    if (pk.status !== "ready") throw new Error("key not ready");

    // Client: prepare (blind a fresh nonce). Only blindedMessage is sent.
    const { blindedMessage, prepared, inv } = await prepareToken({
      publicKey: pk.publicKeySpki,
      info,
    });

    // Server: issue (record-first reservation -> blind-sign).
    const result = await issuer.issue({ group, participant, info, blindedMessage });
    expect(result.status).toBe("issued");
    if (result.status !== "issued") throw new Error("issue failed");
    // Issuer returns the public key by default.
    expect(result.publicKeySpki).toBeDefined();

    // Client: finalize the blind signature into a redeemable token.
    const token = await finalizeToken({
      publicKey: pk.publicKeySpki,
      info,
      prepared,
      inv,
      blindSignature: result.blindSignature,
    });

    // Server: verify the redeemed token.
    const ok = await verifyToken({
      publicKeySpki: pk.publicKeySpki,
      signature: b64urlToBytes(token.signature),
      preparedNonce: b64urlToBytes(token.preparedNonce),
      info,
    });
    expect(ok).toBe(true);

    // The redemption handle (preparedNonce) round-trips to the prepared bytes.
    expect(Array.from(b64urlToBytes(token.preparedNonce))).toEqual(Array.from(prepared));
    void signer;
  });

  it("rejects a token redeemed under a different actionKey (cross-action replay)", async () => {
    const { issuer } = freshSigner();
    const group = "blog-x";
    const infoA: ActionInfo = { infoPrefix: "freedink-vote", actionKey: "round-A" };
    const infoB: ActionInfo = { infoPrefix: "freedink-vote", actionKey: "round-B" };

    const pk = await issuer.getPublicKey(group);
    if (pk.status !== "ready") throw new Error("key not ready");

    const { blindedMessage, prepared, inv } = await prepareToken({
      publicKey: pk.publicKeySpki,
      info: infoA,
    });
    const result = await issuer.issue({
      group,
      participant: "mod-1",
      info: infoA,
      blindedMessage,
    });
    if (result.status !== "issued") throw new Error("issue failed");
    const token = await finalizeToken({
      publicKey: pk.publicKeySpki,
      info: infoA,
      prepared,
      inv,
      blindSignature: result.blindSignature,
    });

    // Verifies under A.
    expect(
      await verifyToken({
        publicKeySpki: pk.publicKeySpki,
        signature: b64urlToBytes(token.signature),
        preparedNonce: b64urlToBytes(token.preparedNonce),
        info: infoA,
      }),
    ).toBe(true);
    // Fails under B - no cross-action replay.
    expect(
      await verifyToken({
        publicKeySpki: pk.publicKeySpki,
        signature: b64urlToBytes(token.signature),
        preparedNonce: b64urlToBytes(token.preparedNonce),
        info: infoB,
      }),
    ).toBe(false);
  });
});

describe("byte-identical interop with FreedInk verifyVoteToken + Signet wire", () => {
  it("a package-produced token verifies under the raw library over freedink-vote:<actionKey>", async () => {
    // FreedInk's verifyVoteToken does exactly: SUITE.verify(pk, sig, prepared,
    // versionInfo(versionId)) where versionInfo = `freedink-vote:${versionId}`.
    // We prove the package's token verifies under that EXACT call with the
    // unmodified library - so a token minted via this package is accepted by
    // FreedInk's current redemption path with zero changes.
    const { issuer } = freshSigner();
    const group = "blog-interop";
    const versionId = "post-version-42";
    const info: ActionInfo = { infoPrefix: "freedink-vote", actionKey: versionId };

    const pk = await issuer.getPublicKey(group);
    if (pk.status !== "ready") throw new Error("key not ready");

    const { blindedMessage, prepared, inv } = await prepareToken({
      publicKey: pk.publicKeySpki,
      info,
    });
    const result = await issuer.issue({
      group,
      participant: "reviewer",
      info,
      blindedMessage,
    });
    if (result.status !== "issued") throw new Error("issue failed");
    const token = await finalizeToken({
      publicKey: pk.publicKeySpki,
      info,
      prepared,
      inv,
      blindSignature: result.blindSignature,
    });

    // buildInfo MUST equal FreedInk's versionInfo() byte-for-byte.
    const freedinkVersionInfo = new TextEncoder().encode(`freedink-vote:${versionId}`);
    expect(Array.from(buildInfo(info))).toEqual(Array.from(freedinkVersionInfo));

    // Verify exactly the way FreedInk's verifyVoteToken does, with the raw library.
    const rawPk = await webcrypto.subtle.importKey(
      "spki",
      pk.publicKeySpki.slice().buffer,
      { name: "RSA-PSS", hash: "SHA-384" },
      true,
      ["verify"],
    );
    const ok = await SUITE.verify(
      rawPk as unknown as CryptoKey,
      b64urlToBytes(token.signature),
      b64urlToBytes(token.preparedNonce),
      freedinkVersionInfo,
    );
    expect(ok).toBe(true);
  });

  it("the Signet /sign wire shape (version_id=actionKey, base64 blinded_message) reconstructs a verifiable token", async () => {
    // The RemoteSigner sends { version_id: actionKey, blinded_message: base64 } and
    // Signet signs over `freedink-vote:<version_id>` (Signet/src/crypto.rs:47). We
    // simulate that exact reconstruction: take the SAME blinded message the client
    // prepared, base64 round-trip it (Signet's wire format), and have the library
    // blind-sign over `freedink-vote:<version_id>`. The package's finalize+verify
    // must then succeed - proving the wire bytes are what Signet expects.
    const keyStore = new MemoryKeyStore();
    // Use 2048-bit (FreedInk + Signet production modulus) for the wire-shape proof.
    const signer = createLocalSigner({ keyStore, modulusLength: 2048 });
    const group = "blog-signet";
    const versionId = "wire-version-7";
    const info: ActionInfo = { infoPrefix: "freedink-vote", actionKey: versionId };

    const pkOut = await signer.getPublicKey(group);
    if (pkOut.status !== "ready") throw new Error("key not ready");
    const publicKeySpki = pkOut.publicKeySpki;

    const { blindedMessage, prepared, inv } = await prepareToken({
      publicKey: publicKeySpki,
      info,
    });

    // ---- Simulate the Signet wire boundary exactly. ----
    // RemoteSigner.sign would send these JSON fields:
    const wireVersionId = info.actionKey; // version_id on the wire
    const wireBlindedB64 = Buffer.from(blindedMessage).toString("base64"); // base64-standard
    // Signet receives them and rebuilds the message bytes + metadata.
    const signetSeesBlinded = new Uint8Array(Buffer.from(wireBlindedB64, "base64"));
    const signetMetadata = new TextEncoder().encode(`freedink-vote:${wireVersionId}`);
    // The blinded bytes Signet sees must be IDENTICAL to what the client produced.
    expect(Array.from(signetSeesBlinded)).toEqual(Array.from(blindedMessage));
    // And the metadata Signet derives must equal buildInfo(info).
    expect(Array.from(signetMetadata)).toEqual(Array.from(buildInfo(info)));

    // Signet (here, the raw library standing in for the Rust signer) blind-signs.
    const rawPriv = keyStore; // keys are in the store; pull the active private key.
    const active = await rawPriv.getOrCreateKeyPair(group, async () => {
      throw new Error("should already exist");
    });
    const sk = await webcrypto.subtle.importKey(
      "pkcs8",
      active.privateKeyPkcs8.slice().buffer,
      { name: "RSA-PSS", hash: "SHA-384" },
      true,
      ["sign"],
    );
    const blindSig = await SUITE.blindSign(
      sk as unknown as CryptoKey,
      signetSeesBlinded,
      signetMetadata,
    );

    // The client finalizes the blind signature from "Signet".
    const token = await finalizeToken({
      publicKey: publicKeySpki,
      info,
      prepared,
      inv,
      blindSignature: blindSig,
    });

    // And it verifies - the wire round-trip preserved every byte.
    const ok = await verifyToken({
      publicKeySpki,
      signature: b64urlToBytes(token.signature),
      preparedNonce: b64urlToBytes(token.preparedNonce),
      info,
    });
    expect(ok).toBe(true);
  });
});
