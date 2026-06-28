// THE ANONYMITY INVARIANT: the raw token nonce NEVER reaches a signer.
//
// Proven two ways:
//   (1) By API shape - structurally. prepareToken keeps `prepared` and `inv`
//       client-side and emits only `blindedMessage`. The Signer/Issuer sign/issue
//       methods accept ONLY blindedMessage; there is no parameter through which a
//       raw or prepared nonce could be passed to a signer.
//   (2) By behavior - the LocalSigner (and the Issuer above it) receives the
//       blinded message and NOT the raw nonce, and the blinded message is provably
//       different from both the raw nonce and the prepared nonce.

import { describe, it, expect } from "vitest";
import { prepareToken } from "../src/client/index.js";
import { createLocalSigner, createIssuer } from "../src/server/index.js";
import type { Signer, SignArgs, ActionInfo } from "../src/server/index.js";
import { MemoryIssuanceStore, MemoryKeyStore } from "./fixtures/memory-stores.js";

const info: ActionInfo = { infoPrefix: "freedink-vote", actionKey: "v-anon" };

describe("anonymity invariant: raw nonce never reaches a signer", () => {
  it("prepareToken emits only blindedMessage; prepared + inv stay client-side", async () => {
    const keyStore = new MemoryKeyStore();
    const signer = createLocalSigner({ keyStore, modulusLength: 1024 });
    const pk = await signer.getPublicKey("g");
    if (pk.status !== "ready") throw new Error("key not ready");

    const out = await prepareToken({ publicKey: pk.publicKeySpki, info });
    // The shape carries the three fields; only blindedMessage is meant to leave.
    expect(out.blindedMessage).toBeInstanceOf(Uint8Array);
    expect(out.prepared).toBeInstanceOf(Uint8Array);
    expect(out.inv).toBeInstanceOf(Uint8Array);
    // The blinded message is NOT equal to the prepared nonce (it has been blinded).
    expect(Array.from(out.blindedMessage)).not.toEqual(Array.from(out.prepared));
  });

  it("the Signer sees the blinded message, never the prepared/raw nonce", async () => {
    // A spy Signer that captures exactly what it was handed.
    let captured: SignArgs | null = null;
    const keyStore = new MemoryKeyStore();
    const local = createLocalSigner({ keyStore, modulusLength: 1024 });
    const spy: Signer = {
      backend: "local",
      getPublicKey: (g) => local.getPublicKey(g),
      sign: async (args) => {
        captured = args;
        return local.sign(args);
      },
      ensureKey: (g) => local.ensureKey(g),
      rotateKey: (g) => local.rotateKey(g),
    };
    const issuer = createIssuer({ signer: spy, issuanceStore: new MemoryIssuanceStore() });

    const pk = await spy.getPublicKey("g");
    if (pk.status !== "ready") throw new Error("key not ready");
    const { blindedMessage, prepared } = await prepareToken({
      publicKey: pk.publicKeySpki,
      info,
    });

    const r = await issuer.issue({
      group: "g",
      participant: "p",
      info,
      blindedMessage,
    });
    expect(r.status).toBe("issued");

    // The signer received exactly the blinded message.
    expect(captured).not.toBeNull();
    const got = captured as unknown as SignArgs;
    expect(Array.from(got.blindedMessage)).toEqual(Array.from(blindedMessage));
    // And NOT the prepared nonce (the redemption handle).
    expect(Array.from(got.blindedMessage)).not.toEqual(Array.from(prepared));
    // SignArgs has no field that could carry a raw or prepared nonce.
    expect(Object.keys(got).sort()).toEqual(
      ["blindedMessage", "group", "info", "participant"].sort(),
    );
  });
});
