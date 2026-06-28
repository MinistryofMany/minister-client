// Issuer orchestration: one-per-(group, participant, actionKey); record-first
// reservation; ROLLBACK-on-failure (a failed sign releases the reservation; a
// SUCCESSFUL sign does NOT); pending + rate_limited + signer_error outcomes.
//
// SAFETY-CRITICAL focus: the single token must never be burned by a transient
// failure (so failure => release => retryable), and must never be re-issuable
// after a success (so success => NO release).

import { describe, it, expect } from "vitest";
import { createIssuer } from "../src/server/index.js";
import type {
  Signer,
  SignArgs,
  SignOutcome,
  PublicKeyOutcome,
  RotateOutcome,
  ActionInfo,
} from "../src/server/index.js";
import { MemoryIssuanceStore } from "./fixtures/memory-stores.js";

// A controllable Signer that returns a programmed outcome and RECORDS every
// blindedMessage it was handed - so we can also assert the raw nonce never reaches
// it (anonymity invariant is partly proven here at the Issuer seam).
class MockSigner implements Signer {
  readonly backend = "local" as const;
  signCalls: SignArgs[] = [];
  constructor(private outcome: () => Promise<SignOutcome>) {}
  async getPublicKey(): Promise<PublicKeyOutcome> {
    return { status: "ready", publicKeySpki: new Uint8Array([1, 2, 3]) };
  }
  async sign(args: SignArgs): Promise<SignOutcome> {
    this.signCalls.push(args);
    return this.outcome();
  }
  async ensureKey(): Promise<void> {}
  async rotateKey(): Promise<RotateOutcome> {
    return { status: "rotated", publicKeySpki: new Uint8Array([1, 2, 3]) };
  }
}

const info: ActionInfo = { infoPrefix: "test", actionKey: "action-1" };
const baseArgs = {
  group: "g1",
  participant: "p1",
  info,
  blindedMessage: new Uint8Array([9, 9, 9]),
};

describe("Issuer one-per-(group, participant, actionKey)", () => {
  it("issues once and refuses a second issuance for the same tuple", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({
      status: "ok",
      blindSignature: new Uint8Array([7]),
    }));
    const issuer = createIssuer({ signer, issuanceStore: store });

    const first = await issuer.issue(baseArgs);
    expect(first.status).toBe("issued");

    const second = await issuer.issue(baseArgs);
    expect(second.status).toBe("already_issued");

    // The signer was called exactly once (the second never reached sign()).
    expect(signer.signCalls).toHaveLength(1);
    // One reservation row remains.
    expect(store.size()).toBe(1);
  });

  it("a different actionKey for the same participant is a distinct token", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({
      status: "ok",
      blindSignature: new Uint8Array([7]),
    }));
    const issuer = createIssuer({ signer, issuanceStore: store });

    expect((await issuer.issue(baseArgs)).status).toBe("issued");
    expect(
      (
        await issuer.issue({
          ...baseArgs,
          info: { infoPrefix: "test", actionKey: "action-2" },
        })
      ).status,
    ).toBe("issued");
    expect(store.size()).toBe(2);
  });
});

describe("Issuer rollback-on-failure (single token never burned)", () => {
  it("a SUCCESSFUL sign does NOT release the reservation", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({
      status: "ok",
      blindSignature: new Uint8Array([7]),
    }));
    const issuer = createIssuer({ signer, issuanceStore: store });

    const r = await issuer.issue(baseArgs);
    expect(r.status).toBe("issued");
    // No release on success - the reservation persists so it cannot be re-issued.
    expect(store.releaseCalls).toBe(0);
    expect(store.has({ group: "g1", participant: "p1", actionKey: "action-1" })).toBe(true);
  });

  it("a THROWN sign releases the reservation (signer_error, retryable)", async () => {
    const store = new MemoryIssuanceStore();
    const boom = new Error("transport down");
    const signer = new MockSigner(async () => {
      throw boom;
    });
    const issuer = createIssuer({ signer, issuanceStore: store });

    const r = await issuer.issue(baseArgs);
    expect(r.status).toBe("signer_error");
    if (r.status === "signer_error") expect(r.error).toBe(boom);
    // Released - so a retry can re-reserve.
    expect(store.releaseCalls).toBe(1);
    expect(store.size()).toBe(0);

    // Retry succeeds (the reservation was freed).
    const signer2 = new MockSigner(async () => ({
      status: "ok",
      blindSignature: new Uint8Array([7]),
    }));
    const issuer2 = createIssuer({ signer: signer2, issuanceStore: store });
    expect((await issuer2.issue(baseArgs)).status).toBe("issued");
  });

  it("a PENDING sign releases the reservation and is retryable", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({ status: "pending" }));
    const issuer = createIssuer({ signer, issuanceStore: store });

    const r = await issuer.issue(baseArgs);
    expect(r.status).toBe("pending");
    expect(store.releaseCalls).toBe(1);
    expect(store.size()).toBe(0);
  });

  it("a RATE_LIMITED sign releases the reservation and is retryable", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({ status: "rate_limited" }));
    const issuer = createIssuer({ signer, issuanceStore: store });

    const r = await issuer.issue(baseArgs);
    expect(r.status).toBe("rate_limited");
    expect(store.releaseCalls).toBe(1);
    expect(store.size()).toBe(0);
  });
});

describe("Issuer omits the public key when configured", () => {
  it("includePublicKeyOnIssue=false skips the getPublicKey round-trip", async () => {
    const store = new MemoryIssuanceStore();
    const signer = new MockSigner(async () => ({
      status: "ok",
      blindSignature: new Uint8Array([7]),
    }));
    const issuer = createIssuer({
      signer,
      issuanceStore: store,
      includePublicKeyOnIssue: false,
    });
    const r = await issuer.issue(baseArgs);
    expect(r.status).toBe("issued");
    if (r.status === "issued") expect(r.publicKeySpki).toBeUndefined();
  });
});
