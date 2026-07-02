// RemoteSigner HTTP-transport behavior, with node:https mocked so no real TLS /
// network is exercised. Covers finding #8:
//   - a Signet 409 (tuple already committed) maps to a coherent terminal
//     `already_issued` instead of an opaque throw (M2);
//   - the in-process public-key cache honors a bounded TTL so an out-of-band key
//     rotation cannot pin a stale key forever (L2).
//
// The mock records every request and lets each test program the response.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const hook = vi.hoisted(() => ({
  calls: [] as { method: string; path: string }[],
  handler: null as null | ((method: string, path: string) => { status: number; body: string }),
}));

vi.mock("node:https", () => {
  class FakeAgent {
    constructor(_opts: unknown) {}
  }
  function makeRes(status: number, body: string) {
    const listeners: Record<string, Array<(...a: unknown[]) => void>> = {};
    return {
      statusCode: status,
      on(ev: string, fn: (...a: unknown[]) => void) {
        (listeners[ev] ||= []).push(fn);
        return this;
      },
      _emit(ev: string, ...args: unknown[]) {
        for (const fn of listeners[ev] ?? []) fn(...args);
      },
    };
  }
  function request(options: { method: string; path: string }, cb: (res: unknown) => void) {
    hook.calls.push({ method: options.method, path: options.path });
    const req = {
      on() {
        return req;
      },
      setTimeout() {
        return req;
      },
      write() {},
      end() {
        const { status, body } = hook.handler
          ? hook.handler(options.method, options.path)
          : { status: 200, body: "{}" };
        // Resolve on a microtask so the caller's await sees an async response.
        queueMicrotask(() => {
          const res = makeRes(status, body);
          cb(res);
          res._emit("data", Buffer.from(body, "utf8"));
          res._emit("end");
        });
      },
    };
    return req;
  }
  return { Agent: FakeAgent, request };
});

// Imported AFTER the mock is declared (vi.mock is hoisted above imports anyway).
const { createRemoteSigner } = await import("../src/server/index.js");
type ActionInfo = import("../src/server/index.js").ActionInfo;

const DUMMY_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const PREFIX = "freedink-vote";
const info: ActionInfo = { infoPrefix: PREFIX, actionKey: "a1" };

function makeSigner(pubKeyCacheTtlMs?: number) {
  return createRemoteSigner({
    baseUrl: "https://signet.invalid:8443",
    clientCert: DUMMY_PEM,
    clientKey: DUMMY_PEM,
    caCert: DUMMY_PEM,
    infoPrefix: PREFIX,
    pubKeyCacheTtlMs,
  });
}

function keyGets(): number {
  return hook.calls.filter((c) => c.method === "GET" && c.path.startsWith("/key")).length;
}

beforeEach(() => {
  hook.calls.length = 0;
  hook.handler = null;
});

describe("RemoteSigner.sign 409 mapping (finding #8 / M2)", () => {
  it("maps a Signet 409 (tuple already signed) to already_issued instead of throwing", async () => {
    hook.handler = () => ({ status: 409, body: '{"error":"already issued for this tuple"}' });
    const signer = makeSigner();
    const outcome = await signer.sign({
      group: "g",
      participant: "p",
      info,
      blindedMessage: new Uint8Array([1, 2, 3]),
    });
    expect(outcome.status).toBe("already_issued");
  });

  it("still throws on a genuine 400 (bad blinded message)", async () => {
    hook.handler = () => ({ status: 400, body: '{"error":"bad blinded_message"}' });
    const signer = makeSigner();
    await expect(
      signer.sign({ group: "g", participant: "p", info, blindedMessage: new Uint8Array([1]) }),
    ).rejects.toThrow(/Signet \/sign failed \(400\)/);
  });
});

describe("RemoteSigner public-key cache TTL (finding #8 / L2)", () => {
  const spkiB64 = Buffer.from([9, 9, 9]).toString("base64");

  it("with a live TTL, serves the cached key without re-fetching", async () => {
    hook.handler = () => ({ status: 200, body: JSON.stringify({ public_key: spkiB64 }) });
    const signer = makeSigner(60_000);
    await signer.getPublicKey("g");
    await signer.getPublicKey("g");
    expect(keyGets()).toBe(1); // second served from cache
  });

  it("with TTL=0, never serves a stale cached key (always re-fetches)", async () => {
    hook.handler = () => ({ status: 200, body: JSON.stringify({ public_key: spkiB64 }) });
    const signer = makeSigner(0);
    await signer.getPublicKey("g");
    await signer.getPublicKey("g");
    expect(keyGets()).toBe(2); // no stale cache: both hit the network
  });

  it("re-fetches once the TTL elapses (bounded staleness after out-of-band rotation)", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(0);
      hook.handler = () => ({ status: 200, body: JSON.stringify({ public_key: spkiB64 }) });
      const signer = makeSigner(1_000);
      await signer.getPublicKey("g"); // fetch #1
      await signer.getPublicKey("g"); // cached
      expect(keyGets()).toBe(1);
      vi.setSystemTime(1_500); // past the 1s TTL
      await signer.getPublicKey("g"); // fetch #2
      expect(keyGets()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
