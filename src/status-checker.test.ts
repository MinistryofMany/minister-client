import { describe, expect, it } from "vitest";

import { createMinisterStatusChecker, type StatusVerifyErrorInfo } from "./status-checker";
import { makeKeys, newStatusBits, setStatusBit, signStatusList, type TestKeys } from "./test-helpers";
import type { BadgeStatusRef } from "./status-list";

const ISSUER = "https://ministry.id";
const ISSUER_DID = "did:web:ministry.id";
const LIST_URL = "https://ministry.id/status/list_abc";
const REF: BadgeStatusRef = { uri: LIST_URL, index: 42 };

// A controllable fetch double: serves whatever JWT + version the test sets, with
// ETag/304 support, and can be flipped to an error/503 to exercise fail modes.
class FakeList {
  jwt = "";
  version = 0;
  mode: "ok" | "error" | "503" = "ok";
  calls = 0;

  fetch: typeof fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    this.calls += 1;
    if (this.mode === "error") throw new Error("network down");
    if (this.mode === "503") {
      return new Response("not yet published", { status: 503 });
    }
    const etag = `"${this.version}"`;
    const inm = new Headers(init?.headers).get("If-None-Match");
    if (inm === etag) {
      return new Response(null, { status: 304, headers: { etag } });
    }
    return new Response(this.jwt, { status: 200, headers: { etag } });
  }) as unknown as typeof fetch;
}

async function publish(
  keys: TestKeys,
  list: FakeList,
  version: number,
  revokedIndices: number[],
  expDeltaSec = 900,
): Promise<void> {
  const bits = newStatusBits();
  for (const i of revokedIndices) setStatusBit(bits, i);
  list.jwt = await signStatusList({
    privateKey: keys.privateKey,
    issuerDid: ISSUER_DID,
    listUrl: LIST_URL,
    version,
    bits,
    expDeltaSec,
  });
  list.version = version;
}

describe("createMinisterStatusChecker", () => {
  it("returns valid for a clear bit and revoked for a set bit", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    await publish(keys, list, 1, []);
    const checker = createMinisterStatusChecker({ issuer: ISSUER, key: keys.publicJwk, fetchImpl: list.fetch });

    expect(await checker.check(REF)).toBe("valid");

    await publish(keys, list, 2, [42]);
    // Force a refetch by using a fresh checker (poll interval would otherwise cache).
    const checker2 = createMinisterStatusChecker({ issuer: ISSUER, key: keys.publicJwk, fetchImpl: list.fetch });
    expect(await checker2.check(REF)).toBe("revoked");
  });

  it("LATCHES a revocation irreversibly: a later (rolled-back) clear list can never un-revoke", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0, // always refetch
      nowFn: () => clock,
    });

    await publish(keys, list, 5, [42]);
    expect(await checker.check(REF)).toBe("revoked");
    expect(checker.isLatched(REF)).toBe(true);

    // Attacker serves an OLDER, validly-signed, CLEAR list.
    clock += 1000;
    await publish(keys, list, 4, []);
    expect(await checker.check(REF)).toBe("revoked"); // latch holds

    // Even a NEWER clear list cannot un-revoke (revocation is irreversible).
    clock += 1000;
    await publish(keys, list, 6, []);
    expect(await checker.check(REF)).toBe("revoked");
  });

  it("rejects a version rollback (defense 3) and keeps the last-known revoked state", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      nowFn: () => clock,
    });

    await publish(keys, list, 10, []);
    expect(await checker.check(REF)).toBe("valid");

    // A rollback to an older version showing the bit set must be rejected — the
    // high-water mark (10) beats version 3, so the last-known (valid) is kept.
    clock += 1000;
    await publish(keys, list, 3, [42]);
    expect(await checker.check(REF)).toBe("valid");
  });

  it("fail-open (default): serves the last-known CLEAR bit when the list goes unfetchable", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      nowFn: () => clock,
    });

    await publish(keys, list, 1, []);
    expect(await checker.check(REF)).toBe("valid");

    // Publisher/CDN outage past the signed exp — fail open on last-known clear.
    list.mode = "error";
    clock += 20 * 60_000; // 20 min later (list exp was +15 min)
    expect(await checker.check(REF)).toBe("valid");
  });

  it("fail-closed knob: returns stale on an unfetchable list past exp", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      staleFailMode: "closed",
      nowFn: () => clock,
    });

    await publish(keys, list, 1, []);
    expect(await checker.check(REF)).toBe("valid");

    list.mode = "error";
    clock += 20 * 60_000;
    expect(await checker.check(REF)).toBe("stale");
  });

  it("maxStaleMs hard cap: fail-open stops honoring last-known past the cap", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      maxStaleMs: 60_000, // only 1 min of grace past exp
      nowFn: () => clock,
    });

    await publish(keys, list, 1, [], 60); // exp in 60s
    expect(await checker.check(REF)).toBe("valid");

    list.mode = "error";
    clock += 30_000; // 30s past fetch, still within exp
    expect(await checker.check(REF)).toBe("valid");

    clock += 5 * 60_000; // well past exp + cap
    expect(await checker.check(REF)).toBe("stale");
  });

  it("returns stale for a brand-new list still 503-ing (no last-known state)", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    list.mode = "503";
    const checker = createMinisterStatusChecker({ issuer: ISSUER, key: keys.publicJwk, fetchImpl: list.fetch });
    expect(await checker.check(REF)).toBe("stale");
  });

  it("Warning A: fail-open honors a FINITE default cap (~1h), then fails closed", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      nowFn: () => clock,
    });
    await publish(keys, list, 1, [], 60); // exp in 60s
    expect(await checker.check(REF)).toBe("valid");

    // Unreachable list. Within the 1h default cap => still fail-open valid.
    list.mode = "error";
    clock += 30 * 60_000; // ~30 min past exp
    expect(await checker.check(REF)).toBe("valid");

    // Past the finite default cap => the un-refreshed CLEAR bit fails CLOSED.
    clock += 40 * 60_000; // ~70 min past exp, beyond the 1h default
    expect(await checker.check(REF)).toBe("stale");
  });

  it("C1: a forged 200 body (bad signature) fails CLOSED past exp, not silent fail-open", async () => {
    const keys = await makeKeys();
    const attacker = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const verifyErrors: StatusVerifyErrorInfo[] = [];
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0, // always refetch
      nowFn: () => clock,
      onVerifyError: (info) => verifyErrors.push(info),
    });

    await publish(keys, list, 1, [], 60); // exp in 60s
    expect(await checker.check(REF)).toBe("valid");

    // Attacker serves a well-formed 200 signed by a DIFFERENT key, version bumped
    // so it is not a 304. Verification must fail on the signature.
    list.jwt = await signStatusList({
      privateKey: attacker.privateKey,
      issuerDid: ISSUER_DID,
      listUrl: LIST_URL,
      version: 2,
      bits: newStatusBits(),
      expDeltaSec: 900,
    });
    list.version = 2;

    // Past the good snapshot's exp but well within the 1h fail-open cap. A verify
    // failure (not an outage) must still fail CLOSED and be reported.
    clock += 5 * 60_000;
    expect(await checker.check(REF)).toBe("stale");
    expect(verifyErrors.length).toBeGreaterThan(0);
    expect(verifyErrors[verifyErrors.length - 1]!.consecutiveFailures).toBeGreaterThanOrEqual(1);
    expect(verifyErrors[verifyErrors.length - 1]!.uri).toBe(LIST_URL);
  });

  it("S1: an out-of-range status index fails CLOSED (revoked), never silently valid", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    const verifyErrors: StatusVerifyErrorInfo[] = [];
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      onVerifyError: (info) => verifyErrors.push(info),
    });
    await publish(keys, list, 1, []); // a full 8,192-bit, all-clear list
    // 9000 is within parseCredentialStatus's 2^20 ceiling but past this shard's
    // 8,192 bits: a malformed pointer. bitIsSet would read byte 1125 as clear.
    const outOfRange: BadgeStatusRef = { uri: LIST_URL, index: 9000 };
    expect(await checker.check(outOfRange)).toBe("revoked");
    expect(verifyErrors.length).toBeGreaterThan(0);
  });

  it("herd-private: a 304 keeps the cached snapshot without a full re-verify", async () => {
    const keys = await makeKeys();
    const list = new FakeList();
    let clock = Date.now();
    const checker = createMinisterStatusChecker({
      issuer: ISSUER,
      key: keys.publicJwk,
      fetchImpl: list.fetch,
      pollIntervalMs: 0,
      nowFn: () => clock,
    });
    await publish(keys, list, 1, []);
    expect(await checker.check(REF)).toBe("valid");
    const callsAfterFirst = list.calls;
    // Second check refetches (poll interval 0) but the server 304s (same version).
    clock += 1000;
    expect(await checker.check(REF)).toBe("valid");
    expect(list.calls).toBeGreaterThan(callsAfterFirst); // it did poll
  });
});
