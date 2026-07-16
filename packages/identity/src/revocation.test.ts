import { describe, expect, it } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import { InMemoryRevocationRegistry } from "./revocation.js";
import { excludeRevoked } from "./types.js";
import type { AnonContext, SemaphoreIdentityLike } from "./types.js";
import { PER_APP_SECRET_BYTES, deriveIdentity } from "./derive.js";

/** A random per-app secret; distinct calls give distinct commitments. */
function randomSecret(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(PER_APP_SECRET_BYTES));
}
const ROOM1: AnonContext = { kind: "room", id: "1" };

describe("SemaphoreIdentityLike contract", () => {
  it("a derived identity satisfies the structural shape membership consumes", async () => {
    const id = await deriveIdentity(randomSecret(), { kind: "room", id: "ctx" });
    // Structural: commitment decimal string + opaque native handle.
    const like: SemaphoreIdentityLike = id;
    expect(typeof like.commitment).toBe("string");
    expect(like.commitment).toMatch(/^[0-9]+$/);
    expect(like.native).toBeInstanceOf(Identity);
    // native narrows back to a v4 Identity whose commitment matches the string.
    expect((like.native as Identity).commitment.toString()).toBe(like.commitment);
  });
});

describe("per-device commitment lifecycle + revocation contract", () => {
  it("registers active devices; revoke flips status and surfaces the revoked commitment", async () => {
    const reg = new InMemoryRevocationRegistry();
    const seedX = randomSecret();
    const seedY = randomSecret();
    const idX = await deriveIdentity(seedX, ROOM1);
    const idY = await deriveIdentity(seedY, ROOM1);

    reg.register("room:1", "device-x", idX.commitment);
    reg.register("room:1", "device-y", idY.commitment);

    expect(await reg.revokedCommitments("room:1")).toEqual(new Set());

    const revoked = await reg.revoke("room:1", "device-x");
    expect(revoked?.status).toBe("revoked");
    expect(await reg.revokedCommitments("room:1")).toEqual(new Set([idX.commitment]));

    const list = await reg.list("room:1");
    expect(list).toHaveLength(2);
    expect(list.find((d) => d.deviceId === "device-y")?.status).toBe("active");
  });

  it("revoke is idempotent and returns null for an unknown device/context", async () => {
    const reg = new InMemoryRevocationRegistry();
    reg.register("room:1", "device-x", "123");
    const first = await reg.revoke("room:1", "device-x");
    const second = await reg.revoke("room:1", "device-x");
    expect(first?.status).toBe("revoked");
    expect(second?.status).toBe("revoked");
    expect(await reg.revoke("room:1", "missing")).toBeNull();
    expect(await reg.revoke("no-such-room", "device-x")).toBeNull();
  });

  it("a rotated device keeps its revoked status (stays excluded)", async () => {
    const reg = new InMemoryRevocationRegistry();
    reg.register("room:1", "device-x", "111");
    await reg.revoke("room:1", "device-x");
    // Key rotation: same deviceId, new commitment.
    reg.register("room:1", "device-x", "222");
    const revoked = await reg.revokedCommitments("room:1");
    expect(revoked).toEqual(new Set(["222"]));
  });

  it("excludeRevoked subtracts revoked commitments and preserves order (membership root contract)", async () => {
    const reg = new InMemoryRevocationRegistry();
    const seeds = [randomSecret(), randomSecret(), randomSecret()];
    const ids = await Promise.all(seeds.map((s) => deriveIdentity(s, ROOM1)));
    ids.forEach((id, i) => reg.register("room:1", `device-${i}`, id.commitment));

    await reg.revoke("room:1", "device-1"); // revoke the middle one

    const eligibleAll = ids.map((i) => i.commitment); // provider-ordered leaf set
    const revoked = await reg.revokedCommitments("room:1");
    const remaining = excludeRevoked(eligibleAll, revoked);

    expect(remaining).toEqual([ids[0]!.commitment, ids[2]!.commitment]);
    // a revoked device can no longer appear in the rebuilt leaf set / root
    expect(remaining).not.toContain(ids[1]!.commitment);
  });
});
