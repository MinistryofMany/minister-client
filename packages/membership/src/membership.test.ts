import { describe, it, expect } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import { createMembership } from "./membership.js";
import { semaphoreEngine, rlnEngine } from "./engines/index.js";
import { inMemorySnapshotStore } from "./test-helpers.js";
import type { EligibleLeaf, RlnGroupProvider, SemaphoreGroupProvider } from "./provider.js";
import type { TreeRef } from "./types.js";

// createMembership composition: defaults, idempotent refresh, the engine/provider
// guard, and the empty-tree root.

function commitments(n: number): string[] {
  return Array.from({ length: n }, () => new Identity().commitment.toString());
}

function semaphoreProvider(getLeaves: () => EligibleLeaf[]): SemaphoreGroupProvider {
  return {
    shape: { kind: "dynamic" },
    engine: "semaphore",
    async listEligible() {
      return getLeaves();
    },
  };
}

describe("createMembership", () => {
  it("defaults the engine to the shipped one matching provider.engine", async () => {
    const cs = commitments(2);
    const provider = semaphoreProvider(() => cs.map((c) => ({ leaf: c, commitment: c })));
    const membership = createMembership({ provider }); // no engine, no store
    const ref: TreeRef = { context: "blog1", subTree: "author" };
    const snap = await membership.current(ref);
    expect(snap.engine).toBe("semaphore");
    expect(snap.eligibleCount).toBe(2);
    expect(snap.root).not.toBe("0");
  });

  it("the empty tree has root '0' (FreedInk convention)", async () => {
    const provider = semaphoreProvider(() => []);
    const membership = createMembership({ provider });
    const snap = await membership.current({ context: "blog1", subTree: "author" });
    expect(snap.root).toBe("0");
    expect(snap.eligibleCount).toBe(0);
    expect(snap.leaves).toEqual([]);
  });

  it("refresh persists idempotently on (context, subTree, root)", async () => {
    const cs = commitments(2);
    const provider = semaphoreProvider(() => cs.map((c) => ({ leaf: c, commitment: c })));
    const store = inMemorySnapshotStore();
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const a = await membership.refresh(ref);
    const b = await membership.refresh(ref); // unchanged tree -> no new row
    expect(a.snapshotId).toBeDefined();
    expect(b.snapshotId).toBe(a.snapshotId);
    expect(store.size()).toBe(1);
  });

  it("refresh after a membership change yields a NEW root + a new row", async () => {
    let cs = commitments(2);
    const provider = semaphoreProvider(() => cs.map((c) => ({ leaf: c, commitment: c })));
    const store = inMemorySnapshotStore();
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const before = await membership.refresh(ref);
    cs = [...cs, new Identity().commitment.toString()]; // add a member
    const after = await membership.refresh(ref);
    expect(after.root).not.toBe(before.root);
    expect(store.size()).toBe(2);
  });

  it("rejects a provider/engine mismatch", () => {
    const provider: SemaphoreGroupProvider = semaphoreProvider(() => []);
    expect(() =>
      // RLN engine with a Semaphore provider is a configuration error.
      createMembership({ provider, engine: rlnEngine }),
    ).toThrow(/engine/i);
  });

  it("verify on a fresh tree with an unknown root returns unknown-snapshot (semaphore)", async () => {
    const provider = semaphoreProvider(() => commitments(2).map((c) => ({ leaf: c, commitment: c })));
    const membership = createMembership({ provider, store: inMemorySnapshotStore() });
    const res = await membership.verify({
      ref: { context: "blog1", subTree: "author" },
      proof: {
        kind: "semaphore",
        merkleTreeDepth: 1,
        merkleTreeRoot: "123",
        nullifier: "1",
        message: "1",
        scope: "1",
        points: [],
      },
      expectedScope: "s",
      expectedMessage: "m",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("unknown-snapshot");
  });

  it("an RLN provider composes with the default rln engine and computes a depth-20 root", async () => {
    const cs = [111n, 222n, 333n];
    const provider: RlnGroupProvider = {
      shape: { kind: "fixed", depth: 20 },
      engine: "rln",
      async listEligible() {
        // For this pure-root test the leaf is the commitment itself; toLeaf maps
        // commitment -> rate commitment inside currentSnapshot.
        return cs.map((c) => ({ leaf: c.toString(), commitment: c.toString() }));
      },
      async engineParams() {
        return { engine: "rln", rlnIdentifier: "12345", userMessageLimit: 1 };
      },
    };
    const membership = createMembership({ provider });
    const snap = await membership.current({ context: "room1", subTree: "room" });
    expect(snap.engine).toBe("rln");
    expect(snap.shape).toEqual({ kind: "fixed", depth: 20 });
    expect(BigInt(snap.root)).toBeGreaterThan(0n);
    // The stored leaves are rate commitments, not the bare commitments.
    expect(snap.leaves).not.toContain("111");
  });
});
