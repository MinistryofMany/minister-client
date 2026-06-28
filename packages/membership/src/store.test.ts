import { describe, it, expect } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import { liveSnapshotStore } from "./store.js";
import { currentSnapshot } from "./snapshot.js";
import { semaphoreEngine } from "./engines/index.js";
import type { EligibleLeaf, SemaphoreGroupProvider } from "./provider.js";
import type { TreeRef } from "./types.js";

// liveSnapshotStore (Discreetly path): no persistence, root recomputed live,
// exactly ONCE per getByRoot (the design's live-store cost risk).

function semaphoreProviderOf(
  leavesByTree: (ref: TreeRef) => EligibleLeaf[],
  onList?: (ref: TreeRef) => void,
): SemaphoreGroupProvider {
  return {
    shape: { kind: "dynamic" },
    engine: "semaphore",
    async listEligible(ref) {
      onList?.(ref);
      return leavesByTree(ref);
    },
  };
}

function commitments(n: number): string[] {
  return Array.from({ length: n }, () => new Identity().commitment.toString());
}

describe("liveSnapshotStore", () => {
  it("put is a no-op echo (no snapshotId, no persistence)", async () => {
    const provider = semaphoreProviderOf(() => []);
    const store = liveSnapshotStore(provider, semaphoreEngine);
    const ref: TreeRef = { context: "blog1", subTree: "author" };
    const snap = await currentSnapshot(provider, semaphoreEngine, ref);
    const echoed = await store.put(snap);
    expect(echoed).toEqual(snap);
    expect(echoed.snapshotId).toBeUndefined();
  });

  it("getByRoot returns the live snapshot iff the root equals the current live root", async () => {
    const cs = commitments(3);
    const leaves: EligibleLeaf[] = cs.map((c) => ({ leaf: c, commitment: c }));
    const provider = semaphoreProviderOf(() => leaves);
    const store = liveSnapshotStore(provider, semaphoreEngine);
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const live = await currentSnapshot(provider, semaphoreEngine, ref);

    const hit = await store.getByRoot(ref, live.root);
    expect(hit.found).toBe(true);
    if (hit.found) expect(hit.snapshot.root).toBe(live.root);

    const miss = await store.getByRoot(ref, "999999");
    expect(miss.found).toBe(false);
    if (!miss.found) expect(miss.stale).toBe(true); // live store has no history
  });

  it("recomputes the live root EXACTLY ONCE per getByRoot", async () => {
    let listCalls = 0;
    const cs = commitments(2);
    const leaves: EligibleLeaf[] = cs.map((c) => ({ leaf: c, commitment: c }));
    const provider = semaphoreProviderOf(
      () => leaves,
      () => {
        listCalls += 1;
      },
    );
    const store = liveSnapshotStore(provider, semaphoreEngine);
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    // Resolve the live root once to know it, resetting the counter afterwards.
    const live = await currentSnapshot(provider, semaphoreEngine, ref);
    listCalls = 0;

    await store.getByRoot(ref, live.root, { requireCurrentRoot: true });
    // listEligible (the recompute) must be hit exactly once - not twice (once for
    // the lookup, once for the requireCurrentRoot check).
    expect(listCalls).toBe(1);
  });

  it("defaults the engine from provider.engine when none is passed", async () => {
    const cs = commitments(2);
    const leaves: EligibleLeaf[] = cs.map((c) => ({ leaf: c, commitment: c }));
    const provider = semaphoreProviderOf(() => leaves);
    // No engine argument: the store must resolve the shipped semaphore engine.
    const store = liveSnapshotStore(provider);
    const ref: TreeRef = { context: "blog1", subTree: "author" };
    const live = await currentSnapshot(provider, semaphoreEngine, ref);
    const hit = await store.getByRoot(ref, live.root);
    expect(hit.found).toBe(true);
  });
});
