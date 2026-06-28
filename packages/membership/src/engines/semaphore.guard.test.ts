import { describe, it, expect } from "vitest";
import { semaphoreEngine } from "./semaphore.js";
import type { SemaphoreProof, VerifyContext } from "../engine.js";
import type { GetByRootResult, SnapshotStore } from "../store.js";
import type { MembershipSnapshot, TreeRef } from "../types.js";

// FIX B (defense-in-depth): the Semaphore engine must not trust a SnapshotStore
// that returns a row whose root differs from the requested proof root. Even
// though getByRoot's contract is to pin on (context, subTree, root), a buggy or
// malicious future store could return a wrong-root snapshot; the engine guards
// `snapshot.root === proof.merkleTreeRoot` explicitly and returns invalid-proof
// BEFORE running the SNARK, matching the RLN engine which forces snapshot.root as
// expectedRoot.

const ref: TreeRef = { context: "blog1", subTree: "author" };

function semaphoreProof(root: string): SemaphoreProof {
  return {
    kind: "semaphore",
    merkleTreeDepth: 1,
    merkleTreeRoot: root,
    nullifier: "1",
    message: "1",
    scope: "1",
    points: [],
  };
}

/** A store that lies: it returns a found snapshot whose root does NOT match the
 *  requested root (the exact failure FIX B defends against). */
function wrongRootStore(returnedRoot: string): SnapshotStore {
  const snapshot: MembershipSnapshot = {
    ref,
    root: returnedRoot,
    leaves: [],
    eligibleCount: 0,
    shape: { kind: "dynamic" },
    engine: "semaphore",
  };
  return {
    async put(s) {
      return s;
    },
    async getByRoot(): Promise<GetByRootResult> {
      return { found: true, snapshot };
    },
  };
}

describe("semaphoreEngine.verify wrong-root guard (FIX B)", () => {
  it("rejects with invalid-proof when the store returns a snapshot whose root != proof root", async () => {
    const proof = semaphoreProof("111");
    const ctx: VerifyContext = {
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
      // The store returns a DIFFERENT root than the proof's.
      store: wrongRootStore("222"),
    };
    const res = await semaphoreEngine.verify(ctx);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("invalid-proof");
  });

  it("does not short-circuit when the store honestly returns the matching root", async () => {
    // A matching-root store passes the guard and proceeds to the scope check; we
    // assert it gets PAST the guard (failing later at scope-mismatch, not at the
    // wrong-root guard), proving the guard only fires on a genuine mismatch.
    const proof = semaphoreProof("333");
    const ctx: VerifyContext = {
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
      store: wrongRootStore("333"), // root matches the proof root
    };
    const res = await semaphoreEngine.verify(ctx);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("scope-mismatch");
  });
});
