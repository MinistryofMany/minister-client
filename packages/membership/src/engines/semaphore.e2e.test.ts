import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Identity } from "@semaphore-protocol/identity";
import { semaphoreEngine } from "./semaphore.js";
import { createMembership } from "../membership.js";
import { liveSnapshotStore } from "../store.js";
import { inMemorySnapshotStore } from "../test-helpers.js";
import type { ArtifactSource } from "../artifacts.js";
import type { EligibleLeaf, SemaphoreGroupProvider } from "../provider.js";
import type { SemaphoreIdentityLike } from "@minister/identity";
import type { TreeRef } from "../types.js";

// Real Semaphore v4 proof, end-to-end, plus the two authorization controls that
// matter most:
//   - R1 pin (control 1): a role-A proof FAILS a role-B verify.
//   - BANNED-EXCLUSION (control 2): a banned commitment cannot prove against the
//     refreshed root (requireCurrentRoot).
//
// The depth-N Semaphore circuit artifacts are INJECTED, not hard-coded. We source
// them from FreedInk's vendored static/snark-artifacts (the lifted-from origin);
// if absent the proof tests skip (the pure-logic controls below still gate the
// engine via the other suites).

const ARTIFACT_BASE = fileURLToPath(
  new URL("../../../../../../../../FreedInk/static/snark-artifacts/semaphore/", import.meta.url),
);

function artifactPaths(depth: number): { wasm: string; zkey: string } {
  return {
    wasm: `${ARTIFACT_BASE}${depth}/semaphore-${depth}.wasm`,
    zkey: `${ARTIFACT_BASE}${depth}/semaphore-${depth}.zkey`,
  };
}

// We need artifacts for depths 1..3 (groups of 2..N members -> depth 1..2).
const haveArtifacts = [1, 2, 3].every((d) => {
  const p = artifactPaths(d);
  return existsSync(p.wasm) && existsSync(p.zkey);
});

function fileArtifactSource(): ArtifactSource {
  return {
    async load(depth: number) {
      const p = artifactPaths(depth);
      return { wasm: new Uint8Array(readFileSync(p.wasm)), zkey: new Uint8Array(readFileSync(p.zkey)) };
    },
  };
}

function likeOf(id: Identity): SemaphoreIdentityLike {
  return { commitment: id.commitment.toString(), native: id };
}

function leavesOf(ids: Identity[]): EligibleLeaf[] {
  return ids.map((i) => {
    const c = i.commitment.toString();
    return { leaf: c, commitment: c };
  });
}

function providerFor(getIds: () => Identity[]): SemaphoreGroupProvider {
  return {
    shape: { kind: "dynamic" },
    engine: "semaphore",
    async listEligible() {
      return leavesOf(getIds());
    },
  };
}

describe.runIf(haveArtifacts)("semaphoreEngine end-to-end (real v4 proof)", () => {
  it("a real Semaphore membership proof verifies against the live snapshot", async () => {
    const me = new Identity();
    const members = [me, new Identity(), new Identity()];
    const provider = providerFor(() => members);
    const membership = createMembership({ provider, store: liveSnapshotStore(provider, semaphoreEngine) });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const snapshot = await membership.current(ref);
    const proof = await semaphoreEngine.prove({
      identity: likeOf(me),
      snapshot,
      scope: "post:create",
      message: "hello world",
      artifacts: fileArtifactSource(),
    });

    expect(proof.kind).toBe("semaphore");
    expect(proof.merkleTreeRoot).toBe(snapshot.root);

    const res = await membership.verify({
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "hello world",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.nullifier).toBe(proof.nullifier);
      expect(res.rln).toBeUndefined();
    }
  }, 60_000);

  it("R1 pin: a role-A (author) proof FAILS a role-B (comment) verify", async () => {
    // Two trees in the SAME blog. The member is in BOTH, but the proof is frozen
    // against the author tree's snapshot; verifying it as the comment tree must
    // fail because the store pins on (context, subTree, root) and the author root
    // is not a known comment-tree root.
    const me = new Identity();
    const authorMembers = [me, new Identity()];
    const commentMembers = [me, new Identity(), new Identity()]; // different set -> different root

    const provider: SemaphoreGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      async listEligible(ref) {
        return ref.subTree === "author" ? leavesOf(authorMembers) : leavesOf(commentMembers);
      },
    };

    // Persisted store so both trees' roots can be frozen and pinned by ref.
    const store = inMemorySnapshotStore();
    const membership = createMembership({ provider, store });
    const authorRef: TreeRef = { context: "blog1", subTree: "author" };
    const commentRef: TreeRef = { context: "blog1", subTree: "comment" };

    await membership.refresh(authorRef);
    await membership.refresh(commentRef);

    const authorSnap = await membership.current(authorRef);
    const proof = await semaphoreEngine.prove({
      identity: likeOf(me),
      snapshot: authorSnap,
      scope: "post:create",
      message: "m",
      artifacts: fileArtifactSource(),
    });

    // Same proof, verified as the AUTHOR tree -> ok.
    const okRes = await membership.verify({
      ref: authorRef,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
    });
    expect(okRes.ok).toBe(true);

    // Same proof, verified as the COMMENT tree -> rejected (R1): the author root
    // is not a known comment-tree snapshot.
    const badRes = await membership.verify({
      ref: commentRef,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
    });
    expect(badRes.ok).toBe(false);
    if (!badRes.ok) expect(badRes.reason).toBe("unknown-snapshot");
  }, 90_000);

  it("BANNED-EXCLUSION: a banned commitment cannot prove against the refreshed root", async () => {
    // The member proves against the pre-ban snapshot. After a ban, listEligible
    // omits them and refresh() yields a NEW root; verify with requireCurrentRoot
    // rejects the stale-root proof.
    const me = new Identity();
    let banned = false;
    const all = [me, new Identity(), new Identity()];
    const provider: SemaphoreGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      async listEligible() {
        const live = banned ? all.filter((i) => i !== me) : all;
        return leavesOf(live);
      },
    };
    // Persisted store WITH the live provider so requireCurrentRoot recomputes.
    const store = inMemorySnapshotStore({ liveProvider: provider, engine: semaphoreEngine });
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    // Freeze the pre-ban snapshot and prove against it.
    const preBan = await membership.refresh(ref);
    const proof = await semaphoreEngine.prove({
      identity: likeOf(me),
      snapshot: preBan,
      scope: "post:create",
      message: "m",
      artifacts: fileArtifactSource(),
    });

    // Before the ban, requireCurrentRoot accepts (root is current).
    const before = await membership.verify({
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
      requireCurrentRoot: true,
    });
    expect(before.ok).toBe(true);

    // Ban the member and refresh -> a new root that excludes their commitment.
    banned = true;
    const postBan = await membership.refresh(ref);
    expect(postBan.root).not.toBe(preBan.root);
    expect(postBan.leaves).not.toContain(me.commitment.toString());

    // The stale-root proof now fails requireCurrentRoot (banned-exclusion).
    const after = await membership.verify({
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
      requireCurrentRoot: true,
    });
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.reason).toBe("stale-root");
  }, 90_000);

  it("SAFE DEFAULT: a verify WITHOUT requireCurrentRoot rejects a stale pre-ban root (fail-closed)", async () => {
    // Same banned-exclusion scenario, but verify() does NOT pass the flag. With
    // the fail-closed default (requireCurrentRoot defaults to true), a forgetful
    // persisted-store consumer still rejects the just-banned member's pre-ban
    // snapshot.
    const me = new Identity();
    let banned = false;
    const all = [me, new Identity(), new Identity()];
    const provider: SemaphoreGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      async listEligible() {
        const live = banned ? all.filter((i) => i !== me) : all;
        return leavesOf(live);
      },
    };
    const store = inMemorySnapshotStore({ liveProvider: provider, engine: semaphoreEngine });
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const preBan = await membership.refresh(ref);
    const proof = await semaphoreEngine.prove({
      identity: likeOf(me),
      snapshot: preBan,
      scope: "post:create",
      message: "m",
      artifacts: fileArtifactSource(),
    });

    // Ban + refresh -> new root excluding the member.
    banned = true;
    const postBan = await membership.refresh(ref);
    expect(postBan.root).not.toBe(preBan.root);

    // No requireCurrentRoot passed: the default is now TRUE, so the stale root is
    // rejected (fail-closed).
    const after = await membership.verify({
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
    });
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.reason).toBe("stale-root");
  }, 90_000);

  it("EXPLICIT requireCurrentRoot:false still accepts a stale pre-ban root (lenient historical mode)", async () => {
    // The deliberately-lenient mode (FreedInk comments) must still be honored: an
    // explicit `false` accepts a historically-known snapshot even after a ban.
    const me = new Identity();
    let banned = false;
    const all = [me, new Identity(), new Identity()];
    const provider: SemaphoreGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      async listEligible() {
        const live = banned ? all.filter((i) => i !== me) : all;
        return leavesOf(live);
      },
    };
    const store = inMemorySnapshotStore({ liveProvider: provider, engine: semaphoreEngine });
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "blog1", subTree: "author" };

    const preBan = await membership.refresh(ref);
    const proof = await semaphoreEngine.prove({
      identity: likeOf(me),
      snapshot: preBan,
      scope: "post:create",
      message: "m",
      artifacts: fileArtifactSource(),
    });

    // Ban + refresh -> new current root; the pre-ban snapshot stays known to the
    // store (it was frozen by refresh()).
    banned = true;
    await membership.refresh(ref);

    // Explicit false: the stale pre-ban root is still accepted (lenient mode).
    const res = await membership.verify({
      ref,
      proof,
      expectedScope: "post:create",
      expectedMessage: "m",
      requireCurrentRoot: false,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.nullifier).toBe(proof.nullifier);
  }, 90_000);
});
