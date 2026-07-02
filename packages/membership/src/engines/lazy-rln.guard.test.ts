import { describe, it, expect, vi } from "vitest";

// PACKAGING GUARD (Stage 0 of the FreedInk migration): the package ROOT must
// never evaluate ./rln.js (and with it @ministryofmany/rln -> rlnjs + Semaphore
// v3) unless a consumer actually selects the rln backend. A static import
// anywhere on the root graph would drag the island back into semaphore-only SSR
// consumers. The mock factory below THROWS on module evaluation, so:
//   - if any root-entry module statically imported ./rln.js, importing the root
//     below would explode - failing this suite;
//   - the semaphore paths must complete without ever tripping it;
//   - selecting rln MUST trip it (proving the dynamic import is the real path).

vi.mock("./rln.js", () => {
  throw new Error("RLN_MODULE_EVALUATED");
});

describe("lazy-rln packaging guard: the root graph never evaluates ./rln.js", () => {
  it("importing the root entry + resolving the semaphore engine never loads ./rln.js", async () => {
    // Dynamic import so the vi.mock above is active first. If ./index.js (or any
    // module it statically reaches) imported ./rln.js eagerly, this line throws.
    const root = await import("../index.js");
    const engine = await root.engineFor("semaphore");
    expect(engine.kind).toBe("semaphore");
    expect(engine).toBe(root.semaphoreEngine);
  });

  it("a semaphore createMembership round-trip never loads ./rln.js", async () => {
    const { createMembership } = await import("../index.js");
    const membership = createMembership({
      provider: {
        shape: { kind: "dynamic" },
        engine: "semaphore",
        async listEligible() {
          return [{ leaf: "1", commitment: "1" }];
        },
      },
    });
    const snap = await membership.current({ context: "blog1", subTree: "author" });
    expect(snap.engine).toBe("semaphore");
    expect(snap.root).not.toBe("0");
  });

  it("the client entry's semaphore routing never loads ./rln.js", async () => {
    const { generateMembershipProof } = await import("../client.js");
    await expect(
      generateMembershipProof({
        identity: { commitment: "1", native: new (class { commitment = 1n })() },
        snapshot: {
          ref: { context: "c", subTree: "t" },
          root: "1",
          leaves: ["1"],
          eligibleCount: 1,
          shape: { kind: "dynamic" },
          engine: "semaphore",
        },
        scope: "s",
        message: "m",
        artifacts: {
          async load() {
            throw new Error("SENTINEL_ARTIFACTS");
          },
        },
      }),
      // It must fail at the SEMAPHORE artifact sentinel - never at the rln mock.
    ).rejects.toThrow("SENTINEL_ARTIFACTS");
  });

  it("selecting the rln backend DOES evaluate ./rln.js (the dynamic import is the real path)", async () => {
    const { engineFor } = await import("../index.js");
    // The mock throws on evaluation; loadRlnEngine wraps it in its
    // missing-optional-peer error with the original as `cause` - proving
    // engineFor("rln") is what triggers module evaluation, and nothing earlier.
    await expect(engineFor("rln")).rejects.toThrow(/@ministryofmany\/rln/);
  });
});
