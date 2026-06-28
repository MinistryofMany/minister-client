import { describe, it, expect } from "vitest";
import { resolveEngineParams } from "./provider.js";
import type {
  EligibleLeaf,
  MerkleGroupProvider,
  RlnGroupProvider,
  SemaphoreGroupProvider,
} from "./provider.js";

// MerkleGroupProvider seam: the discriminated provider type. An RLN provider
// MUST supply engineParams (control: structurally required when engine===rln); a
// Semaphore provider may omit it.

const noLeaves = async (): Promise<EligibleLeaf[]> => [];

describe("MerkleGroupProvider discriminated type", () => {
  it("a Semaphore provider typechecks WITHOUT engineParams", () => {
    const p: SemaphoreGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      listEligible: noLeaves,
    };
    expect(p.engine).toBe("semaphore");
  });

  it("an RLN provider typechecks WITH engineParams", () => {
    const p: RlnGroupProvider = {
      shape: { kind: "fixed", depth: 20 },
      engine: "rln",
      listEligible: noLeaves,
      async engineParams() {
        return { engine: "rln", rlnIdentifier: "12345", userMessageLimit: 1 };
      },
    };
    expect(p.engine).toBe("rln");
  });

  it("an RLN provider WITHOUT engineParams is a type error (structurally required)", () => {
    // @ts-expect-error - engineParams is REQUIRED on an RLN provider (control 3a):
    // an RLN provider cannot typecheck without it.
    const p: RlnGroupProvider = {
      shape: { kind: "fixed", depth: 20 },
      engine: "rln",
      listEligible: noLeaves,
    };
    // Reference p so it is not elided before the @ts-expect-error is evaluated.
    expect(p.engine).toBe("rln");
  });
});

describe("resolveEngineParams", () => {
  it("defaults a Semaphore provider that omits engineParams to { engine: 'semaphore' }", async () => {
    const p: MerkleGroupProvider = {
      shape: { kind: "dynamic" },
      engine: "semaphore",
      listEligible: noLeaves,
    };
    await expect(resolveEngineParams(p, "ctx")).resolves.toEqual({ engine: "semaphore" });
  });

  it("returns the RLN provider's engineParams", async () => {
    const p: MerkleGroupProvider = {
      shape: { kind: "fixed", depth: 20 },
      engine: "rln",
      listEligible: noLeaves,
      async engineParams(context) {
        return { engine: "rln", rlnIdentifier: `id:${context}`, userMessageLimit: 7 };
      },
    };
    await expect(resolveEngineParams(p, "room42")).resolves.toEqual({
      engine: "rln",
      rlnIdentifier: "id:room42",
      userMessageLimit: 7,
    });
  });
});
