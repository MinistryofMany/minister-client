import { describe, it, expect } from "vitest";
import { semaphoreEngine } from "./semaphore.js";
import { rlnEngine } from "./rln.js";
import { asRlnLeaf, asSemaphoreLeaf } from "../types.js";
import type { Leaf, RlnLeaf, SemaphoreLeaf, TreeShape } from "../types.js";
import type { EngineParams } from "../provider.js";

// ENGINE ISOLATION (control 3). The v4 leaf (bare identity commitment) and the
// v3 RLN leaf (rate commitment) are both decimal strings. Without a nominal
// brand a v4 leaf could flow into the depth-20 RLN tree and silently produce a
// wrong-but-valid root. These tests assert both halves:
//   (a) the two engines map the SAME raw commitment to DIFFERENT leaves, and the
//       two trees produce DIFFERENT roots for identical raw leaves;
//   (b) the brand makes "use a v4 leaf as an RLN leaf" a TYPE error.

const semaphoreParams: EngineParams = { engine: "semaphore" };
const rlnParams: EngineParams = { engine: "rln", rlnIdentifier: "12345", userMessageLimit: 1 };
const dynamic: TreeShape = { kind: "dynamic" };
const fixed20: TreeShape = { kind: "fixed", depth: 20 };

describe("engine isolation: leaf mapping + root divergence", () => {
  it("toLeaf maps the same commitment to DIFFERENT leaves per engine", () => {
    const commitment = "100";
    const sLeaf = semaphoreEngine.toLeaf(commitment, semaphoreParams);
    const rLeaf = rlnEngine.toLeaf(commitment, rlnParams);
    // Semaphore: leaf IS the commitment. RLN: leaf is poseidon2(ic, limit).
    expect(String(sLeaf)).toBe("100");
    expect(String(rLeaf)).not.toBe("100");
  });

  it("the two engines produce DIFFERENT roots for identical RAW leaves", async () => {
    // Identical raw decimal strings, branded for each engine. Even with the same
    // numbers in the tree, the dynamic LeanIMT (Semaphore) and the depth-20 v3
    // tree (RLN) hash differently, so the roots must diverge.
    const raw = ["1", "2", "3"];
    const sLeaves: Leaf[] = raw.map(asSemaphoreLeaf);
    const rLeaves: Leaf[] = raw.map(asRlnLeaf);

    const sRoot = await semaphoreEngine.computeRoot(sLeaves, dynamic, semaphoreParams);
    const rRoot = await rlnEngine.computeRoot(rLeaves, fixed20, rlnParams);

    expect(sRoot).not.toBe(rRoot);
  });

  it("a v4 leaf cannot be used where an RLN leaf is required (type-level brand)", () => {
    const v4: SemaphoreLeaf = asSemaphoreLeaf("100");

    function consumesRlnLeaves(_leaves: RlnLeaf[]): void {
      /* depth-20 RLN tree consumer */
    }

    // @ts-expect-error - a SemaphoreLeaf is NOT assignable to an RlnLeaf (control 3).
    consumesRlnLeaves([v4]);

    // The sanctioned crossing exists and typechecks:
    consumesRlnLeaves([asRlnLeaf("100")]);

    // Runtime sanity: the value is unchanged by branding.
    expect(String(v4)).toBe("100");
  });

  it("an RLN leaf cannot be used where a Semaphore leaf is required (type-level brand)", () => {
    const rln: RlnLeaf = asRlnLeaf("200");

    function consumesSemaphoreLeaves(_leaves: SemaphoreLeaf[]): void {
      /* dynamic Semaphore tree consumer */
    }

    // @ts-expect-error - an RlnLeaf is NOT assignable to a SemaphoreLeaf.
    consumesSemaphoreLeaves([rln]);

    consumesSemaphoreLeaves([asSemaphoreLeaf("200")]);
    expect(String(rln)).toBe("200");
  });

  it("the Semaphore engine rejects a fixed shape; the RLN engine rejects a dynamic shape", async () => {
    await expect(
      semaphoreEngine.computeRoot([asSemaphoreLeaf("1")], fixed20, semaphoreParams),
    ).rejects.toThrow(/dynamic/i);
    await expect(
      rlnEngine.computeRoot([asRlnLeaf("1")], dynamic, rlnParams),
    ).rejects.toThrow(/fixed/i);
  });
});
