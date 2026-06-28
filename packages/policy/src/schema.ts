import { z } from 'zod';
import type { PolicyNode } from './types.js';

const attrValue = z.union([z.string(), z.number(), z.boolean()]);

const badgeLeaf = z
  .object({
    badge: z
      .object({
        type: z.string().min(1),
        where: z.record(attrValue).optional(),
        maxAgeDays: z.number().positive().optional(),
      })
      .strict(),
  })
  .strict();

/**
 * Recursive zod schema mirroring `PolicyNode`. Each object is `.strict()` so
 * unknown keys are rejected. Empty `allOf`/`anyOf`/`atLeast.of` arrays are valid
 * and meaningful (`{ allOf: [] }` is admit-all, `{ anyOf: [] }` is admit-none).
 */
export const policyNodeSchema: z.ZodType<PolicyNode> = z.lazy(() =>
  z.union([
    badgeLeaf,
    z.object({ allOf: z.array(policyNodeSchema) }).strict(),
    z.object({ anyOf: z.array(policyNodeSchema) }).strict(),
    z
      .object({
        atLeast: z
          .object({ n: z.number().int().nonnegative(), of: z.array(policyNodeSchema) })
          .strict(),
      })
      .strict(),
  ]),
);

/** Parse + validate untrusted JSON into a PolicyNode; throws ZodError on invalid input. */
export function parsePolicy(input: unknown): PolicyNode {
  return policyNodeSchema.parse(input);
}

/** The admit-all policy (open room): allOf of zero predicates evaluates true. */
export const OPEN_POLICY: PolicyNode = { allOf: [] };
