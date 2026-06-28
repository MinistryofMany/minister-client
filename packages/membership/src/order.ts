// Deterministic ordering of eligible leaves (control 4: ORDERKEYS).
//
// FreedInk's snapshot root is a PURE FUNCTION of a specific sort, and the client
// is forbidden to re-sort (verified). If the package's comparator does not
// EXACTLY reproduce FreedInk's tiebreak chain, roots drift and every stored
// FreedInk snapshot becomes unverifiable. So the comparator is byte-specified:
//
//   - a numeric key (a `number`, e.g. a millisecond timestamp) compares by
//     subtraction (a.key - b.key), matching FreedInk's
//     `a.userCreatedAt.getTime() - b.userCreatedAt.getTime()` and
//     `a.deviceCreatedAt.getTime() - b.deviceCreatedAt.getTime()`.
//   - a string key (a `string`, e.g. a user id or the commitment) compares by
//     `String.prototype.localeCompare`, matching FreedInk's
//     `a.userId.localeCompare(b.userId)` and `a.idc.localeCompare(b.idc)`.
//
// FreedInk's verified key chain is therefore expressed as
//   orderKeys = [userCreatedAtMs (number), userId (string),
//                deviceCreatedAtMs (number), idc (string)]
// and this comparator reproduces its exact result, including the localeCompare
// string tiebreak. A drifted comparator silently invalidates every stored
// FreedInk snapshot, so this file is a tripwire (see order.test.ts + the ported
// FreedInk root-determinism test).

import type { EligibleLeaf } from "./provider.js";

/**
 * Compare two ordering-key values. The key TYPE selects the comparison:
 * `number` -> numeric (subtraction), `string` -> localeCompare. A type mismatch
 * between the two sides at the same position is a provider bug (the key schema
 * must be consistent across rows); we throw rather than silently coerce, because
 * a silent coercion is exactly the drift this control exists to prevent.
 *
 * COLLATION DEPENDENCY: the string branch relies on `localeCompare` producing a
 * STABLE ordering across both the producer (the env that froze the snapshot) and
 * the verifier env. FreedInk's keys are ASCII ids/commitments, for which the
 * default-locale collation is identical everywhere, so this is a latent rather
 * than active concern; but a future locale-sensitive key (non-ASCII) could in
 * principle order differently under a different ICU/locale and drift the root.
 * No behavior change here - this is a tripwire note for whoever adds such a key.
 */
function compareKey(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") {
    // Numeric (ms timestamps): exact subtraction, matching FreedInk's getTime().
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (typeof a === "string" && typeof b === "string") {
    // String ids / commitments: localeCompare, matching FreedInk verbatim.
    return a.localeCompare(b);
  }
  throw new Error(
    `orderKeys type mismatch: comparing ${typeof a} with ${typeof b}; ` +
      `a provider must return the same key schema for every row.`,
  );
}

/**
 * Compare two eligible leaves by their `orderKeys` in order. Shorter key arrays
 * sort before longer ones when they share a prefix (a provider should return a
 * uniform key length, so this is only a defensive total-order tiebreak). Leaves
 * WITHOUT `orderKeys` are treated as equal to one another and are left in the
 * provider's return order by the stable sort in `orderLeaves`.
 */
function compareLeaves(a: EligibleLeaf, b: EligibleLeaf): number {
  const ak = a.orderKeys;
  const bk = b.orderKeys;
  if (!ak || !bk) return 0;
  const n = Math.min(ak.length, bk.length);
  for (let i = 0; i < n; i++) {
    const c = compareKey(ak[i]!, bk[i]!);
    if (c !== 0) return c;
  }
  return ak.length - bk.length;
}

/**
 * Return the eligible leaves in deterministic order.
 *
 * If NO leaf carries `orderKeys` (Discreetly's case), the provider's return
 * order is preserved verbatim - the package never imposes an order the provider
 * did not ask for. If leaves DO carry `orderKeys` (FreedInk/Deforum), they are
 * sorted by the byte-specified comparator above.
 *
 * The sort is STABLE: `Array.prototype.sort` is guaranteed stable in ES2019+, so
 * ties (or no keys at all) preserve the input order, which is the contract
 * Discreetly relies on. The input array is not mutated.
 */
export function orderLeaves(leaves: readonly EligibleLeaf[]): EligibleLeaf[] {
  const anyKeys = leaves.some((l) => l.orderKeys !== undefined);
  const copy = leaves.slice();
  if (!anyKeys) return copy;
  return copy.sort(compareLeaves);
}
