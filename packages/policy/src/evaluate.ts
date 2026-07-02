import {
  type PolicyNode,
  type VerifiedBadge,
  type BadgeLeaf,
  isBadgeLeaf,
  isAllOf,
  isAnyOf,
  isAtLeast,
} from './types.js';

const SECONDS_PER_DAY = 86_400;

function badgeSatisfiesLeaf(leaf: BadgeLeaf, candidate: VerifiedBadge, now: number): boolean {
  const { type, where, maxAgeDays } = leaf.badge;
  if (candidate.type !== type) return false;
  if (maxAgeDays !== undefined && now - candidate.issuedAt > maxAgeDays * SECONDS_PER_DAY) {
    return false;
  }
  if (where) {
    for (const [key, value] of Object.entries(where)) {
      if (candidate.attributes[key] !== value) return false;
    }
  }
  return true;
}

function leafSatisfied(leaf: BadgeLeaf, badges: VerifiedBadge[], now: number): boolean {
  return badges.some((candidate) => badgeSatisfiesLeaf(leaf, candidate, now));
}

// ---------------------------------------------------------------------------
// atLeast: distinct-badge matching
// ---------------------------------------------------------------------------
//
// `atLeast{ n, of: [...] }` is satisfied iff at least `n` of its branches can
// be satisfied SIMULTANEOUSLY using pairwise-DISJOINT badges: a badge spent to
// satisfy one branch cannot be reused by a sibling. Counting satisfied branches
// against the full badge set (the old behavior) let one badge clear multiple
// overlapping branches and weaken the gate (audit finding #6). Reuse is still
// allowed WITHIN a branch (an `allOf` child may be met by a single badge that
// happens to satisfy two of its own leaves) - the disjointness constraint binds
// only across the siblings of an `atLeast`.
//
// Two code paths, identical in semantics:
//
//  * Fast path (every branch is a leaf - the common case, and the exact shape of
//    the reported bug): maximum bipartite matching between branches and badges
//    via Kuhn's augmenting-path algorithm. A matching of size >= n means n
//    distinct badges cover n distinct branches. O(B * E) = O(B^2 * M) where
//    B = branch count (<= MAX_NODE_CHILDREN = 16) and M = disclosed badge count;
//    polynomial and unconditionally bounded.
//
//  * General path (a branch is itself a subtree that consumes >= 1 badge):
//    exact subset-minimal disjoint-witness search. Each node reports the
//    antichain of MINIMAL badge sets that satisfy it (`witnessMasks`); the
//    atLeast search then packs n branches with disjoint witnesses. Worst case is
//    exponential in the subtree, so it is bounded two ways: (a) callers validate
//    breadth/depth first (Minister's `policyBoundsViolation`: MAX_NODE_CHILDREN
//    16, MAX_ATLEAST_N 16, MAX_POLICY_NODES 64, MAX_POLICY_DEPTH 8; Discreetly
//    mirrors it), and (b) an internal operation budget (`EVAL_BUDGET`) that
//    throws - i.e. fails closed - on pathological unbounded input. Minimal-
//    witness filtering keeps the working set to the antichain, which for real
//    policies is tiny.
//
// The Minister-side mirror (`apps/minister/src/lib/oidc-policy.ts`) MUST keep
// these semantics byte-for-behavior identical (drift-checked); the matching
// operates on badge indices, so it is independent of the badge value type.

/** Maximum bipartite matching size between leaf branches and badges. */
function maxLeafMatching(leaves: BadgeLeaf[], badges: VerifiedBadge[], now: number): number {
  // adj[i] = badge indices that satisfy leaf branch i.
  const adj: number[][] = leaves.map((leaf) => {
    const edges: number[] = [];
    for (let j = 0; j < badges.length; j++) {
      if (badgeSatisfiesLeaf(leaf, badges[j]!, now)) edges.push(j);
    }
    return edges;
  });

  // badgeOwner[j] = leaf index currently matched to badge j, or -1.
  const badgeOwner = new Array<number>(badges.length).fill(-1);

  const augment = (leafIdx: number, seen: boolean[]): boolean => {
    for (const j of adj[leafIdx]!) {
      if (seen[j]) continue;
      seen[j] = true;
      const owner = badgeOwner[j]!;
      if (owner === -1 || augment(owner, seen)) {
        badgeOwner[j] = leafIdx;
        return true;
      }
    }
    return false;
  };

  let matched = 0;
  for (let i = 0; i < leaves.length; i++) {
    if (augment(i, new Array<boolean>(badges.length).fill(false))) matched++;
  }
  return matched;
}

// Bit `j` of a mask denotes badge index `j`. bigint keeps the algorithm correct
// for any number of disclosed badges (no 31/32-bit ceiling).
interface EvalCtx {
  badges: VerifiedBadge[];
  now: number;
  ops: number;
}

const EVAL_BUDGET = 2_000_000;

function tick(ctx: EvalCtx): void {
  if (++ctx.ops > EVAL_BUDGET) {
    // Fail closed: an unbounded/pathological policy that a caller failed to
    // breadth-cap must never hang the event loop or silently admit.
    throw new Error('policy evaluation exceeded work budget');
  }
}

/**
 * All subset-minimal badge witness masks that satisfy `node` using only badges
 * whose bit is set in `avail`. An empty array means the node is unsatisfiable
 * within `avail`. `[0n]` means it is satisfiable consuming no badges (a
 * degenerate `allOf:[]` / `atLeast{n:0}`).
 */
function witnessMasks(node: PolicyNode, avail: bigint, ctx: EvalCtx): bigint[] {
  tick(ctx);
  if (isBadgeLeaf(node)) {
    const out: bigint[] = [];
    for (let j = 0; j < ctx.badges.length; j++) {
      const bit = 1n << BigInt(j);
      if ((avail & bit) !== 0n && badgeSatisfiesLeaf(node, ctx.badges[j]!, ctx.now)) {
        out.push(bit); // singletons are already minimal
      }
    }
    return out;
  }
  if (isAllOf(node)) {
    // Every child must hold; a witness is the union of one witness per child
    // (reuse within the allOf lets those unions coincide on shared badges).
    let combos: bigint[] = [0n];
    for (const child of node.allOf) {
      const childWitnesses = witnessMasks(child, avail, ctx);
      if (childWitnesses.length === 0) return []; // a required child cannot be met
      const next: bigint[] = [];
      for (const partial of combos) {
        for (const w of childWitnesses) {
          tick(ctx);
          next.push(partial | w);
        }
      }
      combos = minimalMasks(next);
    }
    return combos;
  }
  if (isAnyOf(node)) {
    const out: bigint[] = [];
    for (const child of node.anyOf) {
      for (const w of witnessMasks(child, avail, ctx)) out.push(w);
    }
    return minimalMasks(out);
  }
  if (isAtLeast(node)) {
    return atLeastWitnessMasks(node.atLeast.of, node.atLeast.n, avail, ctx);
  }
  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

/**
 * Minimal union masks that satisfy at least `n` of `branches` with pairwise-
 * disjoint witnesses. Empty array means fewer than `n` branches can be packed.
 */
function atLeastWitnessMasks(
  branches: PolicyNode[],
  n: number,
  avail: bigint,
  ctx: EvalCtx,
): bigint[] {
  if (n <= 0) return [0n]; // satisfied with no further consumption
  if (branches.length < n) return []; // not enough branches left to reach n
  tick(ctx);
  const [first, ...rest] = branches;
  const out: bigint[] = [];
  // Option A: skip `first`, pack all n from the rest.
  for (const u of atLeastWitnessMasks(rest, n, avail, ctx)) out.push(u);
  // Option B: satisfy `first` with a disjoint witness, then pack n-1 from the
  // rest using only the badges `first` did not consume.
  for (const w of witnessMasks(first!, avail, ctx)) {
    tick(ctx);
    for (const u of atLeastWitnessMasks(rest, n - 1, avail & ~w, ctx)) {
      out.push(w | u);
    }
  }
  return minimalMasks(out);
}

/** Dedupe, then drop any mask that is a strict superset of another. */
function minimalMasks(masks: bigint[]): bigint[] {
  const uniq = Array.from(new Set(masks));
  const out: bigint[] = [];
  for (const m of uniq) {
    let dominated = false;
    for (const other of uniq) {
      // `other` (a distinct value) is a subset of `m` => `m` is dominated.
      if (other !== m && (m & other) === other) {
        dominated = true;
        break;
      }
    }
    if (!dominated) out.push(m);
  }
  return out;
}

/**
 * Evaluate a room access policy against the set of verified, disclosed badges.
 * `now` is unix seconds, passed in for deterministic testing.
 */
export function evaluate(policy: PolicyNode, badges: VerifiedBadge[], now: number): boolean {
  if (isBadgeLeaf(policy)) return leafSatisfied(policy, badges, now);
  if (isAllOf(policy)) return policy.allOf.every((node) => evaluate(node, badges, now));
  if (isAnyOf(policy)) return policy.anyOf.some((node) => evaluate(node, badges, now));
  if (isAtLeast(policy)) {
    const { n, of } = policy.atLeast;
    if (n <= 0) return true;
    if (of.length < n) return false;
    const leaves = of.filter(isBadgeLeaf);
    if (leaves.length === of.length) {
      // Fast path: every branch is a leaf -> exact maximum bipartite matching.
      return maxLeafMatching(leaves, badges, now) >= n;
    }
    // General path: at least one branch is a subtree that consumes badges.
    const ctx: EvalCtx = { badges, now, ops: 0 };
    const full = badges.length === 0 ? 0n : (1n << BigInt(badges.length)) - 1n;
    return atLeastWitnessMasks(of, n, full, ctx).length > 0;
  }
  // Exhaustiveness (compile-time) + fail-closed (runtime): a new PolicyNode
  // variant fails to compile here; a malformed/unrecognized runtime shape throws
  // so callers can never mistake a non-boolean for an admit.
  const _exhaustive: never = policy;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}
