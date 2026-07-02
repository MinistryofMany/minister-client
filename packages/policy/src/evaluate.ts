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
//    atLeast search then packs n branches with disjoint witnesses. Worst case
//    is EXPONENTIAL in the disclosed-badge count M, not just in the policy
//    shape: an `allOf` of k leaves with c interchangeable badges per leaf has
//    c^k minimal witnesses, so caller breadth/depth validation (Minister's
//    `policyBoundsViolation`: MAX_NODE_CHILDREN 16, MAX_ATLEAST_N 16,
//    MAX_POLICY_NODES 64, MAX_POLICY_DEPTH 8; Discreetly mirrors it) does NOT
//    bound the work - 16 leaves x 3 badges each is 3^16 witnesses inside those
//    caps. The path is instead bounded by hard fail-closed guards, all of which
//    throw (=> deny): every unit of work - node visits, badge scans, candidate-
//    mask pushes, and each popcount/subset step inside `minimalMasks` - is
//    charged against EVAL_BUDGET; candidate witness lists are capped at
//    MAX_WITNESS_MASKS; and the disclosed-badge count is capped at
//    MAX_GENERAL_PATH_BADGES (which also bounds the bigint mask width, keeping
//    each charged op O(1)). Real policies have tiny witness antichains and
//    never approach the guards.
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

const EVAL_BUDGET = 10_000_000;

/**
 * Hard cap on any candidate witness-mask list in the general path. The largest
 * antichain a policy inside the caller-validated shape caps can legitimately
 * need is C(16, 8) = 12,870 (an atLeast n=8 over 16 single-witness subtree
 * branches); 32,768 leaves ~2.5x headroom while bounding memory and cutting
 * off cross-product explosions (c^k witness growth) early.
 */
const MAX_WITNESS_MASKS = 32_768;

/**
 * Disclosed-badge cap for the general path only (the leaf fast path is
 * polynomial in M and uncapped). Bounds the bigint mask width so every charged
 * operation is O(1), which is what makes EVAL_BUDGET a wall-time bound.
 * Generous: Minister minimizes disclosures to a minimal satisfying set, so
 * real inputs are dozens at most.
 */
const MAX_GENERAL_PATH_BADGES = 512;

const BUDGET_ERROR = 'policy evaluation exceeded work budget';

/**
 * Charge `ops` units of work against the evaluation budget. Fail closed: a
 * pathological input must never hang the event loop or silently admit. This
 * guarantee holds only because EVERY hot loop in the general path charges its
 * work here - including the subset scans inside `minimalMasks`, which are
 * quadratic in candidate-list length and were the un-ticked core of the
 * complexity-DoS finding.
 */
function charge(ctx: EvalCtx, ops: number): void {
  ctx.ops += ops;
  if (ctx.ops > EVAL_BUDGET) {
    throw new Error(BUDGET_ERROR);
  }
}

function tick(ctx: EvalCtx): void {
  charge(ctx, 1);
}

/** Budget-charged push that also caps candidate-list growth (fail closed). */
function pushMask(list: bigint[], mask: bigint, ctx: EvalCtx): void {
  tick(ctx);
  if (list.length >= MAX_WITNESS_MASKS) {
    throw new Error(BUDGET_ERROR);
  }
  list.push(mask);
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
    charge(ctx, ctx.badges.length); // the scan below is O(M) per leaf visit
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
    // This cross product is the exponential core: c witnesses per child grows
    // `next` toward c^k, so growth is both charged and capped via pushMask.
    let combos: bigint[] = [0n];
    for (const child of node.allOf) {
      const childWitnesses = witnessMasks(child, avail, ctx);
      if (childWitnesses.length === 0) return []; // a required child cannot be met
      const next: bigint[] = [];
      for (const partial of combos) {
        for (const w of childWitnesses) {
          pushMask(next, partial | w, ctx);
        }
      }
      combos = minimalMasks(next, ctx);
    }
    return combos;
  }
  if (isAnyOf(node)) {
    const out: bigint[] = [];
    for (const child of node.anyOf) {
      for (const w of witnessMasks(child, avail, ctx)) pushMask(out, w, ctx);
    }
    return minimalMasks(out, ctx);
  }
  if (isAtLeast(node)) {
    return atLeastWitnessMasks(node.atLeast.of, 0, node.atLeast.n, avail, ctx);
  }
  const _exhaustive: never = node;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}

/**
 * Minimal union masks that satisfy at least `n` of `branches[start..]` with
 * pairwise-disjoint witnesses. Empty array means fewer than `n` branches can
 * be packed. Recurses on `start` rather than slicing so each level does O(1)
 * work outside the charged calls (a `[first, ...rest]` spread here would be an
 * un-charged O(B) copy per level).
 */
function atLeastWitnessMasks(
  branches: PolicyNode[],
  start: number,
  n: number,
  avail: bigint,
  ctx: EvalCtx,
): bigint[] {
  if (n <= 0) return [0n]; // satisfied with no further consumption
  if (branches.length - start < n) return []; // not enough branches left to reach n
  tick(ctx);
  const first = branches[start]!;
  const out: bigint[] = [];
  // Option A: skip `first`, pack all n from the rest.
  for (const u of atLeastWitnessMasks(branches, start + 1, n, avail, ctx)) {
    pushMask(out, u, ctx);
  }
  // Option B: satisfy `first` with a disjoint witness, then pack n-1 from the
  // rest using only the badges `first` did not consume.
  for (const w of witnessMasks(first, avail, ctx)) {
    for (const u of atLeastWitnessMasks(branches, start + 1, n - 1, avail & ~w, ctx)) {
      pushMask(out, w | u, ctx);
    }
  }
  return minimalMasks(out, ctx);
}

/**
 * Dedupe, then drop any mask that is a strict superset of another (keep the
 * subset-minimal antichain). All work is charged against the budget - this
 * scan is worst-case quadratic in the list length, and the list itself can be
 * exponential in the badge count, so un-charged it was the DoS hot loop.
 *
 * Masks are bucketed by popcount, ascending. A strict subset always has a
 * strictly smaller popcount (equal popcount + subset => equal, removed by the
 * dedupe), and every dominated mask has a subset-MINIMAL strict subset
 * (induction on popcount: a minimal-popcount strict subset present in the list
 * cannot itself be dominated). So `m` is dominated iff a KEPT mask of smaller
 * popcount is a subset of `m` - each mask is compared only against those. For
 * the equal-popcount antichains that big-but-legitimate policies produce
 * (e.g. atLeast n=8 over 16 single-witness branches: C(16,8) masks, all
 * popcount 8) this does zero subset comparisons; the output SET is identical
 * to a full pairwise scan, only its order differs, and callers consume it as
 * a set.
 */
function minimalMasks(masks: bigint[], ctx: EvalCtx): bigint[] {
  const uniq = Array.from(new Set(masks));
  const byPopcount = new Map<number, bigint[]>();
  for (const m of uniq) {
    let bits = 0;
    for (let x = m; x !== 0n; x &= x - 1n) bits++;
    charge(ctx, 1 + bits);
    const bucket = byPopcount.get(bits);
    if (bucket) bucket.push(m);
    else byPopcount.set(bits, [m]);
  }
  const out: bigint[] = [];
  const popcounts = Array.from(byPopcount.keys()).sort((a, b) => a - b);
  for (const bits of popcounts) {
    const lowerEnd = out.length; // out[0..lowerEnd) = kept masks of smaller popcount
    for (const m of byPopcount.get(bits)!) {
      charge(ctx, 1 + lowerEnd); // subset scan, charged up front
      let dominated = false;
      for (let i = 0; i < lowerEnd; i++) {
        const other = out[i]!;
        if ((m & other) === other) {
          dominated = true;
          break;
        }
      }
      if (!dominated) out.push(m);
    }
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
    // Cap M here (fail closed) so the bigint masks stay narrow and every
    // budget-charged operation below is O(1); see MAX_GENERAL_PATH_BADGES.
    if (badges.length > MAX_GENERAL_PATH_BADGES) {
      throw new Error(BUDGET_ERROR);
    }
    const ctx: EvalCtx = { badges, now, ops: 0 };
    const full = badges.length === 0 ? 0n : (1n << BigInt(badges.length)) - 1n;
    return atLeastWitnessMasks(of, 0, n, full, ctx).length > 0;
  }
  // Exhaustiveness (compile-time) + fail-closed (runtime): a new PolicyNode
  // variant fails to compile here; a malformed/unrecognized runtime shape throws
  // so callers can never mistake a non-boolean for an admit.
  const _exhaustive: never = policy;
  throw new Error(`unknown policy node shape: ${JSON.stringify(_exhaustive)}`);
}
