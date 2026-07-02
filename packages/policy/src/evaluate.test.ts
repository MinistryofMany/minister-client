import { describe, it, expect } from 'vitest';
import { evaluate } from './evaluate.js';
import type { PolicyNode, VerifiedBadge } from './types.js';

const NOW = 1_750_000_000; // fixed unix seconds for deterministic expiry tests
const DAY = 86_400;

function badge(
  type: string,
  attributes: VerifiedBadge['attributes'] = {},
  ageDays = 0,
): VerifiedBadge {
  return { type, attributes, issuedAt: NOW - ageDays * DAY };
}

describe('evaluate', () => {
  it('matches a single badge leaf by type', () => {
    const policy: PolicyNode = { badge: { type: 'email-domain' } };
    expect(evaluate(policy, [badge('email-domain')], NOW)).toBe(true);
    expect(evaluate(policy, [badge('oauth-account')], NOW)).toBe(false);
  });

  it('enforces attribute constraints', () => {
    const policy: PolicyNode = { badge: { type: 'email-domain', where: { domain: 'acme.com' } } };
    expect(evaluate(policy, [badge('email-domain', { domain: 'acme.com' })], NOW)).toBe(true);
    expect(evaluate(policy, [badge('email-domain', { domain: 'evil.com' })], NOW)).toBe(false);
  });

  it('enforces maxAgeDays expiry', () => {
    const policy: PolicyNode = { badge: { type: 'age-check', maxAgeDays: 30 } };
    expect(evaluate(policy, [badge('age-check', {}, 10)], NOW)).toBe(true);
    expect(evaluate(policy, [badge('age-check', {}, 31)], NOW)).toBe(false);
  });

  it('allOf requires every child', () => {
    const policy: PolicyNode = {
      allOf: [
        { badge: { type: 'residency-country', where: { country: 'PT' } } },
        { badge: { type: 'email-domain', where: { domain: 'acme.com' } } },
      ],
    };
    expect(
      evaluate(
        policy,
        [
          badge('residency-country', { country: 'PT' }),
          badge('email-domain', { domain: 'acme.com' }),
        ],
        NOW,
      ),
    ).toBe(true);
    expect(evaluate(policy, [badge('residency-country', { country: 'PT' })], NOW)).toBe(false);
  });

  it('anyOf requires at least one child', () => {
    const policy: PolicyNode = { anyOf: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] };
    expect(evaluate(policy, [badge('b')], NOW)).toBe(true);
    expect(evaluate(policy, [badge('c')], NOW)).toBe(false);
  });

  it('atLeast requires n satisfied children', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }, { badge: { type: 'c' } }],
      },
    };
    expect(evaluate(policy, [badge('a'), badge('b')], NOW)).toBe(true);
    expect(evaluate(policy, [badge('a')], NOW)).toBe(false);
  });

  it('evaluates the personhood + topic example', () => {
    const policy: PolicyNode = {
      allOf: [
        {
          atLeast: {
            n: 2,
            of: [
              { badge: { type: 'oauth-account', where: { provider: 'github' } } },
              { badge: { type: 'oauth-account', where: { provider: 'google' } } },
              { badge: { type: 'oauth-account', where: { provider: 'steam' } } },
            ],
          },
        },
        { badge: { type: 'steam-game', where: { gameId: 'GAME_X', completed: true } } },
      ],
    };
    const ok = [
      badge('oauth-account', { provider: 'github' }),
      badge('oauth-account', { provider: 'steam' }),
      badge('steam-game', { gameId: 'GAME_X', completed: true }),
    ];
    expect(evaluate(policy, ok, NOW)).toBe(true);

    const missingTopic = [
      badge('oauth-account', { provider: 'github' }),
      badge('oauth-account', { provider: 'steam' }),
    ];
    expect(evaluate(policy, missingTopic, NOW)).toBe(false);
  });

  it('treats a badge issued exactly maxAgeDays ago as still valid (inclusive boundary)', () => {
    const policy: PolicyNode = { badge: { type: 'age-check', maxAgeDays: 30 } };
    expect(evaluate(policy, [badge('age-check', {}, 30)], NOW)).toBe(true);
  });

  it('rejects when a required attribute is absent from the badge', () => {
    const policy: PolicyNode = { badge: { type: 'email-domain', where: { domain: 'acme.com' } } };
    expect(evaluate(policy, [badge('email-domain', {})], NOW)).toBe(false);
  });

  it('uses strict equality: a boolean constraint does not match a string attribute', () => {
    const policy: PolicyNode = { badge: { type: 'steam-game', where: { completed: true } } };
    expect(evaluate(policy, [badge('steam-game', { completed: 'true' })], NOW)).toBe(false);
  });

  it('throws (fails closed) on unrecognized policy shapes', () => {
    // @ts-expect-error malformed shapes are not valid PolicyNode
    expect(() => evaluate({}, [], NOW)).toThrow();
    // @ts-expect-error
    expect(() => evaluate({ foo: 1 }, [], NOW)).toThrow();
    // @ts-expect-error
    expect(() => evaluate([], [], NOW)).toThrow();
  });

  it('documents degenerate-node behavior', () => {
    expect(evaluate({ allOf: [] }, [], NOW)).toBe(true);
    expect(evaluate({ anyOf: [] }, [], NOW)).toBe(false);
    expect(evaluate({ atLeast: { n: 0, of: [] } }, [], NOW)).toBe(true);
    expect(
      evaluate(
        { atLeast: { n: 5, of: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] } },
        [badge('a'), badge('b')],
        NOW,
      ),
    ).toBe(false);
  });
});

describe('atLeast counts DISTINCT satisfying badges (no double-count across branches)', () => {
  // Regression for the finding-#6 gate-weakening bug: `atLeast` used to count
  // satisfied *branches*, each evaluated against the full badge set, so ONE
  // badge could satisfy multiple overlapping branches and clear the threshold.
  // Correct semantics: n DISTINCT badges must be matched to n distinct branches.

  it('two identical branches are NOT both satisfied by a single badge', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [{ badge: { type: 'oauth-account' } }, { badge: { type: 'oauth-account' } }],
      },
    };
    // One oauth badge can fill only ONE of the two branches.
    expect(evaluate(policy, [badge('oauth-account', { provider: 'github' })], NOW)).toBe(false);
    // Two distinct oauth badges fill both.
    expect(
      evaluate(
        policy,
        [
          badge('oauth-account', { provider: 'github' }),
          badge('oauth-account', { provider: 'google' }),
        ],
        NOW,
      ),
    ).toBe(true);
  });

  it('overlapping specificity: {oauth} and {oauth where github} need two distinct badges', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [
          { badge: { type: 'oauth-account' } },
          { badge: { type: 'oauth-account', where: { provider: 'github' } } },
        ],
      },
    };
    // A single github oauth badge satisfies BOTH predicates but is ONE badge.
    expect(evaluate(policy, [badge('oauth-account', { provider: 'github' })], NOW)).toBe(false);
    // A github badge (fills the specific branch) + any other oauth badge (fills
    // the generic branch) => two distinct badges, threshold met.
    expect(
      evaluate(
        policy,
        [
          badge('oauth-account', { provider: 'github' }),
          badge('oauth-account', { provider: 'google' }),
        ],
        NOW,
      ),
    ).toBe(true);
    // Two github badges also work: one covers {github}, the other covers {oauth}.
    expect(
      evaluate(
        policy,
        [
          badge('oauth-account', { provider: 'github' }),
          badge('oauth-account', { provider: 'github' }),
        ],
        NOW,
      ),
    ).toBe(true);
  });

  it('still admits when a genuine matching of size n exists (three branches, n=2)', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [
          { badge: { type: 'oauth-account', where: { provider: 'github' } } },
          { badge: { type: 'oauth-account', where: { provider: 'google' } } },
          { badge: { type: 'oauth-account', where: { provider: 'steam' } } },
        ],
      },
    };
    expect(
      evaluate(
        policy,
        [
          badge('oauth-account', { provider: 'github' }),
          badge('oauth-account', { provider: 'steam' }),
        ],
        NOW,
      ),
    ).toBe(true);
  });

  it('nested anyOf branches: a single badge cannot fill two atLeast branches', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [
          { anyOf: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] },
          { badge: { type: 'a' } },
        ],
      },
    };
    // Only one `a` badge: the anyOf branch and the leaf branch both want it.
    expect(evaluate(policy, [badge('a')], NOW)).toBe(false);
    // `a` (fills the leaf) + `b` (fills the anyOf) => two distinct badges.
    expect(evaluate(policy, [badge('a'), badge('b')], NOW)).toBe(true);
    // Two `a` badges also satisfy both branches.
    expect(evaluate(policy, [badge('a'), badge('a')], NOW)).toBe(true);
  });

  it('nested allOf branch consumes multiple badges, disjoint from siblings', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [
          { allOf: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] },
          { badge: { type: 'c' } },
        ],
      },
    };
    // allOf branch needs {a,b}; leaf branch needs {c}. Disjoint => admit.
    expect(evaluate(policy, [badge('a'), badge('b'), badge('c')], NOW)).toBe(true);
    // Missing c: only the allOf branch is satisfiable => 1 branch < 2 => reject.
    expect(evaluate(policy, [badge('a'), badge('b')], NOW)).toBe(false);
  });

  it('two multi-badge allOf branches cannot share the same badges (sound under nesting)', () => {
    const policy: PolicyNode = {
      atLeast: {
        n: 2,
        of: [
          { allOf: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] },
          { allOf: [{ badge: { type: 'a' } }, { badge: { type: 'b' } }] },
        ],
      },
    };
    // Only one a and one b: at most ONE allOf branch can be satisfied.
    expect(evaluate(policy, [badge('a'), badge('b')], NOW)).toBe(false);
    // Two of each => both branches satisfiable disjointly.
    expect(
      evaluate(policy, [badge('a'), badge('b'), badge('a'), badge('b')], NOW),
    ).toBe(true);
  });

  it('within an allOf, one badge may satisfy overlapping children (reuse allowed inside a branch)', () => {
    // A single github-oauth badge satisfies both "is an oauth account" and "is a
    // github oauth account" INSIDE one allOf branch; the atLeast then counts that
    // branch as consuming a single badge.
    const policy: PolicyNode = {
      atLeast: {
        n: 1,
        of: [
          {
            allOf: [
              { badge: { type: 'oauth-account' } },
              { badge: { type: 'oauth-account', where: { provider: 'github' } } },
            ],
          },
        ],
      },
    };
    expect(evaluate(policy, [badge('oauth-account', { provider: 'github' })], NOW)).toBe(true);
  });

  it('property: distinct-branch matching never exceeds the number of distinct usable badges', () => {
    // For a flat atLeast of leaves that all match the same type, the number of
    // satisfiable branches can never exceed the number of held badges of that
    // type (each badge matches at most one branch in the matching).
    for (let held = 0; held <= 6; held++) {
      for (let branches = 1; branches <= 6; branches++) {
        for (let n = 1; n <= branches; n++) {
          const of: PolicyNode[] = Array.from({ length: branches }, () => ({
            badge: { type: 'oauth-account' },
          }));
          const badges: VerifiedBadge[] = Array.from({ length: held }, (_, i) =>
            badge('oauth-account', { provider: `p${i}` }),
          );
          const expected = Math.min(held, branches) >= n;
          expect(evaluate({ atLeast: { n, of } }, badges, NOW)).toBe(expected);
        }
      }
    }
  });
});

describe('general-path work bounding (complexity-DoS regression)', () => {
  // The general (subtree-branch) atLeast path enumerates subset-minimal
  // witness antichains, which are EXPONENTIAL in the disclosed-badge count in
  // the worst case: an allOf of k distinct-type leaves with c interchangeable
  // badges per type has c^k minimal witnesses, all inside the caller-side
  // policy shape caps (16 children). Before the fix, the un-ticked quadratic
  // scan in minimalMasks ran ~9.5 MINUTES on the 16-leaf / 48-badge input
  // below before the budget finally threw. The evaluator now charges every
  // unit of work (including minimalMasks) against EVAL_BUDGET, caps candidate
  // witness lists, and caps the disclosed-badge count - all fail closed.

  const BUDGET_ERROR = 'policy evaluation exceeded work budget';

  /** atLeast{n:1, of:[allOf: K distinct-type leaves]} - forces the general path. */
  function allOfUnderAtLeast(K: number): PolicyNode {
    return {
      atLeast: {
        n: 1,
        of: [{ allOf: Array.from({ length: K }, (_, i) => ({ badge: { type: `t${i}` } })) }],
      },
    };
  }

  /** `perType` interchangeable badges for each of `types` distinct types. */
  function wallet(types: number, perType: number): VerifiedBadge[] {
    const out: VerifiedBadge[] = [];
    for (let i = 0; i < types; i++) {
      for (let p = 0; p < perType; p++) out.push(badge(`t${i}`, { provider: `p${p}` }));
    }
    return out;
  }

  it('pathological cross-product input fails closed in bounded time (was ~9.5 min)', () => {
    // 16 leaves x 3 badges per type = 48 badges => 3^16 ≈ 43M minimal
    // witnesses. Must throw the budget error long before pegging a core.
    const start = performance.now();
    expect(() => evaluate(allOfUnderAtLeast(16), wallet(16, 3), NOW)).toThrow(BUDGET_ERROR);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('the same large policy with a legitimate wallet (one badge per type) still admits', () => {
    // Identical 16-leaf policy; without badge multiplicity the witness list
    // stays at one mask per level. The guards must key on combinatorial
    // blowup, not on policy size.
    const start = performance.now();
    expect(evaluate(allOfUnderAtLeast(16), wallet(16, 1), NOW)).toBe(true);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('missing one required type still correctly denies (fail-closed guard is not the only deny)', () => {
    expect(evaluate(allOfUnderAtLeast(16), wallet(15, 1), NOW)).toBe(false);
  });

  it('moderate badge multiplicity under a big allOf still admits (9 leaves x 3 per type)', () => {
    // 3^9 = 19,683 equal-popcount witnesses - a chunky-but-terminating input
    // just under the witness-list cap. Must still return the exact admit.
    const start = performance.now();
    expect(evaluate(allOfUnderAtLeast(9), wallet(9, 3), NOW)).toBe(true);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('largest legitimate atLeast antichain (C(16,8) = 12,870) still admits within budget', () => {
    // n=8 over 16 single-witness SUBTREE branches (anyOf-wrapped to force the
    // general path) with one badge per type: every minimal packing is a
    // distinct witness, so the antichain hits the caller-validated maximum.
    // This admitted before the fix (~630ms) and must keep admitting.
    const policy: PolicyNode = {
      atLeast: {
        n: 8,
        of: Array.from({ length: 16 }, (_, i) => ({
          anyOf: [{ badge: { type: `t${i}` } }] as PolicyNode[],
        })),
      },
    };
    const start = performance.now();
    expect(evaluate(policy, wallet(16, 1), NOW)).toBe(true);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('caps the disclosed-badge count on the general path (fail closed)', () => {
    const policy: PolicyNode = {
      atLeast: { n: 1, of: [{ anyOf: [{ badge: { type: 't0' } }] }] },
    };
    // 513 badges of one type exceeds MAX_GENERAL_PATH_BADGES = 512.
    expect(() => evaluate(policy, wallet(1, 513), NOW)).toThrow(BUDGET_ERROR);
    // The leaf-only fast path stays uncapped: same width, flat leaves.
    expect(
      evaluate({ atLeast: { n: 1, of: [{ badge: { type: 't0' } }] } }, wallet(1, 513), NOW),
    ).toBe(true);
  });
});
