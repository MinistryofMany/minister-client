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
