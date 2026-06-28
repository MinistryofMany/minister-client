import { describe, it, expect } from 'vitest';
import { parsePolicy, policyNodeSchema, OPEN_POLICY } from './schema.js';
import { evaluate } from './evaluate.js';
import type { VerifiedBadge } from './types.js';

describe('policyNodeSchema / parsePolicy', () => {
  it('accepts a bare badge leaf', () => {
    const node = parsePolicy({ badge: { type: 'verified-human' } });
    expect(node).toEqual({ badge: { type: 'verified-human' } });
  });

  it('accepts a badge leaf with where + maxAgeDays', () => {
    const input = {
      badge: { type: 'kyc', where: { country: 'US', tier: 2, vip: true }, maxAgeDays: 30 },
    };
    expect(parsePolicy(input)).toEqual(input);
  });

  it('accepts nested allOf / anyOf / atLeast', () => {
    const input = {
      allOf: [
        { badge: { type: 'a' } },
        { anyOf: [{ badge: { type: 'b' } }, { badge: { type: 'c' } }] },
        { atLeast: { n: 1, of: [{ badge: { type: 'd' } }] } },
      ],
    };
    expect(parsePolicy(input)).toEqual(input);
  });

  it('accepts OPEN_POLICY (empty allOf)', () => {
    expect(parsePolicy(OPEN_POLICY)).toEqual({ allOf: [] });
    expect(OPEN_POLICY).toEqual({ allOf: [] });
  });

  it('accepts empty anyOf and empty atLeast.of', () => {
    expect(() => parsePolicy({ anyOf: [] })).not.toThrow();
    expect(() => parsePolicy({ atLeast: { n: 0, of: [] } })).not.toThrow();
  });

  it('rejects a bare {} (not a valid policy)', () => {
    expect(() => parsePolicy({})).toThrow();
  });

  it('rejects an unknown key on a node', () => {
    expect(() => parsePolicy({ allOf: [], foo: 1 })).toThrow();
  });

  it('rejects an unknown key inside a badge', () => {
    expect(() => parsePolicy({ badge: { type: 'a', extra: 1 } })).toThrow();
  });

  it('rejects a wrong attr value type', () => {
    expect(() => parsePolicy({ badge: { type: 'a', where: { x: { nested: 1 } } } })).toThrow();
  });

  it('rejects a non-positive maxAgeDays', () => {
    expect(() => parsePolicy({ badge: { type: 'a', maxAgeDays: -1 } })).toThrow();
    expect(() => parsePolicy({ badge: { type: 'a', maxAgeDays: 0 } })).toThrow();
  });

  it('rejects an empty badge type', () => {
    expect(() => parsePolicy({ badge: { type: '' } })).toThrow();
  });

  it('rejects a non-integer atLeast.n and a negative n', () => {
    expect(() => parsePolicy({ atLeast: { n: 1.5, of: [] } })).toThrow();
    expect(() => parsePolicy({ atLeast: { n: -1, of: [] } })).toThrow();
  });

  it('produces output evaluate() accepts', () => {
    const node = parsePolicy({
      anyOf: [{ badge: { type: 'verified-human' } }, { badge: { type: 'kyc' } }],
    });
    const badges: VerifiedBadge[] = [{ type: 'kyc', attributes: {}, issuedAt: 0 }];
    expect(evaluate(node, badges, 0)).toBe(true);
    expect(evaluate(node, [], 0)).toBe(false);
  });

  it('OPEN_POLICY evaluates true for anyone', () => {
    expect(evaluate(OPEN_POLICY, [], 0)).toBe(true);
  });

  it('policyNodeSchema.safeParse reports failure without throwing', () => {
    expect(policyNodeSchema.safeParse({}).success).toBe(false);
    expect(policyNodeSchema.safeParse({ allOf: [] }).success).toBe(true);
  });
});
