import { describe, it, expect } from 'vitest';
import { requiredScopes } from './required-scopes.js';
import type { PolicyNode } from './types.js';

describe('requiredScopes', () => {
  it('returns a single scope for a single badge leaf', () => {
    const policy: PolicyNode = { badge: { type: 'email-domain', where: { domain: 'acme.com' } } };
    expect(requiredScopes(policy)).toEqual(['badge:email-domain']);
  });

  it('collects and dedupes badge types across a nested tree, sorted', () => {
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
        { badge: { type: 'steam-game', where: { gameId: 'GAME_X' } } },
      ],
    };
    expect(requiredScopes(policy)).toEqual(['badge:oauth-account', 'badge:steam-game']);
  });

  it('handles anyOf', () => {
    const policy: PolicyNode = {
      anyOf: [{ badge: { type: 'residency-country' } }, { badge: { type: 'email-domain' } }],
    };
    expect(requiredScopes(policy)).toEqual(['badge:email-domain', 'badge:residency-country']);
  });
});
