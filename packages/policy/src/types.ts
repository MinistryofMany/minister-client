export type PolicyAttrValue = string | number | boolean;

export interface BadgeLeaf {
  badge: {
    type: string;
    where?: Record<string, PolicyAttrValue>;
    /**
     * Badge must have been issued within this many days of `now`. Evaluated
     * against the badge's `issuedAt` (see `VerifiedBadge.issuedAt`): Minister
     * discloses issuance at MONTH granularity, so this gate is month-granular
     * in practice — express windows in months (30/62/93/...); a sub-month
     * window over-rejects fresh badges issued before the current month (the
     * fail-closed direction) and can never under-reject.
     */
    maxAgeDays?: number;
  };
}

export interface AllOfNode {
  allOf: PolicyNode[];
}

export interface AnyOfNode {
  anyOf: PolicyNode[];
}

export interface AtLeastNode {
  atLeast: { n: number; of: PolicyNode[] };
}

export type PolicyNode = BadgeLeaf | AllOfNode | AnyOfNode | AtLeastNode;

/** A badge the user disclosed, after its VC signature was verified. */
export interface VerifiedBadge {
  type: string;
  attributes: Record<string, PolicyAttrValue>;
  /**
   * Representative issuance instant, unix seconds — the START of the badge's
   * coarse issuance bucket, NOT the VC `iat`. Minister discloses issuance
   * only as a UTC calendar month (`credentialSubject.issuanceMonth`; every
   * finer issuance timestamp is a cross-RP correlator and was removed by
   * MIN-1 — the VC `iat` is the DISCLOSURE instant and must never feed this
   * field). Verifiers (e.g. @ministryofmany/minister-verify) map the month to
   * its first UTC second, so `now - issuedAt` over-estimates age by up to one
   * month: `maxAgeDays` can over-reject a fresh badge (fail-closed) but never
   * admit a stale one. 0 = no issuance evidence (legacy Minister) ⇒ every
   * `maxAgeDays` leaf fails.
   */
  issuedAt: number;
}

export function isBadgeLeaf(node: PolicyNode): node is BadgeLeaf {
  return 'badge' in node;
}

export function isAllOf(node: PolicyNode): node is AllOfNode {
  return 'allOf' in node;
}

export function isAnyOf(node: PolicyNode): node is AnyOfNode {
  return 'anyOf' in node;
}

export function isAtLeast(node: PolicyNode): node is AtLeastNode {
  return 'atLeast' in node;
}
