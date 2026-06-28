export type PolicyAttrValue = string | number | boolean;

export interface BadgeLeaf {
  badge: {
    type: string;
    where?: Record<string, PolicyAttrValue>;
    /** Badge must have been issued within this many days of `now`. */
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
  /** VC `iat`, unix seconds. */
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
