// Shared wire + scheme types for @minister/blind-token. Isomorphic: safe to
// import from the client or the server entry. These are the generalization of
// FreedInk's vote-token wire surface (verified against
// src/lib/client/vote-token.ts + src/lib/server/vote-token.ts).

// The suite is fixed by the scheme (RFC 9474 + the public-metadata extension,
// draft-amjad-cfrg-partially-blind-rsa). Exposed as a constant so a consumer can
// assert agreement, but NEVER parameterized - changing it breaks the wire scheme
// and every existing token / Signet interop. Matches FreedInk's
// RSAPBSSA.SHA384.PSS.Randomized().
export const SUITE_NAME = "RSAPBSSA.SHA384.PSS.Randomized" as const;
export type SuiteName = typeof SUITE_NAME;

// Public-metadata identity for an action. `infoPrefix` is the app-wide constant
// namespace ("freedink-vote", "deforum-ban"); `actionKey` is the per-action
// variable part (post-version id, ban-round id). The bytes signed are
// `<infoPrefix>:<actionKey>` UTF-8 - byte-identical to FreedInk's versionInfo().
export interface ActionInfo {
  readonly infoPrefix: string; // e.g. "freedink-vote" (no colon)
  readonly actionKey: string; // e.g. a post-version id, or a ban-round id
}

// The material a redeemed token carries. base64url throughout (FreedInk's wire
// format). `signature` is the unblinded RSA-PSS signature; `preparedNonce` is the
// library-`prepare`d bytes that were signed (the server verifies over these and
// derives its per-action redemption nullifier from them).
export interface RedeemableToken {
  readonly signature: string; // base64url
  readonly preparedNonce: string; // base64url
}

// SPKI public key bytes (DER). The verification key; served in clear.
export type PublicKeySpki = Uint8Array;

// An issuer key pair (SPKI public + PKCS8 private DER bytes). At-rest encryption
// of the private bytes is the KeyStore implementation's concern, not the
// package's. Lifts FreedInk's VoteTokenKeyPair.
export interface IssuerKeyPair {
  publicKeySpki: Uint8Array; // SPKI DER
  privateKeyPkcs8: Uint8Array; // PKCS8 DER
}

// The (group, participant, actionKey) tuple a token is scoped to. The
// one-per-tuple cap is enforced by the IssuanceStore's UNIQUE index.
export interface TokenScope {
  group: string;
  participant: string;
  actionKey: string;
}

// Discriminated sign outcomes - identical semantics to FreedInk's SignOutcome,
// renamed app-neutrally. `pending` = the issuer key is still being generated
// (Signet keygen); `rate_limited` = Signet's per-participant / global ceiling
// fired. Both are first-class outcomes, NOT errors.
export type SignOutcome =
  | { status: "ok"; blindSignature: Uint8Array }
  | { status: "pending" }
  | { status: "rate_limited" };

// Discriminated public-key outcomes - lifts FreedInk's PublicKeyOutcome. Remote
// mode may return `pending` while keygen runs.
export type PublicKeyOutcome =
  | { status: "ready"; publicKeySpki: PublicKeySpki }
  | { status: "pending" };

// Result of a key rotation request. `pending` covers a Signet rotate where the
// new key is still generating. Lifts the Signet POST /key/rotate contract.
export type RotateOutcome =
  | { status: "rotated"; publicKeySpki: PublicKeySpki }
  | { status: "pending" };
