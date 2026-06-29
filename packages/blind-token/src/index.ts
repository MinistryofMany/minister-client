// @ministryofmany/blind-token (root entry) - shared, isomorphic surface.
//
// Privacy-Pass-style blind-RSA action tokens: a participant is issued exactly one
// unlinkable token per (group, participant, actionKey) and later redeems it
// anonymously. Suite RSAPBSSA.SHA384.PSS.Randomized (RFC 9474 + the
// public-metadata extension) via @cloudflare/blindrsa-ts. Generalized out of
// FreedInk's vote-token system; the Signet remote signer is preserved byte-for-byte.
//
// Import from this root for the wire helpers (buildInfo, base64url codecs, the
// suite constant) and the shared types. Use `/client` for browser prepare/finalize
// and `/server` for the Signer / Issuer / verify.
//
// THE ANONYMITY INVARIANT: the raw token nonce NEVER reaches a signer. The client
// generates a random nonce, prepares it, and blinds it; only the blinded message
// is ever sent to any signer (local or Signet). No API in this package accepts a
// raw or prepared nonce on the signing side.

export { SUITE_NAME } from "./types.js";
export type {
  SuiteName,
  ActionInfo,
  RedeemableToken,
  PublicKeySpki,
  IssuerKeyPair,
  TokenScope,
  SignOutcome,
  PublicKeyOutcome,
  RotateOutcome,
} from "./types.js";

export { buildInfo } from "./info.js";
export { bytesToB64url, b64urlToBytes } from "./codec.js";
