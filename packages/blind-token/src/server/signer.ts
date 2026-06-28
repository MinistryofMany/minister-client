// The blind-signing backend abstraction. ONE interface, TWO implementations
// (local in-process key, remote Signet mTLS), selected by the app. Lifts
// FreedInk's VoteSigner (src/lib/server/vote-signer.ts), renamed app-neutrally
// and keyed on the generic (group, participant, actionKey) tuple.
//
// CRITICAL - same wire scheme both ways. Both backends produce byte-identical
// blind signatures under suite RSAPBSSA.SHA384.PSS.Randomized with public metadata
// <infoPrefix>:<actionKey>. The browser blinds, the backend signs the
// ALREADY-BLINDED message, the browser finalizes, and redemption verifies the
// unblinded signature against the public key from getPublicKey(). The raw nonce
// NEVER reaches a signer in either mode - that is the anonymity invariant, and it
// is structurally enforced: no Signer method accepts a raw or prepared nonce.

import type {
  ActionInfo,
  PublicKeyOutcome,
  RotateOutcome,
  SignOutcome,
} from "../types.js";

// Arguments to sign(). `blindedMessage` is ALREADY BLINDED - the raw nonce is
// never passed. `info` carries the infoPrefix + actionKey the metadata is built
// from; a backend that hard-codes the prefix (Signet) sends only actionKey on the
// wire and asserts the prefix matches.
export interface SignArgs {
  group: string;
  participant: string;
  info: ActionInfo;
  blindedMessage: Uint8Array; // ALREADY blinded; the raw nonce is never passed
}

export interface Signer {
  readonly backend: "local" | "remote";

  // Fetch the group's issuer PUBLIC key (SPKI). Used by the client preflight and
  // by verifyToken. Remote mode may return `pending` while keygen runs.
  getPublicKey(group: string): Promise<PublicKeyOutcome>;

  // Blind-sign an ALREADY-BLINDED message for (group, participant, actionKey).
  // The raw nonce is never an argument. Returns pending/rate_limited, or throws on
  // a real error (malformed message, transport failure). NOTE: the Issuer owns the
  // one-per-tuple reservation; in Local mode this sign() is pure crypto, in Remote
  // mode Signet ALSO enforces the tuple cap (defense in depth).
  sign(args: SignArgs): Promise<SignOutcome>;

  // Idempotently ensure a key exists for the group, kicking off async generation
  // if absent. Never blocks on a multi-second keygen; safe to call repeatedly.
  ensureKey(group: string): Promise<void>;

  // Retire the group's current active key and install a fresh one, returning the
  // new public key (or `pending` for a Signet rotate whose new key is still
  // generating). Added to the interface NOW - before the package ships - so adding
  // per-round rotation later is not a breaking change to a shipped seam: Signet
  // already exposes POST /key/rotate, and FreedInk's KeyStore already carries
  // retiredAt. Local mode rotates via KeyStore.rotateKeyPair; remote mode calls
  // Signet's rotate endpoint.
  rotateKey(group: string): Promise<RotateOutcome>;
}
