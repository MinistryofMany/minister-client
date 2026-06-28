// @minister/blind-token/client - browser side.
//
// Two pure-crypto steps, framework-agnostic. The caller owns ALL network I/O (the
// public-key preflight, the issuance POST, the redemption POST) and the
// "preparing.../retry" UI; this entry owns only the blind-RSA crypto and the
// byte-identical Chromium-safe finalize.
//
//   1. prepareToken({ publicKey, info }) -> { blindedMessage, prepared, inv }
//        Generate a fresh random nonce, prepare it (adds the Randomized-variant
//        randomizer), blind it under the action's public key + metadata. Send
//        ONLY blindedMessage to the issuer; keep `prepared` and `inv` in this
//        same client to finalize.
//   2. finalizeToken({ publicKey, info, prepared, inv, blindSignature })
//        Unblind the issuer's blind signature into a RedeemableToken, running the
//        RFC 9474 self-check via the Chromium-safe finalize.
//
// THE ANONYMITY INVARIANT: the raw nonce and `inv`/`prepared` NEVER leave the
// browser; only `blindedMessage` is sent to any signer. The signer receives the
// already-blinded message only. (Lifts FreedInk src/lib/client/vote-token.ts.)
//
// The heavy crypto (@cloudflare/blindrsa-ts + its bundled sjcl) is lazy-loaded so
// it is not in a consumer's initial chunk - most participants never act.

import { buildInfo } from "../info.js";
import { bytesToB64url, b64urlToBytes } from "../codec.js";
import type { ActionInfo, PublicKeySpki, RedeemableToken } from "../types.js";
import { finalizeInBrowser } from "./finalize.js";

type Suite = Awaited<ReturnType<typeof loadSuite>>["suite"];

let suiteLoad: Promise<{ suite: Suite }> | null = null;
async function loadSuite() {
  const { RSAPBSSA } = await import("@cloudflare/blindrsa-ts");
  return { suite: RSAPBSSA.SHA384.PSS.Randomized() };
}
function getSuite() {
  suiteLoad ??= loadSuite();
  return suiteLoad;
}

// Import an SPKI public key (DER bytes) as an extractable RSA-PSS / SHA-384
// verify key. Extractable because the Chromium-safe finalize exports it to JWK to
// recover the modulus. Lifts FreedInk importPub (vote-token.ts:314-323).
async function importPub(spki: PublicKeySpki): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    spki.slice().buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["verify"],
  );
}

// Thrown when the issuer key isn't ready yet (async pre-gen still running, or a
// Signet keygen in flight): a preflight or the issuance call surfaced the
// `pending` outcome. The caller should show "preparing..." and retry rather than
// surface this as a hard error. The participant's single one-per-tuple token is
// NOT consumed on a pending issuance (the server rolls the reservation back), so
// retrying is safe. Lifts FreedInk VotePendingError (vote-token.ts:249-255),
// renamed app-neutrally.
export class BlindTokenPendingError extends Error {
  readonly pending = true;
  constructor(message = "issuer key is being prepared") {
    super(message);
    this.name = "BlindTokenPendingError";
  }
}

// Output of prepareToken: the blinded message to send to the issuer, plus the
// secrets the SAME client must keep to finalize. `inv` and `prepared` NEVER leave
// the browser; only `blindedMessage` is sent. Holding the raw-nonce invariant.
export interface PreparedBlind {
  readonly blindedMessage: Uint8Array; // -> send to issuer
  readonly prepared: Uint8Array; // kept; the prepared nonce (also the redemption handle)
  readonly inv: Uint8Array; // kept; blinding inverse, needed to finalize
}

// Step 1a - prepare. Generate a fresh random 32-byte nonce, prepare it (adds the
// Randomized-variant randomizer via suite.prepare), and blind it under the
// action's public key + metadata. Pure client crypto; performs NO network I/O.
// Lifts the blind half of FreedInk requestAndBuildToken (vote-token.ts:263-273).
export async function prepareToken(args: {
  publicKey: PublicKeySpki;
  info: ActionInfo;
}): Promise<PreparedBlind> {
  const { suite } = await getSuite();
  const info = buildInfo(args.info);

  // Fresh random nonce; prepare (adds randomness for the Randomized variant).
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const prepared = suite.prepare(nonce);

  const pub = await importPub(args.publicKey);
  const { blindedMsg, inv } = await suite.blind(pub, prepared, info);

  return { blindedMessage: blindedMsg, prepared, inv };
}

// Step 1b - finalize. Unblind the issuer's blind signature into a RedeemableToken,
// running the RFC 9474 self-check. ENCAPSULATES the Chromium-safe workaround:
// consumers never import @cloudflare/blindrsa-ts internals. Throws on a
// malformed/garbled blind signature (caught before the user spends their token).
// Lifts the finalize half of FreedInk requestAndBuildToken (vote-token.ts:291-298).
export async function finalizeToken(args: {
  publicKey: PublicKeySpki;
  info: ActionInfo;
  prepared: Uint8Array; // from PreparedBlind
  inv: Uint8Array; // from PreparedBlind
  blindSignature: Uint8Array; // from the issuer
}): Promise<RedeemableToken> {
  const info = buildInfo(args.info);
  const pub = await importPub(args.publicKey);
  // Use the Chromium-safe finalize: the library's own suite.finalize throws
  // OperationError in Chromium because it imports the 1024-bit derived public key
  // into WebCrypto. The result is byte-identical (proven by the byte-diff test).
  const signature = await finalizeInBrowser(
    pub,
    args.prepared,
    info,
    args.blindSignature,
    args.inv,
  );
  return {
    signature: bytesToB64url(signature),
    preparedNonce: bytesToB64url(args.prepared),
  };
}

// Re-export the shared wire helpers from the client entry for convenience, so a
// browser consumer needs only one import path.
export { buildInfo, bytesToB64url, b64urlToBytes };
export { SUITE_NAME } from "../types.js";
export type { ActionInfo, RedeemableToken, PublicKeySpki } from "../types.js";

// Test-only surface. finalizeInBrowser is internal to finalizeToken; we expose it
// here so the byte-identical / drift-tripwire tests can prove it is byte-compatible
// with the library's finalize without going through the public API. Not part of
// the public contract.
export const __testing = { finalizeInBrowser };
