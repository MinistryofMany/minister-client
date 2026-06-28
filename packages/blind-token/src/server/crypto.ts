// Server-side blind-signature crypto core. Lifted BYTE-FOR-BYTE from FreedInk's
// src/lib/server/vote-token.ts (generateVoteTokenKey, blindSignVoteToken,
// verifyVoteToken), generalized only in naming and in taking the safe-prime
// generator + ActionInfo as parameters.
//
// Scheme: partially-blind RSA signatures with PUBLIC METADATA (RFC 9474 + the
// public-metadata extension / draft-amjad-cfrg-partially-blind-rsa), via the
// vetted @cloudflare/blindrsa-ts library. We do NOT hand-roll any blinding.
//
// Why public metadata: the metadata is <infoPrefix>:<actionKey>. The library
// derives a per-metadata key pair from the issuer key, so a signature for action A
// only verifies under action A - a token cannot be replayed against a different
// action (no cross-action replay).
//
// IMPORTANT (validated empirically in FreedInk): the variant factories' generateKey
// wrapper silently drops a custom safe-prime callback and falls back to a
// multi-minute pure-JS sjcl keygen. We therefore call the STATIC
// PartiallyBlindRSA.generateKey with a fast safe-prime generator
// (Node's generatePrimeSync({safe:true}) by default), which produces a 2048-bit
// key in ~1s. The generator is injectable so a non-Node host can supply one.

import { RSAPBSSA, PartiallyBlindRSA } from "@cloudflare/blindrsa-ts";
import { generatePrimeSync, webcrypto } from "node:crypto";
import type { ActionInfo, IssuerKeyPair, PublicKeySpki } from "../types.js";
import { buildInfo } from "../info.js";

// The suite: RSAPBSSA, SHA-384, PSS, Randomized (matches the library's primary
// partially-blind variant and the draft test vectors). Both sides MUST use the
// same suite + the same `info` byte string. This is SUITE_NAME =
// 'RSAPBSSA.SHA384.PSS.Randomized'.
const SUITE = RSAPBSSA.SHA384.PSS.Randomized();

const DEFAULT_MODULUS_LENGTH = 2048;
const PUBLIC_EXPONENT = Uint8Array.from([1, 0, 1]); // 65537

// subtle handle (Node's webcrypto) for importing/exporting CryptoKeys.
const subtle = webcrypto.subtle;

// The default safe-prime generator. The partially-blind scheme requires SAFE
// primes (p and (p-1)/2 both prime); Node's generatePrimeSync({safe:true})
// returns one quickly, unlike the library's default pure-JS sjcl generator.
export function nodeSafePrime(length: number): bigint {
  return generatePrimeSync(length, { safe: true, bigint: true });
}

// Generate a fresh issuer key pair (safe-prime, ~1s for 2048-bit with the native
// generator). Lifts generateVoteTokenKey. The safe-prime generator is a param so
// the package core stays host-agnostic (the Node default is provided).
export async function generateIssuerKey(opts?: {
  modulusLength?: number;
  safePrime?: (bits: number) => bigint;
}): Promise<IssuerKeyPair> {
  const modulusLength = opts?.modulusLength ?? DEFAULT_MODULUS_LENGTH;
  const safePrime = opts?.safePrime ?? nodeSafePrime;
  const { privateKey, publicKey } = await PartiallyBlindRSA.generateKey(
    { modulusLength, publicExponent: PUBLIC_EXPONENT, hash: "SHA-384" },
    safePrime,
  );
  const [spki, pkcs8] = await Promise.all([
    subtle.exportKey("spki", publicKey),
    subtle.exportKey("pkcs8", privateKey),
  ]);
  return {
    publicKeySpki: new Uint8Array(spki),
    privateKeyPkcs8: new Uint8Array(pkcs8),
  };
}

// The library's signatures use the lib.dom `CryptoKey`; Node's webcrypto returns
// `node:crypto` CryptoKey, which is structurally identical at runtime but a
// distinct nominal type. Cast through unknown at the boundary.
async function importPublicKey(spki: Uint8Array): Promise<CryptoKey> {
  const key = await subtle.importKey(
    "spki",
    spki.slice().buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["verify"],
  );
  return key as unknown as CryptoKey;
}

async function importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  const key = await subtle.importKey(
    "pkcs8",
    pkcs8.slice().buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["sign"],
  );
  return key as unknown as CryptoKey;
}

// SERVER (issuance): blind-sign a client's ALREADY-BLINDED message under the
// action's metadata. The server never sees the unblinded nonce. Lifts
// blindSignVoteToken. Used by the LocalSigner.
export async function blindSignToken(opts: {
  privateKeyPkcs8: Uint8Array;
  blindedMessage: Uint8Array;
  info: ActionInfo;
}): Promise<Uint8Array> {
  const sk = await importPrivateKey(opts.privateKeyPkcs8);
  return SUITE.blindSign(sk, opts.blindedMessage, buildInfo(opts.info));
}

// SERVER (redemption): verify an unblinded signature over (action metadata,
// prepared nonce). Returns true iff the signature was produced by THIS issuer key
// for THIS exact action and prepared nonce. Returns false (never throws) on a
// malformed signature/key. Lifts verifyVoteToken; renamed neutral.
export async function verifyToken(args: {
  publicKeySpki: PublicKeySpki;
  signature: Uint8Array;
  preparedNonce: Uint8Array;
  info: ActionInfo;
}): Promise<boolean> {
  let pk: CryptoKey;
  try {
    pk = await importPublicKey(args.publicKeySpki);
  } catch {
    return false;
  }
  try {
    return await SUITE.verify(
      pk,
      args.signature,
      args.preparedNonce,
      buildInfo(args.info),
    );
  } catch {
    // A malformed signature/nonce throws inside the library; treat as invalid.
    return false;
  }
}
