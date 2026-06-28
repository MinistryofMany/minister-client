// LocalSigner - in-process key, blind-sign in the host process. The "simple /
// less secure" tier (keys plaintext-at-rest unless the KeyStore encrypts). Lifts
// FreedInk's LocalVoteSigner (src/lib/server/vote-signer.ts:69-110): getPublicKey
// returns ready inline (~1s safe-prime keygen), sign() loads the group's private
// key and blind-signs.
//
// participant is unused in local mode for the SIGN itself - the Issuer's
// IssuanceStore unique index is the per-(group,participant,actionKey) cap in local
// mode (Signet additionally enforces it remote-side). It is still part of SignArgs
// so the surface is identical across backends.

import type { KeyStore } from "./store.js";
import type { Signer, SignArgs } from "./signer.js";
import type {
  IssuerKeyPair,
  PublicKeyOutcome,
  RotateOutcome,
  SignOutcome,
} from "../types.js";
import { generateIssuerKey, blindSignToken } from "./crypto.js";

export interface LocalSignerOpts {
  keyStore: KeyStore; // where issuer key pairs live
  modulusLength?: number; // default 2048 (matches FreedInk)
  // Native safe-prime generator. The package ships a Node default
  // (generatePrimeSync({safe:true})); injectable so a non-Node host can supply one.
  safePrime?: (bits: number) => bigint;
}

class LocalSigner implements Signer {
  readonly backend = "local" as const;
  private readonly keyStore: KeyStore;
  private readonly modulusLength: number | undefined;
  private readonly safePrime: ((bits: number) => bigint) | undefined;

  constructor(opts: LocalSignerOpts) {
    this.keyStore = opts.keyStore;
    this.modulusLength = opts.modulusLength;
    this.safePrime = opts.safePrime;
  }

  // The keygen closure handed to the KeyStore on first use / rotation. Carries the
  // injected modulusLength + safePrime so the store never bakes in keygen.
  private generate = (): Promise<IssuerKeyPair> =>
    generateIssuerKey({
      modulusLength: this.modulusLength,
      safePrime: this.safePrime,
    });

  async getPublicKey(group: string): Promise<PublicKeyOutcome> {
    // If a key exists, return it. Otherwise create one now (local keygen is ~1s,
    // so we generate inline rather than returning `pending` - preserving FreedInk's
    // behavior). getOrCreateKeyPair is concurrency-safe via the partial unique index.
    const existing = await this.keyStore.getActivePublicKey(group);
    if (existing) return { status: "ready", publicKeySpki: existing };
    const key = await this.keyStore.getOrCreateKeyPair(group, this.generate);
    return { status: "ready", publicKeySpki: key.publicKeySpki };
  }

  async sign(args: SignArgs): Promise<SignOutcome> {
    // In-process blind-sign with the group's private key (exactly as FreedInk's
    // LocalVoteSigner). The raw nonce is never in scope - only the already-blinded
    // message. The one-per-tuple cap is the Issuer's IssuanceStore, not this method.
    const key = await this.keyStore.getOrCreateKeyPair(args.group, this.generate);
    const blindSignature = await blindSignToken({
      privateKeyPkcs8: key.privateKeyPkcs8,
      blindedMessage: args.blindedMessage,
      info: args.info,
    });
    return { status: "ok", blindSignature };
  }

  async ensureKey(group: string): Promise<void> {
    // Warm the key off the request path. Idempotent: getOrCreateKeyPair no-ops if
    // one exists. Local keygen is ~1s with the native safe-prime generator. A
    // failure here is non-fatal for pre-gen (the on-demand sign path is the hard
    // guarantee), but we surface it so the caller can decide - FreedInk's store
    // swallows+logs it in ensureLocalVoteTokenKey, which stays app-side.
    const existing = await this.keyStore.getActivePublicKey(group);
    if (existing) return;
    await this.keyStore.getOrCreateKeyPair(group, this.generate);
  }

  async rotateKey(group: string): Promise<RotateOutcome> {
    // Retire the active key, install a fresh one (KeyStore drives the retiredAt +
    // insert). Local keygen is ~1s, so the new key is ready inline - never pending.
    const next = await this.keyStore.rotateKeyPair(group, this.generate);
    return { status: "rotated", publicKeySpki: next.publicKeySpki };
  }
}

// LocalSigner - in-process key, blind-sign in the host process. The "simple /
// less secure" tier. Keys are plaintext-at-rest unless the consumer's KeyStore
// encrypts them; Signet/RemoteSigner is the hardened path.
export function createLocalSigner(opts: LocalSignerOpts): Signer {
  return new LocalSigner(opts);
}
