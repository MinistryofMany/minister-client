// Injectable storage seams (no ORM in the package). The consuming app implements
// these over Drizzle / Prisma / whatever; the package never names a column or
// loads a migration. Lifts FreedInk's src/lib/db/vote-tokens.ts contracts.

import type { IssuerKeyPair, PublicKeySpki, TokenScope } from "../types.js";

// One-per-(group, participant, actionKey) reservation guard. reserve() MUST be
// atomic via a UNIQUE index; release() MUST be idempotent (no-op if already gone)
// and is only ever called by the Issuer on a FAILED sign - never after success.
//
// SAFETY-CRITICAL CONTRACT (the Issuer enforces it, the type system cannot):
//   - reserve() is record-first: written BEFORE signing, so a concurrent
//     double-issue loses the UNIQUE race.
//   - release() after a successful sign would let a participant re-issue
//     (burn-and-reissue). It MUST NOT be called after a successful sign.
//   - release() never firing on a failed sign burns the participant's single
//     token. It MUST be called on every non-ok sign outcome.
export interface IssuanceStore {
  // Insert the reservation row. Return true iff NEWLY reserved (the app uses
  // onConflictDoNothing on UNIQUE(group, participant, actionKey)); false if the
  // tuple already had one. Lifts recordIssuance().
  reserve(key: TokenScope): Promise<boolean>;

  // Delete the reservation for the tuple. Idempotent. Lifts releaseIssuance().
  // CONTRACT: never call after a successful sign (the Issuer enforces this).
  release(key: TokenScope): Promise<void>;
}

// Issuer key-pair storage for LocalSigner ONLY (RemoteSigner holds no keys). The
// app implements it over its DB; the package never names a column. Mirrors
// getOrCreateVoteTokenKey / getVoteTokenPublicKey / ensureLocalVoteTokenKey, but
// keyed on `group` (was blogId) and with the safe-prime keygen injected by the
// LocalSigner, not baked into the store.
export interface KeyStore {
  // Active (non-retired) public key for a group, or null. Lifts
  // getVoteTokenPublicKey.
  getActivePublicKey(group: string): Promise<PublicKeySpki | null>;

  // Active private+public key, creating one via `generate` on first use.
  // Concurrency-safe via a partial UNIQUE index (one active key per group): on a
  // lost insert race, re-read the winner. Lifts getOrCreateVoteTokenKey.
  getOrCreateKeyPair(
    group: string,
    generate: () => Promise<IssuerKeyPair>,
  ): Promise<IssuerKeyPair & { id: string }>;

  // Retire the current active key for `group` and install a freshly generated one,
  // returning the new active pair. Implemented over the app's `retiredAt` column
  // (FreedInk's blog_vote_token_keys.retiredAt): set retiredAt on the old active
  // row, then insert the new one as active (the partial UNIQUE index guarantees
  // exactly one active key per group). Added to the seam NOW - before the package
  // ships - so wiring per-round rotation later is not a breaking change to a
  // shipped interface. The Signer's rotateKey() drives this.
  rotateKeyPair(
    group: string,
    generate: () => Promise<IssuerKeyPair>,
  ): Promise<IssuerKeyPair & { id: string }>;
}

// Minimal structured logger the RemoteSigner uses for best-effort warnings
// (matches FreedInk's log.warn). Default no-op. The package NEVER logs request or
// response bodies (no blinded messages, no signatures) - the anonymity invariant
// from signet.ts is preserved.
export interface TokenLogger {
  warn(fields: Record<string, unknown>, msg: string): void;
  info(fields: Record<string, unknown>, msg: string): void;
}

// A no-op logger, used when the consumer supplies none.
export const noopLogger: TokenLogger = {
  warn() {},
  info() {},
};
