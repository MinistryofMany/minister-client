// Issuer - the issuance-guard orchestrator (the generalization core). Lifts
// FreedInk's /api/blog/vote-token route body (src/routes/api/blog/vote-token/+server.ts:
// record-first reservation -> sign -> rollback-on-failure -> outcome mapping) out
// of the SvelteKit route and makes it generic and reusable. It is the heart of
// "one token per (group, participant, actionKey)".
//
// SAFETY-CRITICAL: a token is issued IFF a fresh reservation was made AND signing
// returned ok. Every other path releases the reservation so the participant can
// retry without burning their single token. The reservation is NEVER released
// after a successful sign (that would let a participant re-issue). The Issuer
// centralizes this so no consumer re-implements it.

import type { Signer } from "./signer.js";
import type { IssuanceStore, TokenLogger } from "./store.js";
import { noopLogger } from "./store.js";
import type {
  ActionInfo,
  PublicKeyOutcome,
  PublicKeySpki,
  RotateOutcome,
  SignOutcome,
} from "../types.js";

// Result of an issuance attempt. The app maps these to HTTP. `already_issued` is
// the one-per-tuple refusal; the other non-ok states have already had their
// reservation rolled back by the Issuer, so the participant can retry.
export type IssueResult =
  | { status: "issued"; blindSignature: Uint8Array; publicKeySpki?: PublicKeySpki }
  | { status: "already_issued" }
  | { status: "pending" }
  | { status: "rate_limited" }
  | { status: "signer_error"; error: unknown };

export interface Issuer {
  // Full issuance: reserve (record-first) -> sign -> rollback on any non-ok. The
  // ONLY thing the app must do first is its OWN eligibility check (can_review /
  // is-mod). The Issuer guarantees: a token is issued iff a fresh reservation was
  // made AND signing returned ok; every other path releases the reservation.
  // `blindedMessage` is already blinded - the raw nonce is never passed.
  issue(args: {
    group: string;
    participant: string;
    info: ActionInfo;
    blindedMessage: Uint8Array;
  }): Promise<IssueResult>;

  // Public-key preflight passthrough (records nothing, consumes nothing).
  getPublicKey(group: string): Promise<PublicKeyOutcome>;

  // Pre-gen passthrough (warm a key before first issuance).
  ensureKey(group: string): Promise<void>;

  // Key-rotation passthrough (retire the active key, install a fresh one). Wired
  // through NOW so per-round rotation later is not a breaking change.
  rotateKey(group: string): Promise<RotateOutcome>;
}

export interface IssuerOpts {
  signer: Signer;
  issuanceStore: IssuanceStore; // the one-per-tuple guard
  // Whether issue() returns the public key alongside a successful blind signature
  // (FreedInk does, to save a client round-trip). Default true.
  includePublicKeyOnIssue?: boolean;
  // Best-effort structured logger. Used only to surface a post-sign public-key
  // fetch failure (which is swallowed on purpose so it can never burn a token).
  // Never receives request/response bodies. Default no-op.
  logger?: TokenLogger;
}

class IssuerImpl implements Issuer {
  private readonly signer: Signer;
  private readonly store: IssuanceStore;
  private readonly includePublicKey: boolean;
  private readonly logger: TokenLogger;

  constructor(opts: IssuerOpts) {
    this.signer = opts.signer;
    this.store = opts.issuanceStore;
    this.includePublicKey = opts.includePublicKeyOnIssue ?? true;
    this.logger = opts.logger ?? noopLogger;
  }

  async issue(args: {
    group: string;
    participant: string;
    info: ActionInfo;
    blindedMessage: Uint8Array;
  }): Promise<IssueResult> {
    const scope = {
      group: args.group,
      participant: args.participant,
      actionKey: args.info.actionKey,
    };

    // 1. Record-first reservation (UNIQUE index). If not newly reserved, the tuple
    //    already has a token: refuse. A concurrent double-issue loses this race.
    const reserved = await this.store.reserve(scope);
    if (!reserved) return { status: "already_issued" };

    // 2. Sign the ALREADY-BLINDED message. On ANY non-ok outcome, release the
    //    reservation so the participant can retry. NEVER release after ok.
    let outcome: SignOutcome;
    try {
      outcome = await this.signer.sign({
        group: args.group,
        participant: args.participant,
        info: args.info,
        blindedMessage: args.blindedMessage,
      });
    } catch (error) {
      // A transport/transient failure (Signet unreachable) or a malformed-message
      // error must not burn the participant's single token. Roll back; surface as
      // signer_error (the app maps local -> 400, remote -> 502).
      await this.store.release(scope);
      return { status: "signer_error", error };
    }

    if (outcome.status === "pending") {
      // Key not ready yet (Signet keygen). Roll back so the token isn't consumed;
      // tell the caller to retry (shows "preparing...").
      await this.store.release(scope);
      return { status: "pending" };
    }

    if (outcome.status === "rate_limited") {
      // Signet's per-participant / global ceiling fired. Roll back so the
      // participant can retry after the window.
      await this.store.release(scope);
      return { status: "rate_limited" };
    }

    if (outcome.status === "already_issued") {
      // The SIGNER's own ledger (Signet) already holds this tuple - a 409. This
      // is a TERMINAL, NON-RECOVERABLE state for this token: Signet committed the
      // tuple on a prior attempt (a lost /sign response, or a second issuer
      // instance with a separate local store) but never stored the blind
      // signature, so it cannot be reproduced. We do NOT release the local
      // reservation: keeping it aligns this issuer's ledger with Signet's, so
      // retries short-circuit at reserve() (already_issued) instead of hammering
      // Signet with more 409s. Recovery is out-of-band (admin delete of the
      // Signet row, or a key rotation).
      return { status: "already_issued" };
    }

    // 3. Success. Do NOT release. Optionally fetch the public key for the response
    //    (FreedInk does, to save a client round-trip). A pending pubkey here is
    //    extremely unlikely (we just signed), so we just omit it and let the client
    //    re-fetch via the preflight - we NEVER roll back a successful sign.
    let publicKeySpki: PublicKeySpki | undefined;
    if (this.includePublicKey) {
      try {
        const pk = await this.signer.getPublicKey(args.group);
        if (pk.status === "ready") publicKeySpki = pk.publicKeySpki;
      } catch (error) {
        // The blind signature is ALREADY computed and the reservation is (rightly)
        // kept. The public key is best-effort convenience - the client can
        // re-fetch it via the preflight - so a transport blip here must NEVER
        // throw out of issue() and discard the signature (which would burn the
        // participant's single token: retry -> already_issued). Omit the key, log,
        // and still return the issued signature. Mirrors the pending-key path.
        this.logger.warn(
          { group: args.group, error },
          "issuer: public-key fetch failed after a successful sign; returning the signature without it",
        );
      }
    }
    return { status: "issued", blindSignature: outcome.blindSignature, publicKeySpki };
  }

  getPublicKey(group: string): Promise<PublicKeyOutcome> {
    return this.signer.getPublicKey(group);
  }

  ensureKey(group: string): Promise<void> {
    return this.signer.ensureKey(group);
  }

  rotateKey(group: string): Promise<RotateOutcome> {
    return this.signer.rotateKey(group);
  }
}

// Create the issuance-guard orchestrator over a Signer + an IssuanceStore.
export function createIssuer(opts: IssuerOpts): Issuer {
  return new IssuerImpl(opts);
}
